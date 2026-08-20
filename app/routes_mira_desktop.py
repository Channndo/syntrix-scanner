"""Gated MIRA desktop downloads + electron-updater generic feed.

Artifacts live on the API host under ``MIRA_RELEASES_DIR`` (default ``/data/mira-releases`` on
Render). Only admin accounts or active/trialing subscribers may fetch files. The public marketing
site never gets a permanent CDN URL — browsers and Electron send ``Authorization: Bearer <JWT>``.

Feed layout (same as electron-builder generic provider)::

    mira-releases/
      latest-mac.yml
      MIRA-<version>-mac.zip
      MIRA-<version>.dmg          # optional; used by website Download (macOS)
      latest.yml                  # Windows electron-updater
      MIRA-<version>-setup.exe    # NSIS installer (website + updates)
      MIRA-<version>-portable.exe # optional

Canonical feed URL for packaged apps::

    https://api.syntrix.solutions/api/mira/desktop/releases

Optional DNS: point ``releases.syntrix.solutions/mira`` at the same path (Cloudflare proxy /
redirect) so the bake-time URL keeps working.
"""

from __future__ import annotations

import logging
import mimetypes
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, RedirectResponse

from app.billing import require_mira_desktop_entitlement, user_has_mira_desktop_entitlement
from app.config import settings
from app.deps import AuthenticatedUser, require_user
from app.storage import store

logger = logging.getLogger(__name__)

router = APIRouter(tags=["mira-desktop"])

_SAFE_RELEASE_NAME = re.compile(r"^[A-Za-z0-9._+-]+$")
_DMG_GLOB = "*.dmg"
_MAC_ZIP_GLOB = "*-mac.zip"
_WIN_SETUP_GLOB = "MIRA-*-setup.exe"
_WIN_PORTABLE_GLOB = "MIRA-*-portable.exe"
_WIN_EXE_GLOB = "*.exe"


def _releases_root() -> Path:
    return Path(settings.mira_releases_dir).expanduser().resolve()


def _safe_release_path(filename: str) -> Path:
    name = (filename or "").strip()
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise HTTPException(status_code=400, detail="Invalid release filename")
    if not _SAFE_RELEASE_NAME.match(name):
        raise HTTPException(status_code=400, detail="Invalid release filename")
    root = _releases_root()
    path = (root / name).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid release filename") from exc
    return path


def _newest_matching(pattern: str) -> Optional[Path]:
    root = _releases_root()
    if not root.is_dir():
        return None
    matches = sorted(root.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    for p in matches:
        if p.is_file():
            return p
    return None


def _list_release_files() -> List[str]:
    root = _releases_root()
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_file() and _SAFE_RELEASE_NAME.match(p.name))


def _normalize_platform(platform: Optional[str]) -> str:
    raw = (platform or "mac").strip().lower()
    if raw in {"mac", "macos", "darwin", "osx"}:
        return "mac"
    if raw in {"win", "windows", "win32", "win64"}:
        return "win"
    raise HTTPException(status_code=400, detail="platform must be mac or win")


def _media_type(path: Path) -> str:
    guessed, _ = mimetypes.guess_type(path.name)
    if guessed:
        return guessed
    if path.suffix.lower() == ".yml":
        return "text/yaml; charset=utf-8"
    if path.suffix.lower() == ".yaml":
        return "text/yaml; charset=utf-8"
    if path.suffix.lower() == ".exe":
        return "application/vnd.microsoft.portable-executable"
    return "application/octet-stream"


def _file_response(path: Path) -> FileResponse:
    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Release artifact not found: {path.name}. Upload builds to MIRA_RELEASES_DIR.",
        )
    # electron-updater reads YAML as a body; attachment disposition can confuse some clients.
    as_attachment = path.suffix.lower() not in {".yml", ".yaml"}
    return FileResponse(
        path,
        media_type=_media_type(path),
        filename=path.name if as_attachment else None,
        content_disposition_type="attachment" if as_attachment else "inline",
    )


def _resolve_mac_download(artifact: str) -> Path:
    kind = (artifact or "dmg").strip().lower()
    if kind not in {"dmg", "zip", "mac-zip", "installer", "default"}:
        raise HTTPException(status_code=400, detail="artifact must be dmg or zip for platform=mac")

    if kind in {"dmg", "installer", "default"}:
        path = _newest_matching(_DMG_GLOB)
        if path is None:
            path = _newest_matching(_MAC_ZIP_GLOB)
            if path is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="MIRA macOS installer not published yet. Upload a .dmg (or *-mac.zip) to MIRA_RELEASES_DIR.",
                )
        return path

    path = _newest_matching(_MAC_ZIP_GLOB)
    if path is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MIRA macOS update zip not published yet. Upload *-mac.zip to MIRA_RELEASES_DIR.",
        )
    return path


def _resolve_win_download(artifact: str) -> Path:
    kind = (artifact or "exe").strip().lower()
    if kind not in {"exe", "setup", "nsis", "installer", "portable", "default"}:
        raise HTTPException(
            status_code=400,
            detail="artifact must be exe/setup or portable for platform=win",
        )

    if kind == "portable":
        path = _newest_matching(_WIN_PORTABLE_GLOB)
        if path is None:
            path = _newest_matching(_WIN_EXE_GLOB)
        if path is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="MIRA Windows portable build not published yet. Upload MIRA-*-portable.exe to MIRA_RELEASES_DIR.",
            )
        return path

    path = _newest_matching(_WIN_SETUP_GLOB)
    if path is None:
        # Prefer named setup; then any exe (portable fallback for website).
        path = _newest_matching(_WIN_PORTABLE_GLOB) or _newest_matching(_WIN_EXE_GLOB)
    if path is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MIRA Windows installer not published yet. Upload MIRA-*-setup.exe to MIRA_RELEASES_DIR.",
        )
    return path


@router.get("/desktop/status")
def mira_desktop_status() -> Dict[str, Any]:
    """Public discovery — does not leak filenames beyond counts / readiness."""
    root = _releases_root()
    files = _list_release_files()
    has_mac_yml = "latest-mac.yml" in files
    has_mac_zip = any(n.endswith("-mac.zip") for n in files)
    has_dmg = any(n.lower().endswith(".dmg") for n in files)
    has_win_yml = "latest.yml" in files
    has_win_setup = any(n.lower().endswith("-setup.exe") for n in files)
    has_win_exe = any(n.lower().endswith(".exe") for n in files)
    return {
        "service": "mira-desktop",
        "gate": settings.mira_desktop_gate,
        "releases_configured": root.is_dir(),
        "has_update_feed": has_mac_yml and has_mac_zip,
        "has_mac_update_feed": has_mac_yml and has_mac_zip,
        "has_win_update_feed": has_win_yml and (has_win_setup or has_win_exe),
        "has_dmg": has_dmg,
        "has_win_installer": has_win_setup or has_win_exe,
        "download": "/api/mira/desktop/download",
        "entitlement": "/api/mira/desktop/entitlement",
        "releases_feed": "/api/mira/desktop/releases",
        "platforms": ["mac", "win"],
    }


@router.get("/desktop/entitlement")
def mira_desktop_entitlement(
    user: AuthenticatedUser = Depends(require_user),
) -> Dict[str, Any]:
    """Browser/UI helper — same rules as download without streaming a binary."""
    em = store.canonical_email_for_sub(user.sub, user.email)
    admin = settings.is_admin_email(em)
    sub = store.get_subscription(user.sub)
    status_s = str(sub.get("status") or "inactive")
    entitled = user_has_mira_desktop_entitlement(user)
    reason = "ok"
    if not entitled:
        reason = "subscription_required"
    elif admin:
        reason = "admin"
    elif status_s in {"active", "trialing"}:
        reason = "subscription"
    return {
        "entitled": entitled,
        "reason": reason,
        "role": "admin" if admin else "user",
        "subscription_status": status_s,
        "gate": settings.mira_desktop_gate,
        "download_url": "/api/mira/desktop/download",
        "billing_url": f"{settings.app_base_url.rstrip('/')}/billing.html",
        "platforms": ["mac", "win"],
    }


@router.get("/desktop/download")
def mira_desktop_download(
    platform: str = "mac",
    artifact: str = "default",
    user: AuthenticatedUser = Depends(require_mira_desktop_entitlement),
):
    """Stream the latest installer for entitled users.

    Query params:
      - platform: ``mac`` | ``win`` (aliases: macos, windows)
      - artifact: mac ``dmg``|``zip``; win ``exe``|``setup``|``portable``; or ``default``
    """
    plat = _normalize_platform(platform)
    art = (artifact or "default").strip().lower()

    if plat == "mac":
        path = _resolve_mac_download(art)
    else:
        path = _resolve_win_download(art)

    logger.info(
        "mira_desktop_download sub=%s email=%s platform=%s artifact=%s file=%s",
        user.sub,
        user.email,
        plat,
        art,
        path.name,
    )
    return _file_response(path)


@router.get("/desktop/releases")
def mira_desktop_releases_index(
    user: AuthenticatedUser = Depends(require_mira_desktop_entitlement),
) -> Dict[str, Any]:
    """List release filenames for entitled clients (debugging / ops)."""
    return {
        "feed_base": "/api/mira/desktop/releases",
        "files": _list_release_files(),
    }


@router.get("/desktop/releases/{filename}")
def mira_desktop_release_file(
    filename: str,
    user: AuthenticatedUser = Depends(require_mira_desktop_entitlement),
):
    """electron-updater generic provider path: ``{feed}/{latest-mac.yml|latest.yml|zip|exe|…}``."""
    path = _safe_release_path(filename)
    logger.info(
        "mira_desktop_release_file sub=%s file=%s",
        user.sub,
        path.name,
    )
    return _file_response(path)


@router.get("/desktop/releases/")
def mira_desktop_releases_slash(
    user: AuthenticatedUser = Depends(require_mira_desktop_entitlement),
):
    """Trailing-slash alias → index (some clients append /)."""
    return RedirectResponse(url="/api/mira/desktop/releases", status_code=307)
