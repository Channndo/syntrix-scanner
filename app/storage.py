"""
Storage layer — in-memory for MVP.
Swap for Postgres/Supabase before launch by implementing the same interface.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from threading import Lock


class _MemoryStore:
    def __init__(self):
        self._scans: Dict[str, Dict[str, Any]] = {}
        self._findings: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = Lock()

    def create_scan(self, scan_id: str, target: str, scan_type: str, depth: str, submitted_at: datetime):
        with self._lock:
            self._scans[scan_id] = {
                "scan_id": scan_id,
                "target": target,
                "scan_type": scan_type,
                "depth": depth,
                "status": "queued",
                "progress": 0,
                "findings_count": 0,
                "risk_score": None,
                "risk_tier": None,
                "submitted_at": submitted_at,
                "completed_at": None,
                "error": None,
            }
            self._findings[scan_id] = []

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._scans[scan_id]) if scan_id in self._scans else None

    def update_status(self, scan_id: str, status: str, progress: int = 0):
        with self._lock:
            if scan_id in self._scans:
                self._scans[scan_id]["status"] = status
                self._scans[scan_id]["progress"] = progress

    def save_findings(self, scan_id: str, findings: List[Dict[str, Any]]):
        with self._lock:
            self._findings[scan_id] = findings
            if scan_id in self._scans:
                self._scans[scan_id]["findings_count"] = len(findings)

    def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._findings.get(scan_id, []))

    def get_summary(self, scan_id: str) -> Dict[str, int]:
        with self._lock:
            findings = self._findings.get(scan_id, [])
            summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in findings:
                sev = f.get("severity", "info").lower()
                if sev in summary:
                    summary[sev] += 1
            return summary

    def complete_scan(self, scan_id: str, risk_score: int, risk_tier: str, completed_at: datetime):
        with self._lock:
            if scan_id in self._scans:
                self._scans[scan_id].update({
                    "status": "complete",
                    "progress": 100,
                    "risk_score": risk_score,
                    "risk_tier": risk_tier,
                    "completed_at": completed_at,
                })

    def fail_scan(self, scan_id: str, error: str):
        with self._lock:
            if scan_id in self._scans:
                self._scans[scan_id].update({"status": "failed", "error": error})


store = _MemoryStore()