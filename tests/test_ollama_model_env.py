"""OLLAMA_MODEL resolution (MIRA) — stale Render tag guardrail."""

from app.config import resolved_ollama_model_from_env


def test_resolved_ollama_remaps_llama31_8b_to_llama32_1b(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.1:8b")
    monkeypatch.delenv("SYNTRIX_DISABLE_OLLAMA_MODEL_AUTO_CORRECT", raising=False)
    assert resolved_ollama_model_from_env() == "llama3.2:1b"


def test_resolved_ollama_case_insensitive_remap(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "Llama3.1:8B")
    monkeypatch.delenv("SYNTRIX_DISABLE_OLLAMA_MODEL_AUTO_CORRECT", raising=False)
    assert resolved_ollama_model_from_env() == "llama3.2:1b"


def test_resolved_ollama_respects_disable_auto_correct(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.1:8b")
    monkeypatch.setenv("SYNTRIX_DISABLE_OLLAMA_MODEL_AUTO_CORRECT", "true")
    assert resolved_ollama_model_from_env() == "llama3.1:8b"


def test_resolved_ollama_other_tags_unchanged(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "mistral:7b")
    monkeypatch.delenv("SYNTRIX_DISABLE_OLLAMA_MODEL_AUTO_CORRECT", raising=False)
    assert resolved_ollama_model_from_env() == "mistral:7b"


def test_resolved_ollama_default_when_unset(monkeypatch):
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    monkeypatch.delenv("SYNTRIX_DISABLE_OLLAMA_MODEL_AUTO_CORRECT", raising=False)
    assert resolved_ollama_model_from_env() == "llama3.2:1b"
