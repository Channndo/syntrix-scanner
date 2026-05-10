"""Fixed list of security questions (indices match API and landing `security-questions.js`)."""

from __future__ import annotations

from typing import List

# Must stay in sync with landing/assets/js/security-questions.js
CANNED_SECURITY_QUESTIONS: List[str] = [
    "What city were you born in?",
    "What was the name of your first school?",
    "What was your childhood nickname?",
    "What is your maternal grandmother's first name?",
    "In what city did you meet your spouse or partner?",
    "What was the make of your first car?",
    "What was the name of your first pet?",
    "What street did you grow up on?",
    "What was your dream job as a child?",
    "What is the middle name of your oldest sibling?",
]


def question_text(question_id: int) -> str:
    if question_id < 0 or question_id >= len(CANNED_SECURITY_QUESTIONS):
        raise ValueError("invalid question id")
    return CANNED_SECURITY_QUESTIONS[question_id]
