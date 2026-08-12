"""Ordered keyword signals for the intentionally weak starter policy."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol, Sequence, runtime_checkable, Final

from common import Action, ReasonCode
from guardrail.normalization import normalize_text


@dataclass(frozen=True, slots=True)
class Signal:
    """A detector's proposed action and reason."""

    action: Action
    reason_code: ReasonCode


@runtime_checkable
class Detector(Protocol):
    """Structural interface implemented by starter signal detectors."""

    def detect(self, text: str) -> Signal | None:
        """Return one signal for a flattened input, or no signal."""


@dataclass(frozen=True, slots=True)
class KeywordRule:
    """One ordered policy concept and its literal trigger terms."""

    action: Action
    reason_code: ReasonCode
    keywords: tuple[str, ...]


DEFAULT_KEYWORD_RULES = (
    KeywordRule(
        Action.BLOCK,
        ReasonCode.PROMPT_OVERRIDE,
        ("ignore", "system prompt", "reveal", "secret"),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.MODERATION_EVASION,
        ("bypass", "evade", "avoid the filter"),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.GENERATE_ABUSE,
        ("threaten", "intimidate", "kill"),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.PRIVATE_DATA_REQUEST,
        ("reporter identity", "private data", "home address"),
    ),
)


class OrderedKeywordDetector(Detector):
    """Return the first matching concept according to configured rule order."""

    def __init__(
        self, rules: Sequence[KeywordRule] | None = None
    ) -> None:
        configured = tuple(rules) if rules is not None else DEFAULT_KEYWORD_RULES
        self._rules = tuple(
            KeywordRule(
                rule.action,
                rule.reason_code,
                tuple(
                    normalize_text(keyword).control_stripped
                    for keyword in rule.keywords
                ),
            )
            for rule in configured
        )

    def detect(self, text: str) -> Signal | None:
        flattened = normalize_text(text).control_stripped
        for rule in self._rules:
            for keyword in rule.keywords:
                # Границы слова с учётом пробелов, начала/конца строки
                pattern = r'(?<!\w)' + re.escape(keyword) + r'(?!\w)'
                if re.search(pattern, flattened, re.IGNORECASE):
                    return Signal(rule.action, rule.reason_code)

        return None


DEFAULT_ALLOW_LIST: Final = (
    "hello",
    "good afternoon",
    "good morning",
    "hi there",
    "how are you",
    "can you help me with my account",
    "i need assistance with",
)


class AllowListDetector(Detector):

    def detect(self, text: str) -> Signal | None:
        if any(allow in text.lower() for allow in DEFAULT_ALLOW_LIST):
            return Signal(Action.ALLOW, ReasonCode.ORDINARY_SUPPORT)

        return None