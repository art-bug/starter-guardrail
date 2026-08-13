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
        text_lower = text.lower()

        for rule in self._rules:
            for keyword in rule.keywords:
                if keyword.lower() in text_lower:
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


# Более безопасный набор weak keywords.
# Он используется только как подтверждающий сигнал, не как самостоятельный BLOCK.
WEAK_KEYWORD_RULES: Final = (
    KeywordRule(
        Action.BLOCK,
        ReasonCode.PROMPT_OVERRIDE,
        (
            "system prompt",
            "hidden prompt",
            "initial prompt",
            "original prompt",
            "reveal instructions",
            "secret settings",
        ),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.MODERATION_EVASION,
        (
            "bypass",
            "evade",
            "circumvent",
            "avoid the filter",
        ),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.GENERATE_ABUSE,
        (
            "threaten",
            "intimidate",
            "harass",
            "kill",
        ),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.PRIVATE_DATA_REQUEST,
        (
            "private data",
            "home address",
            "phone number",
            "personal information",
        ),
    ),
)


EXACT_BASELINE_KEYWORD_RULES: Final = (
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


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class SubstringKeywordDetector(Detector):
    """Keyword detector using substring matching (no word boundaries)."""

    def __init__(self, rules: Sequence[KeywordRule] | None = None) -> None:
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
        flattened_lower = flattened.lower()

        for rule in self._rules:
            for keyword in rule.keywords:
                if keyword.lower() in flattened_lower:
                    return Signal(rule.action, rule.reason_code)

        return None


import re as _re


@dataclass(frozen=True, slots=True)
class RegexRule:
    action: Action
    reason_code: ReasonCode
    pattern: _re.Pattern


REGEX_RULES: Final = (
    # PROMPT_OVERRIDE
    RegexRule(
        Action.BLOCK,
        ReasonCode.PROMPT_OVERRIDE,
        _re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\w*\b"
            r".{0,120}?"
            r"\b(?:previous|prior|all|system|developer|initial|hidden|original|safety|content|moderation)\b"
            r".{0,120}?"
            r"\b(?:instructions?|prompts?|rules?|guidelines?|settings?|configuration|directions?|directives?|commands?|orders?)\b",
            _re.IGNORECASE | _re.DOTALL,
        ),
    ),
    RegexRule(
        Action.BLOCK,
        ReasonCode.PROMPT_OVERRIDE,
        _re.compile(
            r"\b(?:reveal|show|print|display|output|repeat|leak|expose|disclose|tell)\w*\b"
            r".{0,120}?"
            r"\b(?:system\s+prompt|hidden\s+prompt|initial\s+prompt|original\s+prompt|"
            r"secret(?:\s+(?:key|token|config|settings))?|hidden\s+settings|"
            r"hidden\s+configuration|confidential\s+settings)\b",
            _re.IGNORECASE | _re.DOTALL,
        ),
    ),

    # MODERATION_EVASION
    RegexRule(
        Action.BLOCK,
        ReasonCode.MODERATION_EVASION,
        _re.compile(
            r"\b(?:bypass|evade|circumvent|trick|fool|get\s+around|slip\s+past|avoid)\w*\b"
            r".{0,120}?"
            r"\b(?:filter|filters|moderation|safety|safeguard|safeguards|review|detection|policy|controls?)\b",
            _re.IGNORECASE | _re.DOTALL,
        ),
    ),

    # GENERATE_ABUSE
    RegexRule(
        Action.BLOCK,
        ReasonCode.GENERATE_ABUSE,
        _re.compile(
            r"\b(?:write|draft|create|generate|compose|make|author)\w*\b"
            r".{0,160}?"
            r"\b(?:threat\w*|intimidat\w*|abus\w*|harass\w*|hate\w*|violent\w*|coercive|scary|frightening)\b"
            r".{0,160}?"
            r"\b(?:message|text|post|comment|letter|email|content|note|language|target|person|individual)\b",
            _re.IGNORECASE | _re.DOTALL,
        ),
    ),
    RegexRule(
        Action.BLOCK,
        ReasonCode.GENERATE_ABUSE,
        _re.compile(
            r"\b(?:threaten|intimidate|harass|stalk|bully|torment|scare|frighten)\w*\b"
            r".{0,140}?"
            r"\b(?:person|user|individual|student|coworker|neighbor|someone|somebody|them|him|her|target)\b",
            _re.IGNORECASE | _re.DOTALL,
        ),
    ),

    # PRIVATE_DATA_REQUEST
    RegexRule(
        Action.BLOCK,
        ReasonCode.PRIVATE_DATA_REQUEST,
        _re.compile(
            r"\b(?:find|get|reveal|show|extract|retrieve|dox|leak|share|publish|look\s+up|tell)\w*\b"
            r".{0,160}?"
            r"\b(?:home\s+address|phone\s+number|email(?:\s+address)?|location|"
            r"private\s+data|personal\s+(?:info|information|details)|contact\s+(?:info|information)|"
            r"reporter(?:'s|s)?\s+identity|identity\s+of\s+(?:the\s+)?reporter|"
            r"source(?:'s|s)?\s+identity|identity\s+of\s+(?:the\s+)?source)\b",
            _re.IGNORECASE | _re.DOTALL,
        ),
    ),
)


class RegexDetector(Detector):
    """Return the first regex-based signal."""

    def __init__(self, rules: Sequence[RegexRule] | None = None) -> None:
        self._rules = tuple(rules) if rules is not None else REGEX_RULES

    def detect(self, text: str) -> Signal | None:
        flattened = normalize_text(text).control_stripped

        for rule in self._rules:
            if rule.pattern.search(flattened):
                return Signal(rule.action, rule.reason_code)

        return None