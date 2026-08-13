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
        (
            "private data",
            "home address",
            "phone number",
            "personal information",
            "reporter identity",
        ),
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


@dataclass(frozen=True, slots=True)
class RegexRule:
    """Deterministic regex-based rule for stronger attack patterns."""

    action: Action
    reason_code: ReasonCode
    pattern: re.Pattern


def _compile_rule(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


STRONG_REGEX_RULES: Final = (

    # PROMPT_OVERRIDE
    RegexRule(
        Action.BLOCK,
        ReasonCode.PROMPT_OVERRIDE,
        _compile_rule(
            r"\b(?:ignore|disregard|forget|override)\b"
            r".{0,140}?"
            r"\b(?:previous|prior|system|developer|initial|hidden|original|safety|content|moderation)\b"
            r".{0,140}?"
            r"\b(?:instructions?|prompts?|rules?|guidelines?|settings?|configuration|"
            r"directions?|directives?|commands?|orders?)\b"
        ),
    ),
    RegexRule(
        Action.BLOCK,
        ReasonCode.PROMPT_OVERRIDE,
        _compile_rule(
            r"\b(?:ignore|disregard|forget|override)\b"
            r".{0,80}?"
            r"\ball\b"
            r".{0,80}?"
            r"\b(?:instructions?|prompts?|rules?|guidelines?|settings?|configuration)\b"
        ),
    ),
    RegexRule(
        Action.BLOCK,
        ReasonCode.PROMPT_OVERRIDE,
        _compile_rule(
            r"\b(?:reveal|show|print|display|output|repeat|leak|expose|disclose|tell)\b"
            r".{0,140}?"
            r"\b(?:system\s+prompt|hidden\s+prompt|initial\s+prompt|original\s+prompt|"
            r"secret(?:\s+(?:key|token|config|settings))?|hidden\s+settings|"
            r"hidden\s+configuration|confidential\s+settings)\b"
        ),
    ),

    # MODERATION_EVASION
    RegexRule(
        Action.BLOCK,
        ReasonCode.MODERATION_EVASION,
        _compile_rule(
            r"\b(?:bypass|evade|circumvent|trick|fool|get\s+around)\b"
            r".{0,140}?"
            r"\b(?:filter|filters|moderation|safety|safeguard|safeguards|review|detection|policy|controls?)\b"
        ),
    ),

    # GENERATE_ABUSE
    RegexRule(
        Action.BLOCK,
        ReasonCode.GENERATE_ABUSE,
        _compile_rule(
            r"\b(?:write|draft|create|generate|compose|make|help\s+me\s+write)\b"
            r".{0,180}?"
            r"\b(?:threat|threatening|intimidating|abusive|harassing|hateful|violent)\b"
            r".{0,180}?"
            r"\b(?:message|text|post|comment|letter|email|content|note)\b"
        ),
    ),
    RegexRule(
        Action.BLOCK,
        ReasonCode.GENERATE_ABUSE,
        _compile_rule(
            r"\b(?:threaten|intimidate|harass|stalk|bully)\b"
            r".{0,160}?"
            r"\b(?:person|user|individual|student|coworker|neighbor|someone|somebody|them|him|her)\b"
        ),
    ),

    # PRIVATE_DATA_REQUEST
    RegexRule(
        Action.BLOCK,
        ReasonCode.PRIVATE_DATA_REQUEST,
        _compile_rule(
            r"\b(?:find|get|reveal|show|extract|retrieve|dox|leak|share|publish|look\s+up)\b"
            r".{0,180}?"
            r"\b(?:home\s+address|phone\s+number|email(?:\s+address)?|location|"
            r"private\s+data|personal\s+information|contact\s+info|contact\s+information)\b"
            r".{0,180}?"
            r"\b(?:of|about|for|belonging\s+to)\b"
            r".{0,180}?"
            r"\b(?:someone|somebody|person|user|individual|victim|target)\b"
        ),
    ),
    RegexRule(
        Action.BLOCK,
        ReasonCode.PRIVATE_DATA_REQUEST,
        _compile_rule(
            r"\b(?:tell|give|show|reveal|disclose|provide|find|get|extract|retrieve|share|publish|look\s+up)\b"
            r".{0,180}?"
            r"\b(?:reporter(?:'s|s)?\s+identity|identity\s+of\s+(?:the\s+)?reporter|"
            r"source(?:'s|s)?\s+identity|identity\s+of\s+(?:the\s+)?source)\b"
        ),
    ),
)


class StrongRegexDetector(Detector):
    """Return the first strong regex-based signal."""

    def __init__(self, rules: Sequence[RegexRule] | None = None) -> None:
        self._rules = tuple(rules) if rules is not None else STRONG_REGEX_RULES

    def detect(self, text: str) -> Signal | None:
        flattened = normalize_text(text).control_stripped

        for rule in self._rules:
            if rule.pattern.search(flattened):
                return Signal(rule.action, rule.reason_code)

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