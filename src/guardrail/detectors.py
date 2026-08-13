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
        (
            "ignore", "system prompt", "reveal", "secret",
            "disregard", "forget your", "override", "jailbreak",
            "prior instructions", "previous instructions", "initial prompt",
            "hidden prompt", "developer mode", "maintenance mode",
            "uncensored", "no restrictions", "bypass your rules",
            "ignore your", "disregard your", "forget your rules",
            "show me your prompt", "print your prompt", "output your rules",
            "sudo mode", "admin override", "DAN mode",
        ),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.MODERATION_EVASION,
        (
            "bypass", "evade", "avoid the filter",
            "get around", "slip past",
            "trick the filter", "trick the moderator",
            "workaround", "evade detection", "avoid detection",
            "bypass the filter", "bypass moderation",
            "evade the filter", "evade moderation",
            "hide forbidden", "hide prohibited",
            "leetspeak", "homograph", "split banned",
        ),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.GENERATE_ABUSE,
        (
            "threaten", "intimidate", "kill",
            "harass", "bully", "stalk", "torment",
            "death threat", "kill you", "hurt you",
            "write a threat", "compose a threat",
            "scare someone", "frighten someone",
            "humiliate", "dehumanize", "terrorize",
            "abusive message", "hateful message",
            "incite violence", "attack someone",
        ),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.PRIVATE_DATA_REQUEST,
        (
            "reporter identity", "private data", "home address",
            "dox", "doxx", "personal info", "personal information",
            "phone number", "social security", "medical records",
            "find someone's address", "find where someone lives",
            "reveal the identity", "real name behind",
            "IP address", "license plate", "date of birth",
            "contact details", "contact information",
            "extract personal", "get personal details",
            "without consent", "without permission",
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
    # PROMPT_OVERRIDE regex patterns
    RegexRule(
        Action.BLOCK,
        ReasonCode.PROMPT_OVERRIDE,
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\b"                                                                     
            r".{0,120}?"                                                                                                           
            r"\b(?:previous|prior|all|system|developer|initial|hidden|original|safety|content|moderation)\b"                       
            r".{0,120}?"                                                                                                           
            r"\b(?:instructions?|prompts?|rules?|guidelines?|settings?|configuration|directions?|directives?|commands?|orders?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    RegexRule(
        Action.BLOCK,
        ReasonCode.PROMPT_OVERRIDE,
        re.compile(
            r"\b(?:reveal|show|print|display|output|repeat|leak|expose|disclose|tell)\b"
            r".{0,120}?"
            r"\b(?:system\s+prompt|hidden\s+prompt|initial\s+prompt|original\s+prompt|"
            r"secret(?:\s+(?:key|token|config|settings))?|hidden\s+settings|"
            r"hidden\s+configuration|confidential\s+settings)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),

    # MODERATION_EVASION regex patterns
    RegexRule(
        Action.BLOCK,
        ReasonCode.MODERATION_EVASION,
        re.compile(
            r"\b(?:bypass|evade|circumvent|trick|fool|get\s+around|slip\s+past|avoid)\b"
            r".{0,120}?"
            r"\b(?:filter|filters|moderation|safety|safeguard|safeguards|review|detection|policy|controls?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),

    # GENERATE_ABUSE regex patterns
    RegexRule(
        Action.BLOCK,
        ReasonCode.GENERATE_ABUSE,
        re.compile(
            r"\b(?:write|draft|create|generate|compose|make|help\s+me\s+write)\b"          
            r".{0,160}?"                                                                   
            r"\b(?:threat\w*|intimidat\w*|abus\w*|harass\w*|hate\w*|violent\w*|coercive)\b"
            r".{0,160}?"                                                                   
            r"\b(?:message|text|post|comment|letter|email|content|note|language|target)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    RegexRule(
        Action.BLOCK,
        ReasonCode.GENERATE_ABUSE,
        re.compile(
            r"\b(?:threaten\w*|intimidat\w*|harass\w*|stalk\w*|bully\w*|torment\w*|scare\w*|frighten\w*)\b"  
            r".{0,140}?"                                                                                     
            r"\b(?:person|user|individual|student|coworker|neighbor|someone|somebody|them|him|her|target)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),

    # PRIVATE_DATA_REQUEST regex patterns
    RegexRule(
        Action.BLOCK,
        ReasonCode.PRIVATE_DATA_REQUEST,
        re.compile(
            r"\b(?:find|get|reveal|show|extract|retrieve|dox|leak|share|publish|look\s+up|tell)\b"
            r".{0,160}?"
            r"\b(?:home\s+address|phone\s+number|email(?:\s+address)?|location|"
            r"private\s+data|personal\s+(?:info|information|details)|contact\s+(?:info|information)|"
            r"reporter(?:'s|s)?\s+identity|identity\s+of\s+(?:the\s+)?reporter|"
            r"source(?:'s|s)?\s+identity|identity\s+of\s+(?:the\s+)?source)\b",
            re.IGNORECASE | re.DOTALL,
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


class FuzzyKeywordDetector(Detector):
    """Keyword detector with fuzzy matching to catch obfuscation."""

    def __init__(
            self,
            rules: Sequence[KeywordRule] | None = None,
            max_distance: int = 2,
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
        self._max_distance = max_distance

    def detect(self, text: str) -> Signal | None:
        flattened = normalize_text(text).control_stripped
        flattened_lower = flattened.lower()
        words = re.findall(r"\w+", flattened_lower)

        for rule in self._rules:
            for keyword in rule.keywords:
                keyword_lower = keyword.lower()

                # Exact substring match
                if keyword_lower in flattened_lower:
                    return Signal(rule.action, rule.reason_code)

                # Fuzzy match for single-word keywords
                if " " not in keyword_lower:
                    for word in words:
                        if _levenshtein(word, keyword_lower) <= self._max_distance:
                            return Signal(rule.action, rule.reason_code)

        return None