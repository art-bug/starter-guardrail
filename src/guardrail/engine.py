"""Orchestration for the intentionally weak starter guardrail."""

from __future__ import annotations

import re
from collections.abc import Sequence

from common import Action, GuardrailDecision, GuardrailRequest, ReasonCode, Route
from guardrail.detectors import (
    Detector,
    OrderedKeywordDetector,
    StrongRegexDetector,
    WEAK_KEYWORD_RULES,
)
from guardrail.normalization import normalize_text
from guardrail.policy import ROUTE_ALLOW_REASONS, StarterPolicy
from guardrail.vector_detector import create_starter_prototype_detector


_INLINE_QUOTE_RE = re.compile(
    r"(?s)(?:\"[^\"]{0,4000}\"|“[^”]{0,4000}”|`[^`]{0,4000}`|\[quote[^\]]*\].*?\[/quote\])",
    re.IGNORECASE,
)

_QUOTED_LINE_RE = re.compile(
    r"(?im)^\s*(?:>|\|).*$"
)

_SPACES_RE = re.compile(r"\s+")


def _remove_quoted(text: str) -> str:
    """Remove obvious quoted/evidence spans from active user intent."""

    text = _INLINE_QUOTE_RE.sub(" ", text)
    text = _QUOTED_LINE_RE.sub(" ", text)

    return _SPACES_RE.sub(" ", text).strip()


def _active_text(request: GuardrailRequest) -> str:
    """Extract normalized active text.

    The goal is to avoid treating quoted evidence or examples as the active
    user request. If evidence is supplied separately in the request schema,
    it should not be concatenated into this active text.
    """

    raw = normalize_text(request.message or "").control_stripped
    active = _remove_quoted(raw)

    return normalize_text(active).control_stripped


class StarterGuardrail:
    """Normalize, separate active text, detect, and fuse conservatively."""

    def __init__(self,
        detectors: Sequence[Detector] | None = None,
        policy: StarterPolicy | None = None,
    ) -> None:
        # Если кто-то явно передал detectors, сохраняем совместимость.
        self._custom_detectors = (
            tuple(detectors) if detectors is not None else None
        )

        self._strong_regex = StrongRegexDetector()
        self._weak_keywords = OrderedKeywordDetector(rules=WEAK_KEYWORD_RULES)
        self._prototype = create_starter_prototype_detector()
        self._policy = policy or StarterPolicy()

    def check(self, request: GuardrailRequest) -> GuardrailDecision:
        active = _active_text(request)
        route = Route(request.context.route)

        # Compatibility path if custom detectors were explicitly provided.
        if self._custom_detectors is not None:
            signals = []

            for detector in self._custom_detectors:
                signal = detector.detect(active)
                if signal is not None:
                    signals.append(signal)

            return self._policy.decide(signals, route)

        # 1. Strong deterministic patterns block immediately.
        strong_signal = self._strong_regex.detect(active)
        if strong_signal is not None:
            return GuardrailDecision(
                action=Action.BLOCK,
                reason_code=strong_signal.reason_code,
                policy_version=self._policy.policy_version,
            )

        # 2. Weak keywords alone do not block.
        weak_signal = self._weak_keywords.detect(active)

        # 3. Vector signal is used only if confident or corroborated.
        match = self._prototype.match(active)

        if match is not None:
            # Very confident vector-only block.
            if self._prototype.is_confident_block(match):
                return GuardrailDecision(
                    action=Action.BLOCK,
                    reason_code=ReasonCode(match.nearest_attack_label),
                    policy_version=self._policy.policy_version,
                )

            # Weaker vector block only if a matching weak keyword confirms it.
            if (
                weak_signal is not None
                and weak_signal.reason_code.value == match.nearest_attack_label
                and self._prototype.is_corroborated_block(match)
            ):
                return GuardrailDecision(
                    action=Action.BLOCK,
                    reason_code=weak_signal.reason_code,
                    policy_version=self._policy.policy_version,
                )

        # 4. Default: allow by route.
        return GuardrailDecision(
            action=Action.ALLOW,
            reason_code=ROUTE_ALLOW_REASONS[route],
            policy_version=self._policy.policy_version,
        )