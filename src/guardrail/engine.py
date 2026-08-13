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


_QUOTE_BLOCK_RE = re.compile(
    r"(?is)\[quote[^\]]*\].*?\[/quote\]",
    re.IGNORECASE,
)

_QUOTED_LINE_RE = re.compile(
    r"(?im)^\s*>.*$"
)

_SPACES_RE = re.compile(r"\s+")


def _remove_quoted(text: str) -> str:
    """Remove only explicit quote blocks and markdown-style quoted lines."""
    text = _QUOTE_BLOCK_RE.sub(" ", text)
    text = _QUOTED_LINE_RE.sub(" ", text)
    return _SPACES_RE.sub(" ", text).strip()


def _active_text(request: GuardrailRequest,
    *,
    remove_quoted: bool = False
) -> str:
    """Extract normalized active text.

    The goal is to avoid treating quoted evidence or examples as the active
    user request. If evidence is supplied separately in the request schema,
    it should not be concatenated into this active text.
    """

    text = normalize_text(request.message or "").control_stripped

    if remove_quoted:
        text = _remove_quoted(text)
        text = normalize_text(text).control_stripped

    return text


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
        self._keywords = OrderedKeywordDetector()
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

        # 1. Strong regex remains an immediate block.
        strong_signal = self._strong_regex.detect(active)
        if strong_signal is not None:
            return GuardrailDecision(
                action=Action.BLOCK,
                reason_code=strong_signal.reason_code,
                policy_version=self._policy.policy_version,
            )

        # 2. Original keyword rules are allowed to block again,
        # but can be suppressed only if the vector match is strongly benign.
        match = self._prototype.match(active)
        is_strongly_benign = (
            match is not None
            and match.nearest_benign_similarity >= 0.90
            and match.margin <= 0.0
        )

        keyword_signal = self._keywords.detect(active)
        if keyword_signal is not None and not is_strongly_benign:
            return GuardrailDecision(
                action=Action.BLOCK,
                reason_code=keyword_signal.reason_code,
                policy_version=self._policy.policy_version,
            )

            # 3. Vector block with near-baseline thresholds.
        if match is not None and self._prototype.is_confident_block(match):
            return GuardrailDecision(
                action=Action.BLOCK,
                reason_code=ReasonCode(match.nearest_attack_label),
                policy_version=self._policy.policy_version,
            )

        # 4. Weak keyword + vector corroboration.
        weak_signal = self._weak_keywords.detect(active)
        if (
                weak_signal is not None
                and match is not None
                and self._prototype.is_corroborated_block(match)
        ):
            return GuardrailDecision(
                action=Action.BLOCK,
                reason_code=weak_signal.reason_code,
                policy_version=self._policy.policy_version,
            )

        # 5. Default allow by route.
        return GuardrailDecision(
            action=Action.ALLOW,
            reason_code=ROUTE_ALLOW_REASONS[route],
            policy_version=self._policy.policy_version,
        )