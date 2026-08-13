"""Orchestration for the starter guardrail with route-aware detection."""

from __future__ import annotations

from collections.abc import Sequence

from common import Action, GuardrailDecision, GuardrailRequest, Route
from guardrail.detectors import (
    Detector,
    FuzzyKeywordDetector,
    OrderedKeywordDetector,
)
from guardrail.normalization import normalize_text
from guardrail.policy import ROUTE_ALLOW_REASONS, StarterPolicy
from guardrail.vector_detector import create_starter_prototype_detector


class StarterGuardrail:
    """Normalize, detect with keyword + vector, and fuse with route awareness."""

    def __init__(
        self,
        detectors: Sequence[Detector] | None = None,
        policy: StarterPolicy | None = None,
    ) -> None:
        self._custom_detectors = (
            tuple(detectors) if detectors is not None else None
        )

        # Layer 1: Exact keyword matching (baseline)
        self._keyword_detector = OrderedKeywordDetector()

        # Layer 2: Fuzzy keyword matching (catches obfuscation)
        self._fuzzy_detector = FuzzyKeywordDetector()

        # Layer 3: Vector prototype matching
        self._vector_detector = create_starter_prototype_detector()

        self._policy = policy or StarterPolicy()

    def check(self, request: GuardrailRequest) -> GuardrailDecision:
        text = normalize_text(request.message or "").control_stripped
        route_str = str(request.context.route.value) if hasattr(request.context.route, 'value') else str(request.context.route)

        # Custom detectors path
        if self._custom_detectors is not None:
            signals = []
            for detector in self._custom_detectors:
                signal = detector.detect(text)
                if signal is not None:
                    signals.append(signal)
            return self._policy.decide(signals, request.context.route)

        # Layer 1: Exact keyword match (highest priority)
        keyword_signal = self._keyword_detector.detect(text)
        if keyword_signal is not None:
            return GuardrailDecision(
                action=Action.BLOCK,
                reason_code=keyword_signal.reason_code,
                policy_version=self._policy.policy_version,
            )

        # Layer 2: Fuzzy keyword match
        fuzzy_signal = self._fuzzy_detector.detect(text)
        if fuzzy_signal is not None:
            return GuardrailDecision(
                action=Action.BLOCK,
                reason_code=fuzzy_signal.reason_code,
                policy_version=self._policy.policy_version,
            )

        # Layer 3: Vector prototype match with route-aware thresholds
        vector_signal = self._vector_detector.detect(text, route=route_str)
        if vector_signal is not None:
            return GuardrailDecision(
                action=Action.BLOCK,
                reason_code=vector_signal.reason_code,
                policy_version=self._policy.policy_version,
            )

        # Default: allow by route
        return GuardrailDecision(
            action=Action.ALLOW,
            reason_code=ROUTE_ALLOW_REASONS[Route(request.context.route)],
            policy_version=self._policy.policy_version,
        )