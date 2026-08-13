"""Orchestration for the starter guardrail with multi-layer detection."""

from __future__ import annotations

from collections.abc import Sequence

from common import Action, GuardrailDecision, GuardrailRequest, Route
from guardrail.detectors import (
    Detector,
    FuzzyKeywordDetector,
    OrderedKeywordDetector,
    StrongRegexDetector,
)
from guardrail.normalization import normalize_text
from guardrail.policy import ROUTE_ALLOW_REASONS, StarterPolicy
from guardrail.vector_detector import create_starter_prototype_detector


class StarterGuardrail:
    """Five-layer detection: exact → regex → fuzzy → vector → allow."""

    def __init__(
        self,
        detectors: Sequence[Detector] | None = None,
        policy: StarterPolicy | None = None,
    ) -> None:
        self._custom_detectors = (
            tuple(detectors) if detectors is not None else None
        )

        # Layer 1: Exact keyword matching
        self._keyword_detector = OrderedKeywordDetector()

        # Layer 2: Regex pattern matching
        self._regex_detector = StrongRegexDetector()

        # Layer 3: Fuzzy keyword matching
        self._fuzzy_detector = FuzzyKeywordDetector(max_distance=2)

        # Layer 4: Vector prototype matching
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

        # Layer 1: Exact keyword match
        keyword_signal = self._keyword_detector.detect(text)
        if keyword_signal is not None:
            return GuardrailDecision(
                action=Action.BLOCK,
                reason_code=keyword_signal.reason_code,
                policy_version=self._policy.policy_version,
            )

        # Layer 2: Regex pattern match
        regex_signal = self._regex_detector.detect(text)
        if regex_signal is not None:
            return GuardrailDecision(
                action=Action.BLOCK,
                reason_code=regex_signal.reason_code,
                policy_version=self._policy.policy_version,
            )

        # Layer 3: Fuzzy keyword match
        fuzzy_signal = self._fuzzy_detector.detect(text)
        if fuzzy_signal is not None:
            return GuardrailDecision(
                action=Action.BLOCK,
                reason_code=fuzzy_signal.reason_code,
                policy_version=self._policy.policy_version,
            )

        # Layer 4: Vector prototype match with route-aware thresholds
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