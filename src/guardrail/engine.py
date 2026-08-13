"""Orchestration for the starter guardrail with an exact baseline mode."""

from __future__ import annotations

from collections.abc import Sequence

from common import Action, GuardrailDecision, GuardrailRequest, Route
from guardrail.detectors import (
    Detector,
    OrderedKeywordDetector,
    StrongRegexDetector,
    EXACT_BASELINE_KEYWORD_RULES,
)
from guardrail.normalization import normalize_text
from guardrail.policy import ROUTE_ALLOW_REASONS, StarterPolicy
from guardrail.vector_detector import create_exact_baseline_prototype_detector


# Пока держим выключенным, чтобы измерить чистый baseline.
# Если после восстановления score захочешь добавить recall-слой,
# можно включить True.
ENABLE_EXTRA_REGEX = False


class StarterGuardrail:
    """Exact-baseline guardrail built from current code."""

    def __init__(
        self,
        detectors: Sequence[Detector] | None = None,
        policy: StarterPolicy | None = None,
    ) -> None:
        self._custom_detectors = (
            tuple(detectors) if detectors is not None else None
        )

        self._baseline_detectors = (
            OrderedKeywordDetector(rules=EXACT_BASELINE_KEYWORD_RULES),
            create_exact_baseline_prototype_detector(),
        )

        self._extra_regex = (
            StrongRegexDetector() if ENABLE_EXTRA_REGEX else None
        )

        self._policy = policy or StarterPolicy()

    def check(self, request: GuardrailRequest) -> GuardrailDecision:
        text = normalize_text(request.message or "").control_stripped
        route = Route(request.context.route)

        # Compatibility path if custom detectors were explicitly provided.
        if self._custom_detectors is not None:
            signals = []

            for detector in self._custom_detectors:
                signal = detector.detect(text)
                if signal is not None:
                    signals.append(signal)

            return self._policy.decide(signals, route)

        # Exact baseline layer.
        signals = []

        for detector in self._baseline_detectors:
            signal = detector.detect(text)
            if signal is not None:
                signals.append(signal)

        # Baseline fusion: first BLOCK wins.
        for signal in signals:
            if signal.action == Action.BLOCK:
                return GuardrailDecision(
                    action=Action.BLOCK,
                    reason_code=signal.reason_code,
                    policy_version=self._policy.policy_version,
                )

        # Optional extra recall layer, currently disabled.
        if self._extra_regex is not None:
            extra_signal = self._extra_regex.detect(text)

            if extra_signal is not None:
                return GuardrailDecision(
                    action=Action.BLOCK,
                    reason_code=extra_signal.reason_code,
                    policy_version=self._policy.policy_version,
                )

        return GuardrailDecision(
            action=Action.ALLOW,
            reason_code=ROUTE_ALLOW_REASONS[route],
            policy_version=self._policy.policy_version,
        )