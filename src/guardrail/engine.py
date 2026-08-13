"""Orchestration for the intentionally weak starter guardrail."""

from __future__ import annotations

from collections.abc import Sequence

from common import GuardrailDecision, GuardrailRequest
from guardrail.detectors import Detector, OrderedKeywordDetector
from guardrail.normalization import normalize_text
from guardrail.policy import StarterPolicy
from guardrail.vector_detector import create_starter_prototype_detector


class StarterGuardrail:
    """Normalize, flatten, detect, and fuse a request."""

    def __init__(
        self,
        detectors: Sequence[Detector] | None = None,
        policy: StarterPolicy | None = None,
    ) -> None:
        self._detectors = (
            tuple(detectors)
            if detectors is not None
            else (
                OrderedKeywordDetector(),
                create_starter_prototype_detector(),
            )
        )
        self._policy = policy or StarterPolicy()

    def check(self, request: GuardrailRequest) -> GuardrailDecision:
        msg_text = normalize_text(request.message).control_stripped

        signals: list = []
        for detector in self._detectors:
            sig = detector.detect(msg_text)
            if sig is not None:
                signals.append(sig)

        return self._policy.decide(signals, request.context.route)