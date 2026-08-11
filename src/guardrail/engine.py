"""Orchestration for the intentionally weak starter guardrail."""

from __future__ import annotations

from collections.abc import Sequence

from common import GuardrailDecision, GuardrailRequest, Action, ReasonCode
from guardrail.detectors import Detector, OrderedKeywordDetector, Signal
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
        signals: list[Signal] = []

        # Обработка активного сообщения
        msg_text = normalize_text(request.message).control_stripped
        for detector in self._detectors:
            sig = detector.detect(msg_text)
            if sig:
                signals.append(sig)

        # Обработка evidence – только keyword, или с завышенным порогом
        evidence_detector = OrderedKeywordDetector()  # только ключевые слова
        for ev in request.evidence:
            ev_text = normalize_text(ev.text).control_stripped
            sig = evidence_detector.detect(ev_text)
            if sig:
                # Сигнал из цитаты можно игнорировать или помечать как ALLOW
                signals.append(Signal(Action.ALLOW, ReasonCode.ORDINARY_SUPPORT))

        return self._policy.decide(signals, request.context.route)
