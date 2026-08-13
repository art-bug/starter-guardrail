"""Deterministic signal fusion for the starter guardrail."""

from __future__ import annotations

from collections.abc import Iterable

from common import Action, GuardrailDecision, ReasonCode, Route
from guardrail.detectors import Signal


POLICY_VERSION = "starter-v1"

ROUTE_ALLOW_REASONS = {
    Route.APPEAL: ReasonCode.APPEAL_DECISION,
    Route.ACCOUNT_SAFETY: ReasonCode.ACCOUNT_SAFETY,
    Route.REPORT: ReasonCode.POLICY_QUESTION,
    Route.GENERAL: ReasonCode.ORDINARY_SUPPORT,
}


class StarterPolicy:
    """Choose the first detector signal, otherwise allow by route."""

    def __init__(self, policy_version: str = POLICY_VERSION) -> None:
        self.policy_version = policy_version

    def decide(self,
       signals: Iterable[Signal], route: Route
    ) -> GuardrailDecision:
        # Если есть BLOCK, возвращаем первый BLOCK
        for sig in signals:
            if sig.action == Action.BLOCK:
                return GuardrailDecision(
                    action=sig.action,
                    reason_code=sig.reason_code,
                    policy_version=self.policy_version,
                )

        # Нет сигналов – разрешаем по маршруту
        return GuardrailDecision(
            action=Action.ALLOW,
            reason_code=ROUTE_ALLOW_REASONS[Route(route)],
            policy_version=self.policy_version,
        )


def fuse_signals(
    signals: Iterable[Signal],
    route: Route,
    *,
    policy_version: str = POLICY_VERSION,
) -> GuardrailDecision:
    """Functional entry point for deterministic starter-policy fusion."""

    return StarterPolicy(policy_version).decide(signals, route)
