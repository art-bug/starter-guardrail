"""Ensemble voting orchestration for the starter guardrail."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from common import Action, GuardrailDecision, GuardrailRequest, ReasonCode, Route
from guardrail.detectors import (
    Detector,
    FuzzyKeywordDetector,
    OrderedKeywordDetector,
    StrongRegexDetector,
)
from guardrail.normalization import normalize_text
from guardrail.policy import ROUTE_ALLOW_REASONS, StarterPolicy
from guardrail.vector_detector import create_starter_prototype_detector


# Веса голосов каждого детектора
VOTE_WEIGHTS = {
    "vector_confident": 4.0,      # vector с высоким confidence — может блокировать один
    "vector_weak": 1.5,           # vector с низким confidence — нужен corroboration
    "keyword": 2.0,               # keyword detector — нужен corroboration
    "fuzzy": 1.5,                 # fuzzy matching — нужен corroboration
    "regex": 2.5,                 # regex patterns — нужен corroboration
}

# Порог для блокировки (суммарный вес голосов)
BLOCK_THRESHOLD = 3.0

# Бонус при согласии детекторов (corroboration)
CORROBORATION_MULTIPLIER = 1.8


class StarterGuardrail:
    """Ensemble voting: multiple detectors vote, agreement amplifies signal."""

    def __init__(
        self,
        detectors: Sequence[Detector] | None = None,
        policy: StarterPolicy | None = None,
    ) -> None:
        self._custom_detectors = (
            tuple(detectors) if detectors is not None else None
        )

        self._keyword_detector = OrderedKeywordDetector()
        self._fuzzy_detector = FuzzyKeywordDetector()
        self._vector_detector = create_starter_prototype_detector()
        self._regex_detector = StrongRegexDetector()
        self._policy = policy or StarterPolicy()

    def check(self, request: GuardrailRequest) -> GuardrailDecision:
        text = normalize_text(request.message or "").control_stripped
        route_str = (
            str(request.context.route.value)
            if hasattr(request.context.route, 'value')
            else str(request.context.route)
        )

        # Custom detectors path (для совместимости)
        if self._custom_detectors is not None:
            signals = []
            for detector in self._custom_detectors:
                signal = detector.detect(text)
                if signal is not None:
                    signals.append(signal)
            return self._policy.decide(signals, request.context.route)

        # Собираем голоса: {reason_code: [(weight, source), ...]}
        votes: dict[str, list[tuple[float, str]]] = defaultdict(list)

        # === Vector detector (с adaptive thresholds) ===
        vector_match = self._vector_detector.get_match(text)
        if vector_match is not None:
            attack_sim = vector_match.nearest_attack_similarity
            margin = vector_match.margin
            reason = vector_match.nearest_attack_label

            # Route-specific benign guard
            skip_vote = False
            if route_str in ("APPEAL", "ACCOUNT_SAFETY"):
                if vector_match.nearest_benign_similarity > 0.60:
                    skip_vote = True

            if not skip_vote:
                # Проверяем, прошёл ли вектор adaptive thresholds
                block = False
                if route_str in ("APPEAL", "ACCOUNT_SAFETY"):
                    if (attack_sim >= 0.70 and margin >= 0.10) or \
                       (attack_sim >= 0.60 and margin >= 0.20):
                        block = True
                elif route_str == "REPORT":
                    if (attack_sim >= 0.60 and margin >= 0.08) or \
                       (attack_sim >= 0.50 and margin >= 0.12) or \
                       (attack_sim >= 0.40 and margin >= 0.18):
                        block = True
                else:
                    if (
                        (attack_sim >= 0.65 and margin >= 0.03) or
                        (attack_sim >= 0.50 and margin >= 0.08) or
                        (attack_sim >= 0.40 and margin >= 0.12) or
                        (attack_sim >= 0.35 and margin >= 0.20) or
                        (attack_sim >= 0.30 and margin >= 0.30) or
                        (attack_sim >= 0.25 and margin >= 0.15)
                    ):
                        block = True

                if block:
                    votes[reason].append((VOTE_WEIGHTS["vector_confident"], "vector"))
                elif attack_sim >= 0.25 and margin >= 0.05:
                    # Weak vector vote
                    votes[reason].append((VOTE_WEIGHTS["vector_weak"], "vector"))

        # === Keyword detector ===
        keyword_signal = self._keyword_detector.detect(text)
        if keyword_signal is not None and keyword_signal.action == Action.BLOCK:
            votes[keyword_signal.reason_code.value].append(
                (VOTE_WEIGHTS["keyword"], "keyword")
            )

        # === Fuzzy detector ===
        fuzzy_signal = self._fuzzy_detector.detect(text)
        if fuzzy_signal is not None and fuzzy_signal.action == Action.BLOCK:
            votes[fuzzy_signal.reason_code.value].append(
                (VOTE_WEIGHTS["fuzzy"], "fuzzy")
            )

        # === Regex detector ===
        regex_signal = self._regex_detector.detect(text)
        if regex_signal is not None and regex_signal.action == Action.BLOCK:
            votes[regex_signal.reason_code.value].append(
                (VOTE_WEIGHTS["regex"], "regex")
            )

        # === Подсчёт голосов с corroboration bonus ===
        best_reason = None
        best_score = 0.0

        for reason, vote_list in votes.items():
            if not vote_list:
                continue

            # Базовый score — сумма весов
            score = sum(weight for weight, _ in vote_list)

            # Corroboration bonus: если голосовало больше одного источника
            unique_sources = len({source for _, source in vote_list})
            if unique_sources >= 2:
                score *= CORROBORATION_MULTIPLIER
            if unique_sources >= 3:
                score *= CORROBORATION_MULTIPLIER  # Двойной бонус

            if score > best_score:
                best_score = score
                best_reason = reason

        # === Решение ===
        if best_score >= BLOCK_THRESHOLD and best_reason is not None:
            return GuardrailDecision(
                action=Action.BLOCK,
                reason_code=ReasonCode(best_reason),
                policy_version=self._policy.policy_version,
            )

        # Default: allow by route
        return GuardrailDecision(
            action=Action.ALLOW,
            reason_code=ROUTE_ALLOW_REASONS[Route(request.context.route)],
            policy_version=self._policy.policy_version,
        )