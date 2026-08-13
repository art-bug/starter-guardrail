"""Small standard-library TF-IDF prototype matcher.

``PrototypeMatcher`` is opt-in when directly constructed.  The starter runtime
intentionally constructs an enabled matcher and wraps it in
``PrototypeDetector`` as a second deterministic detection layer.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from math import log, sqrt
from re import findall, finditer
from typing import Final, TypeAlias

from guardrail.normalization import normalize_text


@dataclass(frozen=True, slots=True)
class LabeledPrototype:
    label: str
    text: str

    def __post_init__(self) -> None:
        if not self.label:
            raise ValueError("prototype label must not be empty")
        if not self.text:
            raise ValueError("prototype text must not be empty")


@dataclass(frozen=True, slots=True)
class PrototypeMatch:
    nearest_attack_label: str
    nearest_attack_similarity: float
    nearest_benign_label: str
    nearest_benign_similarity: float
    margin: float

    @property
    def attack_label(self) -> str:
        return self.nearest_attack_label

    @property
    def attack_similarity(self) -> float:
        return self.nearest_attack_similarity

    @property
    def benign_label(self) -> str:
        return self.nearest_benign_label

    @property
    def benign_similarity(self) -> float:
        return self.nearest_benign_similarity


PrototypeItems: TypeAlias = Iterable[
    LabeledPrototype | tuple[str, str]
]
PrototypeInput: TypeAlias = (
    Mapping[str, str | Sequence[str]] | PrototypeItems
)
Vector: TypeAlias = dict[str, float]
MAX_NORMALIZED_QUERY_LENGTH: Final = 65_536


def _coerce_prototypes(prototypes: PrototypeInput) -> tuple[LabeledPrototype, ...]:
    if isinstance(prototypes, Mapping):
        items: list[LabeledPrototype] = []
        for label, texts in prototypes.items():
            values = (texts,) if isinstance(texts, str) else texts
            items.extend(LabeledPrototype(label, text) for text in values)
        return tuple(items)

    return tuple(
        item
        if isinstance(item, LabeledPrototype)
        else LabeledPrototype(item[0], item[1])
        for item in prototypes
    )


def _normalized_features(normalized: str) -> Counter[str]:
    features: Counter[str] = Counter()

    for size in range(3, 7):
        features.update(
            f"char:{size}:{normalized[index:index + size]}"
            for index in range(len(normalized) - size + 1)
        )

    words = findall(r"\w+", normalized)
    for size in range(1, 3):
        features.update(
            f"word:{size}:{' '.join(words[index:index + size])}"
            for index in range(len(words) - size + 1)
        )

        # Word trigrams
    for index in range(len(words) - 2):
        features[f"word:3:{' '.join(words[index:index + 3])}"] += 1

    # Prefix features
    for word in words:
        if len(word) >= 4:
            features[f"prefix:4:{word[:4]}"] += 1
        if len(word) >= 5:
            features[f"prefix:5:{word[:5]}"] += 1

    # Suffix features
    for word in words:
        if len(word) >= 4:
            features[f"suffix:4:{word[-4:]}"] += 1

    return features


def _features(text: str) -> Counter[str]:
    normalized = normalize_text(text).control_stripped
    return _normalized_features(normalized)


def _vector(features: Counter[str], idf: Mapping[str, float]) -> Vector:
    return {
        feature: count * idf[feature]
        for feature, count in features.items()
        if feature in idf
    }


def _vocabulary_vector(
        normalized: str,
        idf: Mapping[str, float],
) -> Vector:
    """Count an over-budget query without retaining out-of-vocabulary features."""

    features: Counter[str] = Counter()

    # Character n-grams (3-6) — теперь до 6, как в _normalized_features
    for size in range(3, 7):
        for index in range(len(normalized) - size + 1):
            feature = f"char:{size}:{normalized[index:index + size]}"
            if feature in idf:
                features[feature] += 1

                # Word unigrams
    for match in finditer(r"\w+", normalized):
        feature = f"word:1:{match.group()}"
        if feature in idf:
            features[feature] += 1

    # Word bigrams
    previous_word: str | None = None
    for match in finditer(r"\w+", normalized):
        word = match.group()
        if previous_word is not None:
            feature = f"word:2:{previous_word} {word}"
            if feature in idf:
                features[feature] += 1
        previous_word = word

    # Word trigrams (НОВОЕ)
    words: list[str] = []
    for match in finditer(r"\w+", normalized):
        words.append(match.group())
    for index in range(len(words) - 2):
        feature = f"word:3:{words[index]} {words[index + 1]} {words[index + 2]}"
        if feature in idf:
            features[feature] += 1

    # Prefix features (НОВОЕ)
    for word in words:
        if len(word) >= 4:
            feature = f"prefix:4:{word[:4]}"
            if feature in idf:
                features[feature] += 1
        if len(word) >= 5:
            feature = f"prefix:5:{word[:5]}"
            if feature in idf:
                features[feature] += 1

    # Suffix features (НОВОЕ)
    for word in words:
        if len(word) >= 4:
            feature = f"suffix:4:{word[-4:]}"
            if feature in idf:
                features[feature] += 1

    return _vector(features, idf)


def _cosine(left: Mapping[str, float], right: Mapping[str, float]) -> float:
    """Hybrid similarity: TF-IDF cosine + Jaccard on feature keys."""
    # Original TF-IDF cosine
    left_norm = sqrt(sum(value * value for value in left.values()))
    right_norm = sqrt(sum(value * value for value in right.values()))
    if left_norm == 0.0 or right_norm == 0.0:
        tfidf_sim = 0.0
    else:
        dot = sum(
            value * right.get(feature, 0.0)
            for feature, value in left.items()
        )
        tfidf_sim = min(1.0, max(0.0, dot / (left_norm * right_norm)))

    # Jaccard similarity on feature keys
    left_keys = set(left.keys())
    right_keys = set(right.keys())
    union = left_keys | right_keys
    if union:
        jaccard = len(left_keys & right_keys) / len(union)
    else:
        jaccard = 0.0

    # Weighted combination: TF-IDF dominant, Jaccard supplementary
    return min(1.0, max(0.0, 0.65 * tfidf_sim + 0.35 * jaccard))


class PrototypeMatcher:
    """Rank nearest attack and benign prototypes with cosine similarity."""

    def __init__(
        self,
        attack_prototypes: PrototypeInput = (),
        benign_prototypes: PrototypeInput = (),
        *,
        enabled: bool = False,
    ) -> None:
        self.enabled = enabled

        self._attack = _coerce_prototypes(attack_prototypes)
        self._benign = _coerce_prototypes(benign_prototypes)

        if enabled:
            self._require_both_classes()

        all_prototypes = self._attack + self._benign

        document_features = tuple(
            _features(prototype.text) for prototype in all_prototypes
        )
        document_count = len(document_features)
        document_frequency: Counter[str] = Counter()
        for features in document_features:
            document_frequency.update(features.keys())
        self._idf = {
            feature: log((1 + document_count) / (1 + frequency)) + 1.0
            for feature, frequency in document_frequency.items()
        }

        vectors = tuple(
            _vector(features, self._idf) for features in document_features
        )
        attack_count = len(self._attack)
        self._attack_vectors = tuple(
            zip(self._attack, vectors[:attack_count], strict=True)
        )
        self._benign_vectors = tuple(
            zip(self._benign, vectors[attack_count:], strict=True)
        )

        # Сохраняем raw features для BM25
        self._all_features = document_features

        # Вычисляем среднюю длину документа для BM25
        doc_lengths = [sum(f.values()) for f in document_features]
        self._avg_dl = sum(doc_lengths) / len(doc_lengths) if doc_lengths else 1.0

        # Сохраняем длины документов
        attack_count = len(self._attack)
        self._attack_doc_lengths = doc_lengths[:attack_count]
        self._benign_doc_lengths = doc_lengths[attack_count:]

    def _bm25_similarity(
        self,
        query_features: Counter[str],
        doc_features: Counter[str],
        doc_len: int,
        k1: float = 1.2,
        b: float = 0.75,
    ) -> float:
        """BM25 similarity score normalized to [0, 1]."""
        score = 0.0
        for feature in query_features:
            if feature not in doc_features:
                continue
            df = doc_features[feature]
            idf = self._idf.get(feature, 1.0)

            numerator = df * (k1 + 1)
            denominator = df + k1 * (1 - b + b * doc_len / self._avg_dl)
            score += idf * numerator / denominator

        # Sigmoid-like normalization to [0, 1]
        return min(1.0, score / (score + 1.0))

    def _nearest_bm25(
        self,
        query_features: Counter[str],
        prototypes: tuple[tuple[LabeledPrototype, Vector], ...],
        doc_lengths: tuple[int, ...],
    ) -> tuple[str, float]:
        """Find nearest prototype using BM25 similarity."""
        (prototype, vector), *rest = prototypes
        best_label = prototype.label
        best_similarity = self._bm25_similarity(
            query_features,
            self._all_features[0] if len(self._all_features) > 0 else Counter(),
            doc_lengths[0] if doc_lengths else 1,
        )

        for idx, ((prototype, vector), doc_len) in enumerate(zip(rest, doc_lengths[1:])):
            similarity = self._bm25_similarity(
                query_features,
                self._all_features[idx + 1] if idx + 1 < len(self._all_features) else Counter(),
                doc_len,
            )
            if similarity > best_similarity:
                best_label = prototype.label
                best_similarity = similarity

        return best_label, best_similarity

    @property
    def attack_labels(self) -> tuple[str, ...]:
        return tuple(prototype.label for prototype in self._attack)

    def _require_both_classes(self) -> None:
        if not self._attack or not self._benign:
            raise ValueError(
                "enabled matcher requires attack and benign prototypes"
            )

    @staticmethod
    def _nearest(
        query: Mapping[str, float],
        prototypes: tuple[tuple[LabeledPrototype, Vector], ...],
    ) -> tuple[str, float]:
        (prototype, vector), *prototypes = prototypes

        best_label = prototype.label
        best_similarity = _cosine(query, vector)

        for prototype, vector in prototypes:
            similarity = _cosine(query, vector)

            if similarity > best_similarity:
                best_label = prototype.label
                best_similarity = similarity

        return best_label, best_similarity

    def match(self, text: str) -> PrototypeMatch | None:
        if not self.enabled:
            return None

        normalized = normalize_text(text).control_stripped

        is_over_budget = len(normalized) > MAX_NORMALIZED_QUERY_LENGTH

        # Оригинальный TF-IDF вектор
        query = (
            _vocabulary_vector(normalized, self._idf)
            if is_over_budget
            else _vector(_normalized_features(normalized), self._idf)
        )

        # Оригинальный cosine similarity (baseline) — всегда используется
        attack_label, attack_similarity = self._nearest(
            query, self._attack_vectors
        )
        benign_label, benign_similarity = self._nearest(
            query, self._benign_vectors
        )

        # BM25 — применяем ТОЛЬКО для подтверждения уже сильных сигналов.
        # Это защищает от false positives на пустых/коротких/дефолтных запросах,
        # где cosine даёт низкий score, а BM25 через сигмоиду — ложно высокий.
        if (
                not is_over_budget
                and 0.45 <= attack_similarity < 0.65
                and len(query) >= 10
        ):
            query_features = _normalized_features(normalized)

            # BM25 для attack — только amplification
            bm25_attack_label, bm25_attack_sim = self._nearest_bm25(
                query_features,
                self._attack_vectors,
                self._attack_doc_lengths,
            )

            if bm25_attack_sim > attack_similarity:
                attack_label = bm25_attack_label
                attack_similarity = bm25_attack_sim

        # Для benign: применяем BM25 только если benign similarity подозрительно высокая
        # (это значит, что benign prototype слишком близок и может дать false positive).
        # BM25 может дать более низкий score, увеличив margin.
        if (
                not is_over_budget
                and benign_similarity > 0.55
                and len(query) >= 15
        ):
            query_features = _normalized_features(normalized)
            bm25_benign_label, bm25_benign_sim = self._nearest_bm25(
                query_features,
                self._benign_vectors,
                self._benign_doc_lengths,
            )

            if bm25_benign_sim < benign_similarity:
                benign_label = bm25_benign_label
                benign_similarity = bm25_benign_sim

        return PrototypeMatch(
            nearest_attack_label=attack_label,
            nearest_attack_similarity=attack_similarity,
            nearest_benign_label=benign_label,
            nearest_benign_similarity=benign_similarity,
            margin=attack_similarity - benign_similarity,
        )
