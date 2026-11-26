"""Bounded in-memory BM25 ranking over indexed passages; no external NLP model."""

import math
import re
from collections import Counter, defaultdict

from cybertriage.domain.retrieval import IndexedPassage, KnowledgeRetrievalError

STOP_WORDS = frozenset("a an and are as at be been being by can could did do does for from had has have how i if in into is it its may more no not of on or our should so than that the their them then there these they this those to was we were what when where which who will with would you your".split())
TOKEN = re.compile(r"t\d{4}(?:\.\d{3})?|0x[0-9a-f]+|[a-z0-9_]+", re.IGNORECASE)


def tokens(text: str) -> list[str]:
    return [token for token in TOKEN.findall(text.casefold()) if token not in STOP_WORDS]


class BM25PassageIndex:
    def __init__(self, passages: tuple[IndexedPassage, ...]):
        self._lengths: dict[str, int] = {}
        self._postings: dict[str, dict[str, int]] = defaultdict(dict)
        posting_count = 0
        for passage in passages:
            reference = passage.reference
            body = reference.text.removeprefix(reference.title).lstrip()
            words = tokens(reference.title) * 2 + tokens(body)
            frequencies = Counter(words)
            posting_count += len(frequencies)
            if posting_count > 2_000_000:
                raise KnowledgeRetrievalError("Lexical index exceeds its two-million term/passage entry budget.")
            self._lengths[reference.chunk_id] = len(words)
            for term, frequency in frequencies.items():
                self._postings[term][reference.chunk_id] = frequency
        self._count = len(passages)
        self._average = sum(self._lengths.values()) / self._count if self._count else 1.0

    def rank(self, query: str, allowed: set[str], limit: int = 20) -> list[tuple[str, float]]:
        scores: dict[str, float] = defaultdict(float)
        for term in sorted(set(tokens(query))):
            postings = self._postings.get(term, {})
            frequency = len(postings)
            if not frequency:
                continue
            inverse = math.log(1 + (self._count - frequency + 0.5) / (frequency + 0.5))
            for chunk_id, count in postings.items():
                if chunk_id not in allowed:
                    continue
                denominator = count + 1.5 * (0.25 + 0.75 * self._lengths[chunk_id] / max(self._average, 1.0))
                scores[chunk_id] += inverse * count * 2.5 / denominator
        return sorted(scores.items(), key=lambda row: (-row[1], row[0]))[:limit]
