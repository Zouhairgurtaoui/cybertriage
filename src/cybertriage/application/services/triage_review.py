from collections import Counter, defaultdict

from cybertriage.application.ports.triage_policy import TriageReviewRepository
from cybertriage.domain.triage_policy import AnalystFeedback, TriageEvaluationRow


class ReviewTriage:
    def __init__(self, repository: TriageReviewRepository):
        self._repository = repository

    def feedback(self, feedback: AnalystFeedback):
        return self._repository.feedback(feedback)

    def release(self, alert_record_id: str, analyst: str, reason: str):
        # Validate the same operator metadata without changing an existing label.
        AnalystFeedback(alert_record_id, analyst, "uncertain", reason)
        return self._repository.release(alert_record_id, analyst, reason)

    def inspect(self, alert_record_id: str):
        if not isinstance(alert_record_id, str) or not alert_record_id.strip():
            raise ValueError("An alert record ID is required.")
        return self._repository.inspect(alert_record_id)


def _metrics(rows: tuple[TriageEvaluationRow, ...]) -> dict[str, object]:
    actions = Counter(row.action for row in rows)
    reviewed = [row for row in rows if row.label in ("benign", "malicious")]
    eligible = [row for row in reviewed if row.action != "untriaged"]
    benign = sum(row.label == "benign" for row in eligible)
    malicious = sum(row.label == "malicious" for row in eligible)
    suppressed_benign = sum(row.action == "suppress" and row.label == "benign" for row in eligible)
    suppressed_malicious = sum(row.action == "suppress" and row.label == "malicious" for row in eligible)
    suppressed_reviewed = suppressed_benign + suppressed_malicious

    def rate(numerator: int, denominator: int) -> float | None:
        return numerator / denominator if denominator else None

    return {
        "alert_count": len(rows), "initial_actions": dict(actions),
        "initial_individual_jobs_avoided": actions["group"] + actions["suppress"],
        "reviewed_benign_count": benign, "reviewed_malicious_count": malicious,
        "unreviewed_count": sum(row.label is None for row in rows),
        "uncertain_count": sum(row.label == "uncertain" for row in rows),
        "label_coverage": rate(len(reviewed), len(rows)),
        "suppressed_benign_count": suppressed_benign,
        "suppressed_malicious_count": suppressed_malicious,
        "reviewed_suppression_precision": rate(suppressed_benign, suppressed_reviewed),
        "benign_suppression_rate": rate(suppressed_benign, benign),
        "benign_retention_rate": rate(benign - suppressed_benign, benign),
        "malicious_suppression_rate": rate(suppressed_malicious, malicious),
        "malicious_retention_rate": rate(malicious - suppressed_malicious, malicious),
        "suppression_label_coverage": rate(suppressed_reviewed, actions["suppress"]),
    }


class EvaluateTriage:
    def __init__(self, repository: TriageReviewRepository):
        self._repository = repository

    def execute(self) -> dict[str, object]:
        rows = self._repository.evaluation_rows()
        revisions: dict[str, list[TriageEvaluationRow]] = defaultdict(list)
        for row in rows:
            revisions[row.policy_revision].append(row)
        return {
            "basis": "Original scheduling decision and latest analyst label per alert; no model-generated ground truth.",
            "overall": _metrics(rows),
            "by_policy_revision": {key: _metrics(tuple(value)) for key, value in revisions.items()},
            "limitations": [
                "Reviewed alerts may not be representative of all alerts.",
                "Unreviewed and uncertain alerts are excluded from label-based rates.",
                "No measured token, latency, or monetary savings are inferred from job counts.",
                "Historical unsafe suppressions remain counted after an analyst releases an alert.",
                "Grouping is a scheduling optimization; these metrics do not measure attack detection recall.",
            ],
        }
