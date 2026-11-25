from cybertriage.application.ports.alerts import AlertReader
from cybertriage.application.ports.jobs import JobCompleter
from cybertriage.application.ports.triage_policy import AlertEvidenceGrounder, GroupEvidenceReader
from cybertriage.application.ports.triage import AlertAnalyzer
from cybertriage.application.use_cases.analyze_stored_alert import (
    AnalyzeStoredAlert,
)
from cybertriage.domain.jobs import ClaimedAnalysisJob
from cybertriage.domain.triage import AnalysisRecord


class _JobCompletionWriter:
    def __init__(
        self,
        completer: JobCompleter,
        job: ClaimedAnalysisJob,
    ):
        self._completer = completer
        self._job = job

    def save(self, record: AnalysisRecord) -> None:
        self._completer.complete(self._job, record)


class ProcessAnalysisJob:
    def __init__(
        self,
        reader: AlertReader,
        analyzer: AlertAnalyzer,
        completer: JobCompleter,
        *,
        group_reader: GroupEvidenceReader | None = None,
        grounder: AlertEvidenceGrounder | None = None,
    ):
        self._reader = reader
        self._analyzer = analyzer
        self._completer = completer
        self._group_reader = group_reader
        self._grounder = grounder

    def execute(self, job: ClaimedAnalysisJob) -> AnalysisRecord:
        investigation = AnalyzeStoredAlert(
            reader=self._reader,
            analyzer=self._analyzer,
            writer=_JobCompletionWriter(self._completer, job),
            group_reader=self._group_reader,
            grounder=self._grounder,
        )

        return investigation.execute(job.alert_record_id)
