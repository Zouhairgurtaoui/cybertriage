"""Reuses the existing bounded model/tools processor and leased completion boundary."""

from cybertriage.application.policies.stored_investigation import ReadOnlyStoredInvestigationPlanner
from cybertriage.application.use_cases.process_analysis_job import ProcessAnalysisJob
from cybertriage.domain.agent import StoredInvestigationPlan, validate_investigation_task


class RequestedInvestigationPlanner:
    def __init__(self, task: str):
        self._task = task

    def plan(self, alert, group_context=None):
        base = ReadOnlyStoredInvestigationPlanner().plan(alert, group_context)
        task = validate_investigation_task(base.task + "\nAnalyst investigation objective:\n" + self._task)
        return StoredInvestigationPlan(task, base.scope)


class ProcessRequestedInvestigation:
    def __init__(self, queue, reader, analyzer, grounder, group_reader):
        self._queue, self._reader, self._analyzer = queue, reader, analyzer
        self._grounder, self._groups = grounder, group_reader

    def execute(self, job):
        context = self._queue.processing_context(job)
        processor = ProcessAnalysisJob(self._reader, self._analyzer, self._queue, group_reader=self._groups,
            grounder=self._grounder, investigation_planner=RequestedInvestigationPlanner(context["task"]))
        return processor.execute(job)
