from collections.abc import Mapping, Sequence
from typing import Protocol

from cybertriage.domain.case import IncidentCase
from cybertriage.domain.graph import CaseGraph, CaseGraphSnapshot, GraphProjectionReceipt


class CaseGraphReader(Protocol):
    def snapshot(self, case_id: str) -> CaseGraphSnapshot: ...
    def current_version(self, case_id: str) -> int: ...


class CaseGraphSink(Protocol):
    def publish(self, graph: CaseGraph) -> GraphProjectionReceipt: ...


class CaseStageRepository(Protocol):
    def add_stage(self, case_id: str, stage: str, kind: str, supporting_ids: Sequence[str], expected_version: int,
                  actor: str, reason: str) -> Mapping[str, object]: ...
    def review_stage(self, case_id: str, assertion_id: str, decision: str, expected_version: int,
                     actor: str, reason: str) -> IncidentCase: ...
    def stages(self, case_id: str, limit: int, after: int) -> Mapping[str, object]: ...
