"""Leased chat processing with bounded retries and heartbeat ownership checks."""

import logging
from threading import Event, Thread

from cybertriage.application.ports.case_chat import ChatQueue, ChatTurnProcessor
from cybertriage.domain.case import CaseError, CaseStorageError
from cybertriage.domain.agent import InvalidModelResponseError, IncompleteModelResponseError, ModelContextLimitError
from cybertriage.domain.case_chat import ChatClaim, ChatLeaseLostError

logger = logging.getLogger(__name__)


class CaseChatWorker:
    def __init__(self, queue: ChatQueue, processor: ChatTurnProcessor):
        self._queue, self._processor = queue, processor

    def run(self, stop: Event, *, once=False):
        while not stop.is_set():
            try:
                claim = self._queue.claim()
            except CaseStorageError:
                logger.error("Case conversation storage unavailable")
                if once:
                    raise
                stop.wait(2)
                continue
            if claim is None:
                if once:
                    return
                stop.wait(2)
                continue
            finished = Event()
            thread = Thread(target=self._heartbeat, args=(claim,finished), name="case-chat-lease", daemon=True)
            thread.start()
            logger.info("Processing chat turn=%s case=%s attempt=%s", claim.turn_id, claim.case_id, claim.attempt_count)
            try:
                self._processor.execute(claim)
                logger.info("Completed chat turn=%s", claim.turn_id)
            except ChatLeaseLostError:
                logger.warning("Discarded stale chat reply turn=%s", claim.turn_id)
            except CaseStorageError:
                # Completion may have committed: let the lease/reply transaction decide recovery.
                logger.error("Chat storage outcome requires recovery turn=%s", claim.turn_id)
            except Exception as error:
                logger.warning("Chat turn failed turn=%s error_type=%s", claim.turn_id, type(error).__name__)
                try:
                    code = ("output_incomplete" if isinstance(error,IncompleteModelResponseError) else
                            "model_context_limit" if isinstance(error,ModelContextLimitError) else
                            "model_response_invalid" if isinstance(error,InvalidModelResponseError) else
                            "generation_timeout" if isinstance(error,TimeoutError) else
                            "invalid_context" if isinstance(error,(CaseError,ValueError)) else "generation_failed")
                    self._queue.fail(claim,code,not isinstance(error,(CaseError,ValueError,TimeoutError,InvalidModelResponseError)))
                except (ChatLeaseLostError, CaseStorageError):
                    logger.warning("Chat failure update unavailable turn=%s", claim.turn_id)
            finally:
                finished.set()
                thread.join()
            if once:
                return

    def _heartbeat(self, claim: ChatClaim, finished: Event):
        while not finished.wait(30):
            try:
                self._queue.renew(claim)
            except ChatLeaseLostError:
                return
            except CaseStorageError:
                logger.warning("Chat lease renewal unavailable turn=%s", claim.turn_id)
