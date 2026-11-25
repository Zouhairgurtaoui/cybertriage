import logging
import math
from threading import Event, Thread

from cybertriage.application.ports.jobs import (
    ClaimedJobProcessor,
    JobClaimer,
    JobFailureRecorder,
    JobLeaseRenewer,
)
from cybertriage.domain.alert import (
    AlertNotFoundError,
    InvalidAlertError,
)
from cybertriage.domain.jobs import (
    ClaimedAnalysisJob,
    JobLeaseLostError,
    JobStorageError,
)


logger = logging.getLogger(__name__)


class AnalysisWorker:
    def __init__(
        self,
        claimer: JobClaimer,
        renewer: JobLeaseRenewer,
        failures: JobFailureRecorder,
        processor: ClaimedJobProcessor,
        *,
        lease_seconds: int = 600,
        max_attempts: int = 3,
        retry_delay_seconds: int = 30,
        poll_seconds: float = 2.0,
    ):
        if (
            type(lease_seconds) is not int
            or not 30 <= lease_seconds <= 86400
        ):
            raise ValueError(
                "Worker lease_seconds must be between 30 and 86400."
            )

        if type(max_attempts) is not int or max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer.")

        if (
            type(retry_delay_seconds) is not int
            or not 0 <= retry_delay_seconds <= 86400
        ):
            raise ValueError(
                "retry_delay_seconds must be between 0 and 86400."
            )

        if not math.isfinite(poll_seconds) or poll_seconds <= 0:
            raise ValueError("poll_seconds must be finite and positive.")

        self._claimer = claimer
        self._renewer = renewer
        self._failures = failures
        self._processor = processor

        self._lease_seconds = lease_seconds
        self._max_attempts = max_attempts
        self._retry_delay_seconds = retry_delay_seconds
        self._poll_seconds = poll_seconds

    def run(self, stop: Event, *, once: bool = False) -> None:
        logger.info("Analysis worker started")

        while not stop.is_set():
            try:
                job = self._claimer.claim_next(
                    lease_seconds=self._lease_seconds,
                    max_attempts=self._max_attempts,
                )

            except JobStorageError:
                logger.error("Analysis queue is unavailable")

                if once:
                    raise

                stop.wait(self._poll_seconds)
                continue

            if job is None:
                if once:
                    logger.info("No eligible analysis job")
                    return

                stop.wait(self._poll_seconds)
                continue

            self._process(job)

            if once:
                return

        logger.info("Analysis worker stopped")

    def _heartbeat(
        self,
        job: ClaimedAnalysisJob,
        finished: Event,
    ) -> None:
        interval = min(30.0, self._lease_seconds / 3)

        while not finished.wait(interval):
            try:
                self._renewer.renew(
                    job,
                    lease_seconds=self._lease_seconds,
                )

            except JobLeaseLostError:
                # Completion also checks ownership before saving.
                return

            except JobStorageError:
                logger.warning(
                    "Lease renewal unavailable job=%s",
                    job.job_id,
                )

    def _process(self, job: ClaimedAnalysisJob) -> None:
        logger.info(
            "Claimed job=%s alert=%s attempt=%s",
            job.job_id,
            job.alert_record_id,
            job.attempt_count,
        )

        finished = Event()
        heartbeat = Thread(
            target=self._heartbeat,
            args=(job, finished),
            name="analysis-lease-heartbeat",
            daemon=True,
        )
        heartbeat.start()

        try:
            record = self._processor.execute(job)

            logger.info(
                "Completed job=%s analysis=%s",
                job.job_id,
                record.analysis_id,
            )

        except JobLeaseLostError:
            logger.warning(
                "Discarded result because claim is no longer valid job=%s",
                job.job_id,
            )

        except JobStorageError:
            # Do not assume whether completion committed.
            # A committed job is already completed; otherwise its lease
            # can expire and allow recovery.
            logger.error(
                "Job storage operation failed; recovery may be needed job=%s",
                job.job_id,
            )

        except (AlertNotFoundError, InvalidAlertError, ValueError):
            self._record_failure(
                job,
                error_code="invalid_input",
                retryable=False,
            )

        except Exception as error:
            # Log the exception class, not potentially sensitive messages.
            logger.warning(
                "Analysis attempt failed job=%s error_type=%s",
                job.job_id,
                type(error).__name__,
            )

            self._record_failure(
                job,
                error_code="analysis_failed",
                retryable=True,
            )

        finally:
            finished.set()
            heartbeat.join()

    def _record_failure(
        self,
        job: ClaimedAnalysisJob,
        *,
        error_code: str,
        retryable: bool,
    ) -> None:
        delay = min(
            self._retry_delay_seconds
            * (2 ** min(job.attempt_count - 1, 10)),
            86400,
        )

        try:
            self._failures.fail(
                job,
                error_code=error_code,
                retryable=retryable,
                max_attempts=self._max_attempts,
                retry_delay_seconds=delay,
            )

            status = (
                "pending"
                if retryable and job.attempt_count < self._max_attempts
                else "failed"
            )

            logger.warning(
                "Recorded failure job=%s status=%s code=%s",
                job.job_id,
                status,
                error_code,
            )

        except JobLeaseLostError:
            logger.warning(
                "Could not record failure: claim no longer valid job=%s",
                job.job_id,
            )

        except JobStorageError:
            logger.error(
                "Could not persist failure; lease recovery required job=%s",
                job.job_id,
            )