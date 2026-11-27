"""Bounded model transport and single-host generation scheduling."""

from contextlib import contextmanager
import logging
import os
from pathlib import Path
import time

import httpx

logger = logging.getLogger(__name__)


class ModelBusyError(TimeoutError):
    """Another local worker held the generation slot beyond its wait budget."""


def model_timeout_seconds() -> int:
    value = os.environ.get("CYBERTRIAGE_MODEL_TIMEOUT_SECONDS", "600")
    if not value.isdecimal() or not 30 <= int(value) <= 1800:
        raise ValueError("CYBERTRIAGE_MODEL_TIMEOUT_SECONDS must be 30-1800.")
    return int(value)


def model_http_timeout() -> httpx.Timeout:
    return httpx.Timeout(model_timeout_seconds(), connect=5.0, write=30.0, pool=5.0)


@contextmanager
def generation_slot():
    directory = Path("data/runtime")
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "model-generation.lock").open("a+b") as file:
        if file.seek(0, os.SEEK_END) == 0:
            file.write(b"\0")
            file.flush()
        deadline = time.monotonic() + model_timeout_seconds()
        acquired = False
        logger.info("Waiting for local model generation slot")
        try:
            while not acquired:
                try:
                    if os.name == "nt":
                        import msvcrt
                        file.seek(0)
                        msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                except (BlockingIOError, PermissionError):
                    if time.monotonic() >= deadline:
                        raise ModelBusyError("Local generation slot wait exceeded its budget.") from None
                    time.sleep(0.2)
            yield
        finally:
            if acquired:
                if os.name == "nt":
                    import msvcrt
                    file.seek(0)
                    msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(file.fileno(), fcntl.LOCK_UN)


def invoke_model(model, messages):
    with generation_slot():
        start = time.monotonic()
        items = messages.to_messages() if hasattr(messages,"to_messages") else messages
        message_bytes = sum(len(message.content.encode("utf-8")) for message in items if isinstance(message.content,str))
        logger.info("Model generation request started; read_timeout_seconds=%s message_bytes=%s", model_timeout_seconds(),message_bytes)
        try:
            answer = model.invoke(messages)
        except httpx.TimeoutException as error:
            logger.warning("Model generation timed out after %.1fs", time.monotonic()-start)
            raise TimeoutError("Model generation did not respond within its configured transport timeout.") from error
        metadata = answer.response_metadata if isinstance(getattr(answer,"response_metadata",None),dict) else {}
        def number(key):
            value = metadata.get(key)
            return value if type(value) is int and value>=0 else None
        def seconds(key):
            value = number(key)
            return round(value/1_000_000_000,3) if value is not None else None
        reason = metadata.get("done_reason")
        reason = reason if isinstance(reason,str) and reason in {"stop","length","load","unload"} else "other"
        output_tokens,decode_seconds = number("eval_count"),seconds("eval_duration")
        rate = round(output_tokens/decode_seconds,2) if output_tokens is not None and decode_seconds else None
        logger.info("Model response received after %.1fs finish=%s input_tokens=%s output_tokens=%s load_seconds=%s prompt_seconds=%s decode_seconds=%s tokens_per_second=%s",
            time.monotonic()-start,reason,number("prompt_eval_count"),output_tokens,seconds("load_duration"),
            seconds("prompt_eval_duration"),decode_seconds,rate)
        return answer
