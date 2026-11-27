from collections.abc import Callable
from langchain_ollama import ChatOllama

from cybertriage.adapters.models.triage_prompt import TRIAGE_PROMPT
from cybertriage.domain.triage import RetrievedReference
from cybertriage.adapters.models.reference_formatting import format_reference


class OllamaTriageModel:
    def __init__(self, model: ChatOllama, *, invoker: Callable | None = None):
        self._model = model
        self._invoke = invoker or (lambda client,messages: client.invoke(messages))

    def analyze(
        self,
        evidence: str,
        references: tuple[RetrievedReference, ...],
    ) -> str:
        if not evidence.strip() or len(evidence.encode("utf-8")) > 12000:
            raise ValueError("Evidence must contain 1-12000 UTF-8 bytes.")
        if len(references) > 8 or any(len(reference.text) > 4000 for reference in references):
            raise ValueError("Reference context exceeds the configured budget.")

        prompt = TRIAGE_PROMPT.invoke({
            "evidence": evidence,
            "references": self._format_references(references),
        })
        answer = self._invoke(self._model, prompt)

        if answer.response_metadata.get("done_reason") != "stop":
            raise RuntimeError(
                "The model did not finish its report normally. "
                "No partial report was accepted."
            )
        if not isinstance(answer.content, str) or not answer.content.strip():
            raise RuntimeError("The model returned an empty or non-text report.")

        return answer.content.strip()

    @staticmethod
    def _format_references(references: tuple[RetrievedReference, ...]) -> str:
        if not references:
            return "No reference material was retrieved. State this limitation; do not invent citations."
        return "\n\n".join(
            format_reference(reference, number)
            for number, reference in enumerate(references, start=1)
        )
