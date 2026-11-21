# Decision 001: Provisional local model selection

Status: provisional. Recorded: 21 November 2026.

## Context

CyberTriage is a learning project running on a laptop with an Intel i5-1340P,
approximately 40 GB RAM, and integrated Iris Xe graphics. A Wazuh VM shares
the host and is allocated 8 GB RAM. Model evaluation needs to account for
both answer quality and the latency of several calls in an investigation.

## Decision

Use `qwen3:4b-instruct` as the provisional baseline for the first Python client.
The model is locally hosted through Ollama. Its weights remain outside Git.

The upstream Qwen Instruct-2507 variant explicitly supports non-thinking output.
In one completed manual SSH-alert test, the selected candidate returned an answer
in approximately 72 seconds, compared with 411 seconds for the tested `qwen3:4b`.
The complete measurements and reasoning issues are recorded in
[Experiment 001](../experiments/001-local-model-baseline.md).

## Alternatives considered

- Continue with the tested `qwen3:4b`: completed output took nearly seven minutes,
  and attempts to disable thinking did not produce a verified direct answer.
- Try a smaller or another non-thinking model: remains an option if latency or
  tool reliability is inadequate; no such alternative has been measured yet.
- Use a hosted model: remains an option, but introduces provider, cost, and data
  handling decisions; it is unnecessary for the initial local learning exercise.

## Consequences and review criteria

This is not a production approval or a claim of cybersecurity expertise.
Unsupported statements remained in the selected model's response. Review the
choice after repeatable latency tests, fact-versus-hypothesis checks, and later
structured-output and tool-calling tests. Change models if those results justify it.

Installation and usage commands belong in the root README. This document records
why the choice was made, rather than duplicating setup instructions.
