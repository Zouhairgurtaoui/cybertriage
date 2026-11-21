# Experiment 001: Local model baseline

## Objective

Determine whether a lightweight local model can produce a complete, cautious
assessment of a synthetic SSH authentication alert, and measure response time.
This tests the model alone: no RAG, agent loop, webhook, or live Wazuh access.

## Evidence and provenance

Recorded on 21 November 2026 from terminal output supplied by the project author
in the guided project discussion. These are manually reported runs, not an
automated benchmark. Exact execution timestamps, model digests, full runtime
configuration, and complete raw output files were not captured.

The [prompt](../../examples/prompts/ssh-baseline.txt) is synthetic and contains
no production logs. The response excerpts below are quoted from the supplied output.

## Environment reported

| Component | Configuration |
|---|---|
| Host | Huawei laptop running Windows |
| CPU | Intel Core i5-1340P; 12 cores, 16 logical processors |
| RAM | Approximately 40 GB |
| GPU | Integrated Intel Iris Xe; shared system memory |
| Storage | Approximately 1 TB; NVMe SSD shown in Task Manager |
| Wazuh | Linux VM allocated 8 GB RAM on the same laptop |
| Ollama | CLI reported version 0.40.17 |
| Inference backend | Not captured; CPU/GPU split is unverified |
| Background load | Not controlled or recorded for the tests |

Wazuh VM allocation is known, but its running state during each test was not recorded.
The observed model loading times are very short; these results do not measure
a cold application start or model download time.

## Method

The author submitted the baseline prompt through the Ollama CLI with verbose
statistics and shared each completed response and its timing output.
The final comparison uses one completed run per variant. It does not include
the separate, truncated API experiments described below.

Both final responses contained the requested four sections and concluded that
the supplied evidence did not confirm compromise. Quality was reviewed manually,
without a formal score or independent SOC reviewer.

## Completed-run measurements

| Metric | `qwen3:4b` | `qwen3:4b-instruct` |
|---|---:|---:|
| Total duration | 6m50.9434052s | 1m11.7674055s |
| Load duration | 11.1932 ms | 9.6173 ms |
| Prompt tokens | 127 | 125 |
| Prompt evaluation duration | 2.26219s | 2.11144s |
| Prompt evaluation rate | 56.14 tokens/s | 59.20 tokens/s |
| Generated tokens | 2,672 | 566 |
| Generation duration | 6m48.662193s | 1m9.637488s |
| Generation rate | 6.54 tokens/s | 8.13 tokens/s |

The Instruct run was approximately 5.73 times faster in total elapsed time.
It generated approximately 79% fewer tokens. Generation throughput increased
by approximately 24%. Most of the elapsed-time reduction came from fewer
generated tokens, rather than a similar increase in tokens per second.

Generated-token counts do not, by themselves, separate thinking and final-answer
tokens. These measurements do not establish that either model is consistently
faster across different alerts or repeated runs.

## Response review: `qwen3:4b`

Positive behavior:

- Followed the requested report structure.
- Listed missing timestamps, MFA information, and post-login activity.
- Did not confirm compromise from the supplied evidence alone.

Issues observed:

- Described the success as "likely the 25th try". The evidence does not establish
  that the provided events are a complete, consecutive sequence.
- Mentioned credential stuffing and a password reset as possible explanations
  without supporting evidence for either mechanism.
- Listed a malicious source IP as an example of evidence for confirmation.
  Malicious-IP reputation can support suspicion but cannot independently prove
  that this particular account was compromised.

Representative conclusion excerpt:

> No. The evidence shows 24 failed SSH attempts followed by a single successful login from the same IP, but it does not confirm compromise.

## Response review: `qwen3:4b-instruct`

Positive behavior:

- Produced a complete answer directly in the submitted output.
- Followed all four requested sections.
- Recommended reviewing timestamps, authentication context, and session activity.
- Explicitly stated that account compromise was unconfirmed.

Issues observed:

> The failed attempts were part of a brute-force attack targeting user "alice,"

This states a hypothesis as a fact. A better formulation is that the failures
could be consistent with password guessing; the alert alone does not establish it.

> The same IP may be a trusted internal system or a legitimate user device, making the attack less likely to be malicious.

Internal or previously trusted devices can themselves be compromised. Such context
should be investigated rather than treated as evidence that activity is benign.

The answer also proposed password changes/resets and credential reuse without
evidence supporting those particular explanations. These should remain explicitly
unsupported possibilities, not reasons to lower concern.

## Diagnostic attempts and lessons

Before the completed comparison, the author estimated an initial response at about
20 minutes. That estimate had no captured statistics and is excluded from the table.
It should not be reported as a measured benchmark.

Two separate API tests set `think = false`, a context limit of 2,048 tokens,
and an output limit of 120 tokens. Reported results were:

| Metric | API attempt 1 | API attempt 2 |
|---|---:|---:|
| Total duration, nanoseconds | 13,196,378,600 | 11,891,761,000 |
| Load duration, nanoseconds | 12,561,300 | 10,635,100 |
| Generated tokens | 120 | 120 |
| Generation duration, nanoseconds | 13,057,590,000 | 11,739,522,000 |
| Observed output | Incomplete planning commentary | Incomplete planning commentary |

The second result explicitly reported `done = True` and `done_reason = length`.
The first result also reached exactly 120 tokens, but its stopping reason was
not supplied. These truncated outputs are not successful completed answers and
must not be compared directly against the full-answer latencies.

The planning text included invented assumptions about the user's feelings and
role. One attempt also claimed SSH failures trigger lockouts or rate limiting;
those controls depend on configuration and must not be assumed.

The installed `qwen3:4b` metadata reported Q4_K_M quantization, a context length
of 262,144, and thinking levels containing only `true`, enabled by default.
That context figure was model metadata, not evidence that the test used that
many tokens. Earlier advice assumed `think = false` would disable thinking;
the observed configuration and results did not support that assumption.

A standalone `/no_think` line was rejected by the CLI as an unknown command.
Appending it to the question passed it as prompt text, but the supplied output
still began with thinking text and ended without completed statistics.
Neither attempt demonstrated successful disabling of thinking.

The lesson is to verify the exact model variant and runtime controls rather
than assuming all similarly named tags behave like the original model card.
The replacement was selected as an explicitly non-thinking variant; this is a
model comparison, not a successful toggle within the first model.

## Decision and limitations

Use `qwen3:4b-instruct` provisionally for the next learning exercise.
See [Decision 001](../decisions/001-local-model-selection.md).

A roughly 72-second answer is an improvement, but several sequential calls could
still take minutes. There is no evidence yet for tool-call reliability, RAG
grounding, injection resistance, or incident-correlation accuracy. A structured
answer and a cautious conclusion do not guarantee correct intermediate claims.

## Next experiment

Build a small Python API client as a guided exercise. It should record the prompt,
model identity, generation options, response, stop reason, and timing statistics.
Then repeat the same test in independent conversations before reporting an average
or median. Record backend allocation and background VM load. Evaluate concise
answers separately from full reports, and add benign/ambiguous cases before tools.

## References

- [Ollama model: qwen3:4b-instruct](https://ollama.com/library/qwen3:4b-instruct)
- [Qwen Instruct-2507 model card: non-thinking behavior](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507)
- [Ollama generation API and timing fields](https://docs.ollama.com/api/generate)
