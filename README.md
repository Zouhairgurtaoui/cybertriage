# CyberTriage

An AI assistant that helps SOC analysts
investigate Wazuh security alerts.

## Overview

CyberTriage will receive alerts from Wazuh, gather relevant context,
consult cybersecurity investigation procedures, and produce a report
for a human analyst to review.

The project combines Python, a locally hosted open-weight language
model, Retrieval-Augmented Generation (RAG), and agent tools using
LangChain and LangGraph.

## Problem

A security alert is the starting point of an investigation.

An analyst still needs to examine related events, consider possible
explanations, consult procedures, and decide what to investigate next.

CyberTriage aims to support this work by organizing evidence and
suggesting next steps while making uncertainty explicit.

## Project Objectives

The planned capabilities are to:

- Receive Wazuh alerts through a webhook.
- Retrieve relevant investigation procedures using RAG.
- Let an AI agent request additional context through controlled tools.
- Generate reports that distinguish facts, hypotheses, and missing evidence.
- Include references to the evidence and procedures used.
- Evaluate investigation quality using attack simulations and benign activity
  in a controlled lab.

The initial scope will focus on authentication alerts.
Response actions will remain under human control.

## Planned Architecture

Wazuh → Webhook receiver → Investigation agent → Report → Analyst review

The agent will access a local language model, a document collection,
and investigation tools.

## Current Status

Early model evaluation and documentation.

The GitHub repository is initialized. Two local model variants have been
tested manually using a synthetic SSH alert. `qwen3:4b-instruct` is the
provisional baseline, pending further evaluation.

The Python application, RAG pipeline, agent tools, and Wazuh webhook
are not yet implemented in this repository. The manual tests did not
access Wazuh or execute investigation tools.

## Local Model Setup

The initial model tests use Ollama on the Windows host, outside the Wazuh VM.

1. Install [Ollama for Windows](https://ollama.com/download/windows).
2. Restart PowerShell. If using VS Code, close all VS Code windows and reopen
   it so its terminal inherits the updated PATH.
3. Check the installed version:

   ```powershell
   ollama --version
   ```

4. Download the selected candidate, approximately 2.5 GB:

   ```powershell
   ollama pull qwen3:4b-instruct
   ollama show qwen3:4b-instruct
   ```

5. Start a manual test with timing statistics:

   ```powershell
   ollama run qwen3:4b-instruct --verbose
   ```

   Paste the [baseline prompt](examples/prompts/ssh-baseline.txt).
   Enter `/bye` to leave the chat. Use a fresh conversation for each independent test.

Ollama exposes its local API at `http://localhost:11434`.
The model weights are managed by Ollama and are not stored in this repository.
The local model does not require a paid model API key. Runtime memory exceeds
the model download size and varies with context and execution settings.

Sources: [Windows setup](https://docs.ollama.com/windows),
[model details](https://ollama.com/library/qwen3:4b-instruct).

## Documentation

Design decisions, learning notes, experiments, and evaluation results
will be documented as the project progresses:

- [Experiment 001: local model comparison](docs/experiments/001-local-model-baseline.md)
- [Decision 001: provisional model selection](docs/decisions/001-local-model-selection.md)
- [Baseline SSH prompt](examples/prompts/ssh-baseline.txt)

Further installation, configuration, and usage instructions will be added
to this README as the corresponding components become available.
