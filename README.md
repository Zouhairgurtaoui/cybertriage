# CyberTriage

A learning project to build an AI assistant that helps SOC analysts
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

Planning and documentation.

The GitHub repository is initialized. The application, model integration,
and Wazuh webhook are not yet implemented in this repository.

## Documentation

Design decisions, learning notes, experiments, and evaluation results
will be documented as the project progresses.

Installation, configuration, and usage instructions will be added
to this README as the corresponding components become available.
