# Multi-Agent Cyber Threat Intelligence & Risk Analysis System

This project presents a multi-agent based system designed to improve cyber threat intelligence (CTI) and dynamic risk analysis for critical systems.

## Overview

Modern cyber threat intelligence involves large volumes of heterogeneous data from multiple sources such as vulnerability databases (CVE) and threat feeds (e.g., URLhaus, Dark Web). These sources are often analyzed independently, which limits the ability to assess real-world risk accurately.

This project proposes a multi-agent architecture that correlates data from different sources and performs contextual risk analysis.

## Key Features

- Multi-agent architecture for modular data processing
- Integration of multiple threat intelligence sources (CVE, URLhaus, Dark Web)
- Graph-based relationship modeling
- Dynamic risk scoring mechanism
- Context-aware vulnerability prioritization

## Risk Model

The system uses a weighted risk scoring model:

Risk = w1·CVSS + w2·Exploit + w3·Recency + w4·Centrality

Where:

- CVSS: Technical severity of the vulnerability
- Exploit: Presence of active exploitation indicators
- Recency: Freshness of the vulnerability
- Centrality: Importance in the threat graph

Initial weights:

- w1 = 0.4
- w2 = 0.3
- w3 = 0.2
- w4 = 0.1

These weights are subject to optimization based on experimental results.

## Architecture

The system consists of the following components:

- Data Collection Agents
- Processing Layer
- Graph Model
- Risk Analysis Engine
- Output / Reporting Layer

## Technologies

- Go (data collection & processing)
- Python (analysis & orchestration)
- Graph-based modeling
- Threat intelligence data sources

## Repository Structure

agent-go/       -> data collection agents (Go)
agent-python/   -> analysis & orchestration (Python)

## Project Status

This project is developed as part of an academic research study and is currently in the proposal / prototype stage.

## Contribution

This project aims to provide a more realistic and context-aware approach to cyber threat analysis by combining vulnerability data with threat intelligence signals.

---

## Author

Furkan Korkmaz