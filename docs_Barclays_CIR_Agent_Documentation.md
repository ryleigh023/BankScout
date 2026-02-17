## Abstract

This project presents a fully local, banking-grade cyber incident response agent designed for environments such as Barclays where data residency, regulatory compliance, and security assurance are paramount. The agent ingests heterogeneous alerts from SIEM and EDR sources, applies anomaly detection (PyOD) and behavioural analytics (UEBA via tsfresh), and enriches findings with optional Elasticsearch-based correlation. A LangChain/LangGraph-driven playbook engine, backed by locally hosted Ollama LLMs, generates stepwise, context-aware response plans aligned to high-value banking assets and fraud vectors. The entire pipeline is offline, transparent, and auditable, favouring explainable scoring and modular design for secure extension across global banking estates.

## Methodology

### Scalability

- **Stream-oriented architecture**: The agent is structured around a streaming ingestion and analysis model where SIEM/EDR alerts are batched but processed in a stateless FastAPI service. This allows horizontal scaling via multiple API replicas behind an internal load balancer.
- **Elastic indexing**: Logs and derived user/incident records can be optionally indexed into a local Elasticsearch cluster, enabling shard-based distribution and near-real-time correlation over millions of events without changing the application code.
- **Modular engines**: Anomaly detection, UEBA, correlation, and playbook generation are implemented as separate Python modules. This separation allows individual components to be replaced (e.g., a GPU-optimised PyOD model or a different UEBA engine) without impacting the overall control plane.
- **LLM isolation**: Local LLM inference via Ollama is decoupled from request handling, enabling independent scaling of model-serving infrastructure based on demand for playbook generation rather than raw alert volume.

### Security

- **Offline-by-design**: All analytics, scoring, and playbook generation occur within the bank’s perimeter. The codebase intentionally avoids any external HTTP calls for enrichment or LLM access; Ollama, Elasticsearch, and LangChain operate against local endpoints only.
- **Data minimisation for LLMs**: Only high-level, non-PII incident summaries are passed into the LLM layer. Detailed raw logs remain in controlled storage (JSON/Elasticsearch), reducing the risk of sensitive data propagation while still enabling rich contextual reasoning.
- **Explainable scoring**: Risk and fidelity scores are derived from transparent features (failed logins, after-hours access, UEBA deviation, anomaly flags). Each incident record retains a `signals` field showing exactly which behaviours contributed to the score, supporting auditability and regulator-facing explanations.
- **Principle of least privilege**: The agent is designed to run with read access to SIEM/EDR exports and write access only to its own storage indices. Containment and remediation steps are recommendations, not direct actions, so that operational teams can enforce separation of duties.

### Performance

- **Lightweight feature engineering**: PyOD and tsfresh are applied on aggregated per-user time-series, significantly reducing dimensionality while preserving behavioural signal. This keeps latency acceptable even under high-volume alert streams.
- **Local search acceleration**: When enabled, Elasticsearch provides low-latency search and aggregation over historical alerts, allowing the correlation engine to rapidly contextualise an incoming anomaly with weeks of prior activity.
- **Adaptive playbook generation**: The system uses a fast rule-based playbook engine by default, only escalating to LLM-based generation when local models are available or when incidents exceed defined risk/fidelity thresholds. This ensures predictable performance for routine cases while reserving LLM capacity for complex situations.
- **Asynchronous-friendly design**: Although the reference implementation is synchronous for clarity, all components are written to be easily adapted to async execution, background tasks, or message-queue-based pipelines in a production deployment.

## Future Scope

- **Richer UEBA and entity graphs**: Extend behavioural analytics from individual users to multi-entity graphs (devices, applications, branches, counterparties) using graph databases and embedding-based similarity, enabling early detection of coordinated fraud campaigns.
- **Model governance and policy controls**: Integrate model versioning, bias assessment, and policy-driven guardrails around LLM outputs to ensure that generated playbooks comply with internal standards and external regulations (e.g., PRA, FCA, GDPR).
- **Integration with SOAR and ticketing**: Provide secure connectors into internal SOAR platforms and service desks so that high-fidelity incidents automatically create enriched tickets with ready-to-execute playbooks and validation checklists.
- **Advanced banking-specific playbooks**: Curate a library of Barclays-tailored playbook templates for scenarios such as SWIFT manipulation, real-time payment fraud, insider trading alerts, and API abuse, combining deterministic runbooks with LLM-assisted customisation.
- **Privacy-preserving analytics**: Explore differential privacy and secure enclaves for cross-entity modelling, allowing the bank to leverage global behavioural trends across regions while tightly controlling exposure of customer-identifiable information.

