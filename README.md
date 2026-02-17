# BankScout – Cyber Incident Response Agent

A **fully local**, banking-grade incident response agent that ingests security alerts (SIEM/EDR), runs anomaly detection and UEBA, and generates step-by-step playbooks. Built for environments where data must stay on-prem and no external APIs are allowed.

## Quick start

```bash
# Clone and enter the repo
cd BankScout

# Create virtualenv and install dependencies
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Start the API
uvicorn main:app --reload --port 8000
```

- **API docs:** http://127.0.0.1:8000/docs  
- **Ingest logs:** `POST /ingest` with a JSON array of `{ "timestamp", "user", "ip", "event_type", "device" }`  
- **Run analysis:** `GET /analyze` — returns risk/fidelity scores, correlation, and playbooks  

## Optional: LLM playbooks (Ollama)

For LLM-generated Barclays-style playbooks, run [Ollama](https://ollama.com) locally and pull a model (e.g. `ollama pull llama3`). Then:

```bash
USE_LLM_PLAYBOOK=1 uvicorn main:app --reload --port 8000
```

## Tech

- **PyOD** + **tsfresh** (anomaly + UEBA) · **FastAPI** · **LangChain/LangGraph** + **Ollama** (local LLM) · optional **Elasticsearch**

For abstract, methodology, and future scope, see **[docs_Barclays_CIR_Agent_Documentation.md](docs_Barclays_CIR_Agent_Documentation.md)**.
