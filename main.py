from concurrent.futures import TimeoutError as FuturesTimeoutError
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List

from fastapi import FastAPI
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.docs import get_swagger_ui_html

from models import SecurityLog
from storage import save_logs, load_logs
from anomaly_engine import detect_anomalies
from risk_engine import compute_risk
from correlation_engine import correlate_patterns
from playbook_engine import generate_playbook
from ueba_engine import compute_ueba_scores

app = FastAPI(title="Barclays AI Cyber Agent", docs_url=None)  # we serve custom /docs below

# Where to edit how /docs looks: project folder "static" -> docs-theme.css
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/docs", include_in_schema=False)
def custom_swagger_ui():
    html_resp = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " – API Docs",
    )
    # Load our theme last so it overrides Swagger UI defaults (edit static/docs-theme.css)
    # Cache-bust so theme updates show without hard refresh
    inject = (
        '<link href="https://fonts.googleapis.com/css2?family=Fira+Code&family=JetBrains+Mono&display=swap" rel="stylesheet" />'
        '\n<link rel="stylesheet" href="/static/docs-theme.css?v=2">'
    )
    decoded = html_resp.body.decode("utf-8")
    # Prefer end of body so our CSS wins over Swagger's
    if "</body>" in decoded:
        decoded = decoded.replace("</body>", inject + "\n</body>")
    else:
        decoded = decoded.replace("</head>", inject + "\n</head>")
    return HTMLResponse(decoded)


@app.post("/ingest")
def ingest_logs(logs: List[SecurityLog]):
    """
    Ingest raw security alerts/logs from SIEM, EDR, or other banking systems.

    Logs are durably stored locally and optionally indexed into Elasticsearch.
    """
    log_dicts = [log.dict() for log in logs]
    save_logs(log_dicts)

    return {
        "status": "success",
        "logs_received": len(log_dicts),
    }


@app.get("/analyze")
def analyze_logs():
    """
    End-to-end analysis pipeline:
      1. Load ingested logs
      2. Run anomaly detection (PyOD)
      3. Compute UEBA scores (tsfresh + PyOD)
      4. Attach risk & fidelity scores
      5. Correlate into incident-style views
      6. Generate a tailored response playbook (LLM/rule-based)
    """
    try:
        logs = load_logs()
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Failed to load logs", "detail": str(e)})

    if not logs:
        return {"error": "No logs available"}

    try:
        # 1) Per-user anomaly detection
        user_records = detect_anomalies(logs)
        if not user_records:
            return {"total_users": 0, "analysis": [], "message": "No user aggregates from logs"}

        # 2) Behavioural analytics via UEBA (time-bounded so docs never hang)
        try:
            with ThreadPoolExecutor(max_workers=1) as ex:
                future = ex.submit(compute_ueba_scores, logs)
                ueba_scores = future.result(timeout=15)
        except (FuturesTimeoutError, Exception):
            ueba_scores = {}
        for record in user_records:
            user_id = record.get("user")
            record["ueba_score"] = ueba_scores.get(user_id, 0.0)

        # 3) Risk and fidelity scoring
        user_records = compute_risk(user_records)

        # 4) Cross-entity correlation
        user_records = correlate_patterns(user_records)

        # 5) Attach playbooks
        for record in user_records:
            record["playbook"] = generate_playbook(record)

        return {
            "total_users": len(user_records),
            "analysis": user_records,
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": "Analysis pipeline failed", "detail": str(e)},
        )


@app.get("/")
def root():
    return {"message": "Barclays AI Cyber Agent Running"}

