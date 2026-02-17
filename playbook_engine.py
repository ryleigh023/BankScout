import os
from concurrent.futures import TimeoutError as FuturesTimeoutError
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List

# Max seconds to wait for Ollama; then fall back to rule-based playbook
PLAYBOOK_LLM_TIMEOUT = int(os.getenv("PLAYBOOK_LLM_TIMEOUT", "20"))
# Set to "1", "true", "yes" to use Ollama for playbooks; default off so /analyze returns quickly
USE_LLM_PLAYBOOK = os.getenv("USE_LLM_PLAYBOOK", "0").lower() in ("1", "true", "yes")


def _rule_based_playbook(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fallback playbook when LLM / LangGraph is not available.
    Still produces deterministic and explainable guidance.
    """
    user = context.get("user") or context.get("primary_user") or "unknown"
    risk_score = float(context.get("risk_score", 0.0) or 0.0)
    fidelity_score = float(context.get("fidelity_score", 0.0) or 0.0)
    ueba_score = float(context.get("signals", {}).get("ueba_score", 0.0) or 0.0)

    steps: List[str] = []

    if risk_score >= 80 or fidelity_score >= 80:
        severity = "Critical"
        steps.append("1. Immediately disable user access to high-risk banking systems.")
        steps.append("2. Trigger emergency authentication reset for the user.")
        steps.append("3. Capture volatile artefacts from endpoints (EDR snapshots, memory).")
        steps.append("4. Search SIEM for lateral movement and payment-related activity.")
        steps.append("5. Notify cyber operations lead and fraud monitoring team.")
    elif risk_score >= 50:
        severity = "High"
        steps.append("1. Enforce password reset and step-up MFA for the user.")
        steps.append("2. Review last 24 hours of SWIFT/core-banking and payment activity.")
        steps.append("3. Correlate EDR alerts for the associated device/IP.")
        steps.append("4. Add targeted monitoring rule to SIEM for this user and device.")
    else:
        severity = "Medium"
        steps.append("1. Add this user to a 7-day heightened monitoring watchlist.")
        steps.append("2. Review access patterns for unusual devices or geolocations.")
        steps.append("3. Educate user on secure behaviour (phishing, password hygiene).")

    if ueba_score >= 70:
        steps.append(
            "6. UEBA indicates strong behavioural deviation – extend investigation to peer group."
        )

    return {
        "severity": severity,
        "summary": f"{severity} risk activity detected for user {user}",
        "recommended_action": steps[0],
        "steps": steps,
        "strategy": "rule_based",
    }


def _llm_playbook(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Use a local LLM via LangChain + LangGraph + Ollama to generate
    a step-by-step, Barclays-specific incident response playbook.
    """
    try:
        from langchain_community.chat_models import ChatOllama
        from langgraph.graph import END, StateGraph
    except Exception:
        # LangChain / LangGraph / Ollama not available: fall back
        return _rule_based_playbook(context)

    from typing import TypedDict

    class PlaybookState(TypedDict):
        incident_summary: str
        playbook: str

    model_name = os.getenv("OLLAMA_MODEL", "llama3")
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    # Prevent hanging: timeout request to Ollama (seconds); not all LangChain versions support this
    request_timeout = min(120, max(5, PLAYBOOK_LLM_TIMEOUT))
    try:
        llm = ChatOllama(
            model=model_name,
            base_url=base_url,
            request_timeout=request_timeout,
        )
    except TypeError:
        llm = ChatOllama(model=model_name, base_url=base_url)

    def draft_playbook(state: PlaybookState) -> PlaybookState:
        prompt = f"""
You are a senior incident responder following a Barclays-style Cyber Incident Response (IR) standard.
Generate a bank-grade, step-by-step incident response playbook for the following context.

Context:
{state['incident_summary']}

Follow this structure exactly, using short, imperative sentences:

1. Context & Classification
   - Clearly summarise what is known.
   - Propose a severity: Critical / High / Medium / Low.
   - Indicate likely incident type (e.g. account takeover, data exfiltration, malware, policy breach).
   - Note potential impact on payments, SWIFT, treasury, and customer data.

2. Triage & Initial Validation
   - Steps to validate signal quality, rule out false positives, and confirm scope.

3. Containment
   - Steps to limit further harm while preserving evidence (accounts, endpoints, network, privileged access).

4. Investigation & Forensics
   - Steps to analyse SIEM, EDR, UEBA, and Elasticsearch data, including peer/user comparisons.

5. Eradication & Hardening
   - Steps to remove root cause and strengthen controls so the pattern cannot easily recur.

6. Recovery & Validation
   - Steps to safely restore business services, with explicit checks before declaring success.

7. Communication & Reporting
   - Steps for internal escalation, stakeholder updates, and potential regulator notification (e.g. PRA/FCA/GDPR timelines).

8. Post-Incident Review & Lessons Learned
   - Steps to capture lessons, update playbooks, and feed back into UEBA/monitoring.

Constraints:
- Assume all tooling is local to the bank (SIEM, EDR, UEBA, Elasticsearch, ticketing).
- Do NOT invent external services or SaaS tools.
- Number or label every concrete action clearly so it can be turned into a runbook.
"""
        response = llm.invoke(prompt)
        content = getattr(response, "content", str(response))

        return {
            "incident_summary": state["incident_summary"],
            "playbook": content.strip(),
        }

    graph = StateGraph(PlaybookState)
    graph.add_node("draft_playbook", draft_playbook)
    graph.set_entry_point("draft_playbook")
    graph.add_edge("draft_playbook", END)
    app = graph.compile()

    user = context.get("user") or context.get("primary_user") or "unknown"
    incident_id = context.get("incident_id", "INC-LOCAL")

    summary_parts = [
        f"Incident ID: {incident_id}",
        f"User: {user}",
        f"Risk score: {context.get('risk_score', 0)}",
        f"Fidelity score: {context.get('fidelity_score', 0)}",
        f"UEBA score: {context.get('signals', {}).get('ueba_score', 0)}",
        f"Correlated users: {', '.join(context.get('correlated_users', [])) or 'none'}",
        f"Signals: {context.get('signals', {})}",
    ]
    incident_summary = "\n".join(summary_parts)

    state: PlaybookState = {"incident_summary": incident_summary, "playbook": ""}
    result = app.invoke(state)
    raw_playbook = result["playbook"]

    # Roughly split out a first recommended action and list of steps
    lines = [ln.strip() for ln in raw_playbook.splitlines() if ln.strip()]
    numbered_steps = [
        ln
        for ln in lines
        if ln[0].isdigit()
        or ln.lower().startswith("step")
        or ln.lower().startswith("- ")
    ]

    if not numbered_steps:
        numbered_steps = lines

    recommended = (
        numbered_steps[0]
        if numbered_steps
        else "Follow Barclays cyber incident response standard runbook."
    )

    # Map quantitative risk into a Barclays-style qualitative severity
    risk_score = float(context.get("risk_score", 0.0) or 0.0)
    if risk_score >= 80:
        severity = "Critical"
    elif risk_score >= 60:
        severity = "High"
    elif risk_score >= 40:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "severity": severity,
        "summary": f"LLM-generated incident response plan for user {user} (incident {incident_id})",
        "recommended_action": recommended,
        "steps": numbered_steps,
        "strategy": "llm_langgraph",
        "llm_model": model_name,
    }


def generate_playbook(user_or_incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Public entrypoint used by the FastAPI app.

    Attempts to generate a rich, Barclays-specific playbook using
    local LLMs via Ollama + LangChain + LangGraph. If that stack
    is not available or times out, falls back to a deterministic rule-based plan.
    """
    if not USE_LLM_PLAYBOOK:
        return _rule_based_playbook(user_or_incident)

    def _run_llm() -> Dict[str, Any]:
        return _llm_playbook(user_or_incident)

    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_run_llm)
            return future.result(timeout=PLAYBOOK_LLM_TIMEOUT)
    except (FuturesTimeoutError, Exception):
        # Timeout or any LLM error: never hang the pipeline
        return _rule_based_playbook(user_or_incident)
