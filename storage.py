import json
import os
from typing import Dict, List, Optional

LOG_FILE = "ingested_logs.json"


def _get_es_client():
    """
    Lazily create an Elasticsearch client if explicitly enabled via env.

    This keeps the default behaviour fully local (JSON file storage),
    while allowing optional indexing into a local Elasticsearch cluster
    for richer search and correlation.
    """
    enable_es = os.getenv("ENABLE_ELASTICSEARCH", "").lower() in {"1", "true", "yes"}
    if not enable_es:
        return None

    try:
        from elasticsearch import Elasticsearch  # type: ignore
    except Exception:
        return None

    es_url = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")

    try:
        client = Elasticsearch(es_url, request_timeout=2)
    except Exception:
        return None

    return client


def _index_logs_in_elasticsearch(logs: List[Dict]) -> None:
    client = _get_es_client()
    if not client:
        return

    try:
        from elasticsearch import helpers  # type: ignore
    except Exception:
        return

    index_name = os.getenv("ES_LOG_INDEX", "barclays-security-logs")

    actions = [
        {
            "_index": index_name,
            "_op_type": "index",
            "_source": log,
        }
        for log in logs
    ]

    try:
        helpers.bulk(client, actions, raise_on_error=False)
    except Exception:
        # Elasticsearch is optional; failures must not impact the agent
        return


def save_logs(logs: List[Dict]) -> None:
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            existing = json.load(f)
    else:
        existing = []

    existing.extend(logs)

    with open(LOG_FILE, "w") as f:
        json.dump(existing, f, indent=2)

    # Optionally index into local Elasticsearch for fast correlation/search
    _index_logs_in_elasticsearch(logs)


def load_logs() -> List[Dict]:
    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r") as f:
        return json.load(f)

