import os
import secrets
from typing import Optional

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Security
from fastapi.security import APIKeyHeader

API_KEY_ENV = "IDS_API_KEY"
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def create_app(ids):
    app = FastAPI(
        title="IDS Remote Monitoring API",
        version="1.0.0",
        description="Query alerts, traffic flows and control the IDS remotely.",
    )
    expected_key = os.environ.get(API_KEY_ENV)
    if not expected_key:
        print(
            f"WARNING: {API_KEY_ENV} is not set - the API is unauthenticated. "
            f"Do not expose it beyond localhost."
        )

    def require_api_key(api_key: Optional[str] = Security(api_key_header)):
        if not expected_key:
            return
        if api_key is None or not secrets.compare_digest(api_key, expected_key):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

    # Unauthenticated liveness probe for load balancers / uptime checks
    @app.get("/health")
    def health():
        return {'status': 'ok', 'ids_running': ids.is_running}

    router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])

    @router.get("/status")
    def get_status():
        return ids.get_status()

    @router.get("/alerts")
    def list_alerts(
        limit: int = Query(100, ge=1, le=1000),
        threat_type: Optional[str] = Query(None, description="signature or anomaly"),
        rule: Optional[str] = Query(None, description="e.g. SYN_FLOOD, PORT_SCAN"),
        min_confidence: float = Query(0.0, ge=0.0, le=1.0),
        since_id: Optional[int] = Query(None, description="Only alerts newer than this id (for polling)"),
    ):
        return ids.alert_system.get_alerts(
            limit=limit,
            threat_type=threat_type,
            rule=rule,
            min_confidence=min_confidence,
            since_id=since_id,
        )

    @router.get("/alerts/stats")
    def alert_stats():
        return ids.alert_system.get_stats()

    @router.get("/alerts/{alert_id}")
    def get_alert(alert_id: int):
        alert = ids.alert_system.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert

    @router.get("/flows")
    def list_flows(limit: int = Query(50, ge=1, le=1000)):
        return ids.traffic_analyzer.get_flow_summary(limit=limit)

    @router.get("/rules")
    def list_rules():
        return {'signature_rules': list(ids.detection_engine.signature_rule)}

    @router.post("/capture/start")
    def start_capture():
        if not ids.start_in_background():
            raise HTTPException(status_code=409, detail="IDS is already running")
        return {'message': 'IDS started'}

    @router.post("/capture/stop")
    def stop_capture():
        if not ids.is_running:
            raise HTTPException(status_code=409, detail="IDS is not running")
        ids.stop()
        return {'message': 'IDS stopped'}

    app.include_router(router)
    return app


def run_api(ids, host="127.0.0.1", port=8000):
    uvicorn.run(create_app(ids), host=host, port=port)
