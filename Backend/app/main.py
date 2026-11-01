from contextlib import asynccontextmanager
import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db import Base, check_database_connection, engine, SessionLocal
from app import models  # Registers SQLAlchemy model metadata
from app.models import ScenarioRun, LLMAnalysis
from app.schemas import AnalyzeEventRequest
from app.simulator import analyze_brute_force
from app.scenarios import run_scenario
from app.detector import detect_event
from app.llm_agent import analyze_event_with_llm


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Bootstrap only. Replace with Alembic migrations before adding real tables.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)

# CORS: explicit frontend origins only, never "*".
# Override with a comma-separated CORS_ORIGINS environment variable.
_cors_origins = [
    o.strip()
    for o in os.getenv(
        "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/api/health")
def health():
    return {"status": "ok", "app": settings.app_name, "environment": settings.app_env}


@app.get("/api/health/db")
def database_health():
    try:
        check_database_connection()
        return {"status": "ok", "database": "connected"}
    except Exception:
        # Keep the response useful without leaking credentials or internal details.
        raise HTTPException(
            status_code=503,
            detail="Database unavailable. Check PostgreSQL and DATABASE_URL.",
        )


@app.post("/api/analyze")
def analyze_event(event: AnalyzeEventRequest):
    return analyze_brute_force(
        failed_attempts=event.failed_attempts,
        threshold=event.threshold,
    )


@app.post("/api/scenarios/{scenario_id}/run")
def execute_scenario(scenario_id: str):
    try:
        event = run_scenario(scenario_id)
        result = detect_event(event)
    except ValueError:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scenario: {scenario_id}",
        )

    db = SessionLocal()

    try:
        record = ScenarioRun(
            scenario_id=scenario_id,
            classification=result["classification"],
            severity=result["severity"],
            event_data=event,
            result_data=result,
            simulated=True,
        )

        db.add(record)
        db.commit()
        db.refresh(record)

        return {
            "id": record.id,
            "scenario_id": record.scenario_id,
            "classification": record.classification,
            "severity": record.severity,
            "created_at": record.created_at,
            "event": record.event_data,
            "result": record.result_data,
        }

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Failed to save scenario run.",
        )

    finally:
        db.close()


@app.get("/api/scenarios/runs")
def get_scenario_runs():
    db = SessionLocal()

    try:
        records = (
            db.query(ScenarioRun)
            .order_by(ScenarioRun.created_at.desc())
            .limit(50)
            .all()
        )

        return [
            {
                "id": record.id,
                "scenario_id": record.scenario_id,
                "classification": record.classification,
                "severity": record.severity,
                "created_at": record.created_at,
                "event": record.event_data,
                "result": record.result_data,
            }
            for record in records
        ]

    finally:
        db.close()


@app.post("/api/scenarios/{scenario_id}/analyze-llm")
def analyze_scenario_with_llm(scenario_id: str):
    try:
        event = run_scenario(scenario_id)
    except ValueError:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scenario: {scenario_id}",
        )

    try:
        proposal = analyze_event_with_llm(event)

        db = SessionLocal()
        try:
            record = LLMAnalysis(
                scenario_id=scenario_id,
                model_name=os.getenv(
                    "DEEPSEEK_MODEL", "deepseek-flash"
                ),
                proposal_data=proposal,
                executed=False,
            )

            db.add(record)
            db.commit()
            db.refresh(record)

            return {
                "analysis_id": record.id,
                "scenario_id": record.scenario_id,
                "model_name": record.model_name,
                "llm_proposal": record.proposal_data,
                "executed": record.executed,
                "created_at": record.created_at,
            }
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    except Exception:
        raise HTTPException(
            status_code=502,
            detail="LLM analysis or database save failed. Check the backend terminal.",
        )


@app.get("/api/scenarios/llm-analyses")
def get_llm_analyses():
    db = SessionLocal()

    try:
        records = (
            db.query(LLMAnalysis)
            .order_by(LLMAnalysis.created_at.desc())
            .limit(50)
            .all()
        )

        return [
            {
                "analysis_id": record.id,
                "scenario_id": record.scenario_id,
                "model_name": record.model_name,
                "llm_proposal": record.proposal_data,
                "executed": record.executed,
                "created_at": record.created_at,
            }
            for record in records
        ]

    finally:
        db.close()