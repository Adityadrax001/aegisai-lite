
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Integer,
    String,
    JSON,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class AppMeta(Base):
    __tablename__ = "app_meta"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(
        String(100), unique=True, index=True
    )
    value: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )


class ScenarioRun(Base):
    __tablename__ = "scenario_runs"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )
    scenario_id: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )
    classification: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    severity: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    event_data: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )
    result_data: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )
    simulated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )



class LLMAnalysis(Base):
    __tablename__ = "llm_analyses"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )
    scenario_id: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )
    model_name: Mapped[str] = mapped_column(
        String(100), nullable=False
    )
    proposal_data: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )
    executed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
