"""TripStar 请求与响应模型。"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class TripStarRequest(BaseModel):
    city: str = Field(..., min_length=1, max_length=80)
    start_date: str = Field(..., min_length=4, max_length=32)
    end_date: str = Field(..., min_length=4, max_length=32)
    travel_days: int = Field(..., ge=1, le=30)
    preferences: list[str] = Field(default_factory=list)
    language: str = Field(default="zh", max_length=10)
    departure_city: str | None = Field(default=None, max_length=80)
    budget: str | None = Field(default=None, max_length=80)
    companions: str | None = Field(default=None, max_length=80)
    special_requirements: str | None = Field(default=None, max_length=500)

    @field_validator("city", "start_date", "end_date", "language")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("字段不能为空")
        return cleaned

    @field_validator("preferences", mode="before")
    @classmethod
    def normalize_preferences(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return []


class TripStarSubmitResponse(BaseModel):
    task_id: str
    plan_id: str
    status: str
    ws_url: str
    message: str


class TripStarTaskStatus(BaseModel):
    task_id: str
    plan_id: str
    status: str
    stage: str
    progress: int
    message: str
    result: dict[str, Any] | None = None
    error: str | None = None
    request_payload: dict[str, Any] | None = None


class TripStarMapPoint(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    longitude: float
    latitude: float


class TripStarRouteRequest(BaseModel):
    points: list[TripStarMapPoint] = Field(..., min_length=2, max_length=20)
    mode: str = Field(default="walking", max_length=20)
