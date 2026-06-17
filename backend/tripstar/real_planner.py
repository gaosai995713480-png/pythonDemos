"""TripStar 真实 LLM 规划链路。"""
from __future__ import annotations

import json
import math
from typing import Any, Callable

from .config import TripStarSettings
from .models.schemas import TripStarRequest
from .services.amap_service import AmapService, AmapServiceError, parse_amap_location
from .services.llm_service import TripStarLLMClient, TripStarLLMError
from .services.xhs_service import XhsService, XhsServiceError


ProgressCallback = Callable[[str, str, int], None]


class RealTripStarPlannerError(RuntimeError):
    """真实 TripStar planner 执行失败。"""


class RealTripStarPlanner:
    """LLM + 小红书 + 高德的真实规划器。

    当前实现不照搬原 TripStar 的运行时框架，而是在现有 FastAPI 契约内复刻主链路：
    小红书/地图候选 → LLM 结构化编排 → 高德补坐标/路线 → 前端统一结果。
    """

    def __init__(
        self,
        settings: TripStarSettings,
        *,
        llm_client: Any | None = None,
        xhs_service: Any | None = None,
        amap_service: Any | None = None,
    ):
        self.settings = settings
        self.llm = llm_client or TripStarLLMClient(settings)
        self.xhs = xhs_service or (
            XhsService(settings.xhs_cookie) if settings.enable_xhs and settings.xhs_cookie else None
        )
        self.amap = amap_service or (AmapService(settings.amap_web_key) if settings.amap_web_key else None)

    def plan(self, request: TripStarRequest, progress: ProgressCallback) -> dict[str, Any]:
        warnings: list[str] = []

        progress("xhs", "正在检索小红书真实游记...", 15)
        xhs_notes = self._search_xhs_notes(request, warnings)

        progress("poi", "正在检索高德候选景点...", 32)
        poi_candidates = self._search_poi_candidates(request, warnings)

        progress("llm", "正在调用大模型编排旅行计划...", 58)
        llm_plan = self._generate_llm_plan(request, xhs_notes, poi_candidates)

        progress("geocode", "正在补齐景点坐标...", 76)
        plan_data = self._normalize_plan_data(request, llm_plan, xhs_notes, poi_candidates, warnings)

        progress("route", "正在计算地图路线...", 90)
        self._attach_map_routes(plan_data, warnings)

        progress("finalize", "正在整理知识图谱和输出结构...", 98)
        graph_data = self._build_graph_data(plan_data)
        return {
            "success": True,
            "message": "真实 LLM 旅行计划生成成功",
            "data": plan_data,
            "graph_data": graph_data,
            "mock_mode": False,
            "real_planner_ready": True,
        }

    def _search_xhs_notes(self, request: TripStarRequest, warnings: list[str]) -> list[dict[str, Any]]:
        if not self.xhs:
            warnings.append("小红书未配置，已跳过真实游记检索")
            return []

        preference_text = " ".join(request.preferences) if request.preferences else "旅游攻略"
        query = f"{request.city} {preference_text} 旅游 攻略 景点 美食"
        try:
            return self.xhs.search_notes(query, min(12, max(6, request.travel_days * 2)))
        except XhsServiceError as exc:
            warnings.append(f"小红书检索失败：{exc}")
            return []

    def _search_poi_candidates(self, request: TripStarRequest, warnings: list[str]) -> list[dict[str, Any]]:
        if not self.amap:
            warnings.append("高德 Web 服务 Key 未配置，已跳过 POI 候选检索")
            return []

        keywords = []
        for preference in request.preferences:
            keywords.append(f"{request.city}{preference}")
        keywords.extend([f"{request.city}旅游景点", f"{request.city}美食", f"{request.city}博物馆"])

        candidates: list[dict[str, Any]] = []
        seen: set[str] = set()
        for keyword in keywords:
            try:
                items = self.amap.search_poi(request.city, keyword, min(10, max(4, request.travel_days)))
            except AmapServiceError as exc:
                warnings.append(f"高德 POI 检索失败（{keyword}）：{exc}")
                continue
            for item in items:
                name = str(item.get("name") or "").strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                candidates.append(item)
                if len(candidates) >= 40:
                    return candidates
        return candidates

    def _generate_llm_plan(
        self,
        request: TripStarRequest,
        xhs_notes: list[dict[str, Any]],
        poi_candidates: list[dict[str, Any]],
    ) -> dict[str, Any]:
        try:
            return self.llm.chat_json(
                system_prompt=(
                    "你是 TripStar 旅行规划智能体。你必须基于用户需求、小红书游记摘要和地图 POI 候选，"
                    "输出严格 JSON 对象；不得输出 markdown；不得编造不存在的字段。"
                ),
                user_prompt=self._build_user_prompt(request, xhs_notes, poi_candidates),
            )
        except TripStarLLMError:
            raise
        except Exception as exc:
            raise RealTripStarPlannerError(f"大模型规划失败：{exc}") from exc

    def _build_user_prompt(
        self,
        request: TripStarRequest,
        xhs_notes: list[dict[str, Any]],
        poi_candidates: list[dict[str, Any]],
    ) -> str:
        compact_notes = [
            {
                "title": note.get("title", ""),
                "desc": note.get("desc", ""),
                "liked_count": note.get("liked_count", 0),
                "author": (note.get("author") or {}).get("nickname", ""),
                "note_url": note.get("note_url", ""),
            }
            for note in xhs_notes[:10]
        ]
        compact_pois = [
            {
                "name": item.get("name", ""),
                "address": item.get("address", ""),
                "type": item.get("type", ""),
                "district": item.get("district", ""),
                "location": item.get("location"),
            }
            for item in poi_candidates[:30]
        ]
        schema = {
            "overview": "整体行程说明",
            "days": [
                {
                    "day": 1,
                    "title": "第 1 天标题",
                    "summary": "当天安排摘要",
                    "attractions": [
                        {
                            "name": "景点名",
                            "address": "地址",
                            "duration": "2小时",
                            "description": "结合小红书/POI 的推荐理由和避坑提示",
                            "reservation_required": False,
                            "reservation_tips": "",
                            "location": {"longitude": 114.0, "latitude": 30.0},
                        }
                    ],
                    "meals": [{"type": "午餐", "name": "餐食建议", "budget": "100元/人"}],
                    "transportation": "交通建议",
                    "hotel_suggestion": "住宿建议",
                }
            ],
            "budget": {
                "currency": "CNY",
                "total_estimate": "预算范围",
                "items": [{"category": "餐饮", "amount": "金额"}],
            },
            "weather": {"summary": "天气提醒", "tips": ["提示"]},
            "overall_suggestions": "整体建议",
        }
        return (
            f"用户需求：\n"
            f"- 城市：{request.city}\n"
            f"- 出发地：{request.departure_city or '未填写'}\n"
            f"- 日期：{request.start_date} 至 {request.end_date}\n"
            f"- 天数：{request.travel_days}\n"
            f"- 偏好：{', '.join(request.preferences) or '未填写'}\n"
            f"- 预算：{request.budget or '未填写'}\n"
            f"- 同行人：{request.companions or '未填写'}\n"
            f"- 特殊要求：{request.special_requirements or '无'}\n"
            f"- 输出语言：{request.language}\n\n"
            f"小红书游记摘要（可能为空）：\n{json.dumps(compact_notes, ensure_ascii=False)}\n\n"
            f"高德 POI 候选（优先从中选择，可能为空）：\n{json.dumps(compact_pois, ensure_ascii=False)}\n\n"
            f"请输出 JSON，schema 参考：\n{json.dumps(schema, ensure_ascii=False)}\n\n"
            f"硬性要求：\n"
            f"1. days 数量必须等于 {request.travel_days}。\n"
            f"2. 每天 2-3 个景点，尽量避免重复。\n"
            f"3. 如果 POI 候选包含 location，请尽量带上 location。\n"
            f"4. description 要体现游玩理由、避坑或预约提醒，不要写空泛模板。\n"
            f"5. 只输出 JSON 对象。"
        )

    def _normalize_plan_data(
        self,
        request: TripStarRequest,
        llm_plan: dict[str, Any],
        xhs_notes: list[dict[str, Any]],
        poi_candidates: list[dict[str, Any]],
        warnings: list[str],
    ) -> dict[str, Any]:
        poi_by_name = {str(item.get("name") or "").strip(): item for item in poi_candidates}
        raw_days = llm_plan.get("days") if isinstance(llm_plan.get("days"), list) else []
        days = []
        for index in range(request.travel_days):
            raw_day = raw_days[index] if index < len(raw_days) and isinstance(raw_days[index], dict) else {}
            attractions = self._normalize_attractions(
                request.city,
                raw_day.get("attractions") if isinstance(raw_day.get("attractions"), list) else [],
                poi_by_name,
                warnings,
            )
            days.append(
                {
                    "day": int(raw_day.get("day") or index + 1),
                    "title": raw_day.get("title") or f"{request.city}第 {index + 1} 天",
                    "summary": raw_day.get("summary") or "大模型未返回当天摘要，建议按地图顺序弹性安排。",
                    "attractions": attractions,
                    "meals": raw_day.get("meals") if isinstance(raw_day.get("meals"), list) else [],
                    "transportation": raw_day.get("transportation") or "建议结合地铁、步行和打车。",
                    "hotel_suggestion": raw_day.get("hotel_suggestion") or "建议住在交通便利的核心商圈或地铁站附近。",
                }
            )

        budget = llm_plan.get("budget") if isinstance(llm_plan.get("budget"), dict) else {}
        weather = llm_plan.get("weather") if isinstance(llm_plan.get("weather"), dict) else {}
        return {
            "city": request.city,
            "start_date": request.start_date,
            "end_date": request.end_date,
            "travel_days": request.travel_days,
            "language": request.language,
            "preferences": request.preferences,
            "overview": llm_plan.get("overview") or f"{request.city} {request.travel_days} 天真实 LLM 旅行规划。",
            "days": days,
            "budget": {
                "currency": budget.get("currency") or "CNY",
                "total_estimate": budget.get("total_estimate") or "",
                "items": budget.get("items") if isinstance(budget.get("items"), list) else [],
            },
            "weather": {
                "summary": weather.get("summary") or "请在出行前再次确认实时天气。",
                "tips": weather.get("tips") if isinstance(weather.get("tips"), list) else [],
            },
            "overall_suggestions": llm_plan.get("overall_suggestions") or "",
            "source_summary": {
                "planner": "llm",
                "llm_model": self.settings.llm_model_id,
                "xhs_note_count": len(xhs_notes),
                "poi_candidate_count": len(poi_candidates),
                "warnings": warnings,
            },
        }

    def _normalize_attractions(
        self,
        city: str,
        raw_attractions: list[Any],
        poi_by_name: dict[str, dict[str, Any]],
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        attractions = []
        for raw in raw_attractions:
            if not isinstance(raw, dict):
                continue
            name = str(raw.get("name") or "").strip()
            if not name:
                continue
            poi = poi_by_name.get(name, {})
            location = (
                parse_amap_location(raw.get("location"))
                or parse_amap_location(poi.get("location"))
                or self._geocode(city, name, warnings)
            )
            attractions.append(
                {
                    "name": name,
                    "address": raw.get("address") or poi.get("address") or "",
                    "duration": raw.get("duration") or "2小时",
                    "description": raw.get("description") or "大模型推荐景点。",
                    "reservation_required": bool(raw.get("reservation_required", False)),
                    "reservation_tips": raw.get("reservation_tips") or "",
                    "location": location,
                    "map_source": "amap" if location else "llm",
                }
            )
        return attractions

    def _geocode(self, city: str, name: str, warnings: list[str]) -> dict[str, float] | None:
        if not self.amap:
            return None
        try:
            item = self.amap.geocode(city, name)
            return parse_amap_location(item.get("location"))
        except AmapServiceError as exc:
            warnings.append(f"景点坐标补齐失败（{name}）：{exc}")
            return None

    def _attach_map_routes(self, plan_data: dict[str, Any], warnings: list[str]) -> None:
        routes = []
        for day in plan_data.get("days") or []:
            points = []
            for attraction in day.get("attractions") or []:
                location = parse_amap_location(attraction.get("location"))
                if not location:
                    continue
                points.append(
                    {
                        "name": attraction.get("name") or "景点",
                        "longitude": location["longitude"],
                        "latitude": location["latitude"],
                    }
                )
            if not points:
                continue
            route = self._route_for_points(points, warnings)
            routes.append(
                {
                    "day": day.get("day"),
                    "mode": route.get("mode", "walking"),
                    "points": points,
                    "polyline": route.get("polyline") or [[point["longitude"], point["latitude"]] for point in points],
                    "distance_meters": route.get("distance_meters", 0),
                    "duration_seconds": route.get("duration_seconds", 0),
                    "segments": route.get("segments", []),
                    "source": route.get("source", "amap"),
                }
            )

        plan_data["map_routes"] = routes
        center = self._first_location(plan_data)
        if center:
            plan_data["map_center"] = center

    def _route_for_points(self, points: list[dict[str, Any]], warnings: list[str]) -> dict[str, Any]:
        if len(points) < 2:
            return {
                "mode": "walking",
                "distance_meters": 0,
                "duration_seconds": 0,
                "polyline": [[points[0]["longitude"], points[0]["latitude"]]] if points else [],
                "segments": [],
                "source": "single_point",
            }
        if self.amap:
            try:
                route = self.amap.route_many(points, "walking")
                return {**route, "source": "amap"}
            except AmapServiceError as exc:
                warnings.append(f"高德路线规划失败，已用直线估算：{exc}")
        distance = self._route_distance(points)
        return {
            "mode": "walking",
            "distance_meters": distance,
            "duration_seconds": max(0, int(distance / 80 * 60)) if distance else 0,
            "polyline": [[point["longitude"], point["latitude"]] for point in points],
            "segments": [],
            "source": "estimated",
        }

    def _first_location(self, plan_data: dict[str, Any]) -> dict[str, float] | None:
        for day in plan_data.get("days") or []:
            for attraction in day.get("attractions") or []:
                location = parse_amap_location(attraction.get("location"))
                if location:
                    return location
        return None

    def _build_graph_data(self, plan_data: dict[str, Any]) -> dict[str, Any]:
        nodes = [{"id": "city", "name": plan_data.get("city") or "目的地", "category": "city"}]
        edges = []
        for day in plan_data.get("days") or []:
            day_id = f"day-{day.get('day')}"
            nodes.append({"id": day_id, "name": day.get("title") or day_id, "category": "day"})
            edges.append({"source": "city", "target": day_id, "label": "包含"})
            for attraction in day.get("attractions") or []:
                attraction_id = f"{day_id}-{attraction.get('name')}"
                nodes.append(
                    {
                        "id": attraction_id,
                        "name": attraction.get("name") or "景点",
                        "category": "attraction",
                    }
                )
                edges.append({"source": day_id, "target": attraction_id, "label": "游玩"})
        return {
            "nodes": nodes,
            "edges": edges,
            "categories": [{"name": "city"}, {"name": "day"}, {"name": "attraction"}],
        }

    def _route_distance(self, points: list[dict[str, Any]]) -> int:
        distance = 0.0
        for index in range(len(points) - 1):
            distance += self._haversine_meters(points[index], points[index + 1])
        return int(distance)

    def _haversine_meters(self, start: dict[str, Any], end: dict[str, Any]) -> float:
        radius = 6371000
        start_lat = math.radians(float(start["latitude"]))
        end_lat = math.radians(float(end["latitude"]))
        delta_lat = end_lat - start_lat
        delta_lng = math.radians(float(end["longitude"]) - float(start["longitude"]))
        value = (
            math.sin(delta_lat / 2) ** 2
            + math.cos(start_lat) * math.cos(end_lat) * math.sin(delta_lng / 2) ** 2
        )
        return 2 * radius * math.asin(math.sqrt(value))
