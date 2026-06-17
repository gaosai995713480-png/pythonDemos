"""TripStar 高德地图 Web 服务适配器。"""
from __future__ import annotations

from typing import Any

import httpx


GEOCODE_URL = "https://restapi.amap.com/v3/geocode/geo"
POI_TEXT_URL = "https://restapi.amap.com/v3/place/text"
DIRECTION_URLS = {
    "walking": "https://restapi.amap.com/v3/direction/walking",
    "driving": "https://restapi.amap.com/v3/direction/driving",
}


class AmapServiceError(RuntimeError):
    """高德地图服务调用失败。"""


def parse_amap_location(value: Any) -> dict[str, float] | None:
    """将高德 `lng,lat` 字符串规范化为前端可直接使用的坐标对象。"""
    if isinstance(value, dict):
        longitude = value.get("longitude", value.get("lng"))
        latitude = value.get("latitude", value.get("lat"))
        if longitude is None or latitude is None:
            return None
        try:
            return {"longitude": float(longitude), "latitude": float(latitude)}
        except (TypeError, ValueError):
            return None

    if not isinstance(value, str) or "," not in value:
        return None
    lng_text, lat_text = value.split(",", 1)
    try:
        return {"longitude": float(lng_text), "latitude": float(lat_text)}
    except ValueError:
        return None


def _format_point(point: dict[str, Any]) -> str:
    longitude = point.get("longitude", point.get("lng"))
    latitude = point.get("latitude", point.get("lat"))
    if longitude is None or latitude is None:
        raise AmapServiceError("路线点缺少 longitude/latitude")
    return f"{float(longitude)},{float(latitude)}"


def _append_polyline(target: list[list[float]], raw_polyline: str) -> None:
    for chunk in raw_polyline.split(";"):
        location = parse_amap_location(chunk)
        if not location:
            continue
        point = [location["longitude"], location["latitude"]]
        if target and target[-1] == point:
            continue
        target.append(point)


class AmapService:
    """封装 TripStar 需要的高德 Web 服务能力。"""

    def __init__(self, api_key: str, timeout: float = 8.0):
        self.api_key = api_key
        self.timeout = timeout

    def _request(self, url: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self.api_key:
            raise AmapServiceError("TripStar 高德 Web 服务 Key 未配置")

        request_params = {**params, "key": self.api_key, "output": "json"}
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(url, params=request_params)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPError as exc:
            raise AmapServiceError(f"高德地图服务请求失败：{exc}") from exc
        except ValueError as exc:
            raise AmapServiceError("高德地图服务返回了无法解析的 JSON") from exc

        if str(data.get("status", "1")) != "1":
            info = data.get("info") or data.get("infocode") or "未知错误"
            raise AmapServiceError(f"高德地图服务返回失败：{info}")
        return data

    def geocode(self, city: str, keyword: str) -> dict[str, Any]:
        keyword = keyword.strip()
        if not keyword:
            raise AmapServiceError("地理编码关键词不能为空")

        data = self._request(GEOCODE_URL, {"address": keyword, "city": city})
        geocodes = data.get("geocodes") or []
        if not geocodes:
            raise AmapServiceError(f"未找到地点：{keyword}")

        item = geocodes[0]
        location = parse_amap_location(item.get("location"))
        if not location:
            raise AmapServiceError(f"地点缺少有效坐标：{keyword}")

        return {
            "name": item.get("formatted_address") or keyword,
            "address": item.get("formatted_address") or item.get("district") or "",
            "location": location,
            "amap_id": item.get("adcode") or "",
            "city": item.get("city") or city,
            "district": item.get("district") or "",
        }

    def search_poi(self, city: str, keyword: str, limit: int = 10) -> list[dict[str, Any]]:
        keyword = keyword.strip()
        if not keyword:
            raise AmapServiceError("POI 搜索关键词不能为空")

        safe_limit = max(1, min(int(limit or 10), 25))
        data = self._request(
            POI_TEXT_URL,
            {"keywords": keyword, "city": city, "offset": safe_limit, "page": 1},
        )

        items: list[dict[str, Any]] = []
        for poi in data.get("pois") or []:
            location = parse_amap_location(poi.get("location"))
            if not location:
                continue
            items.append(
                {
                    "name": poi.get("name") or keyword,
                    "address": poi.get("address") if isinstance(poi.get("address"), str) else "",
                    "location": location,
                    "amap_id": poi.get("id") or "",
                    "type": poi.get("type") or "",
                    "city": poi.get("cityname") or city,
                    "district": poi.get("adname") or "",
                }
            )
        return items

    def route_many(self, points: list[dict[str, Any]], mode: str = "walking") -> dict[str, Any]:
        normalized_mode = mode if mode in DIRECTION_URLS else "walking"
        if len(points) < 2:
            raise AmapServiceError("路线规划至少需要两个地点")

        total_distance = 0
        total_duration = 0
        full_polyline: list[list[float]] = []
        segments: list[dict[str, Any]] = []

        for index in range(len(points) - 1):
            origin = points[index]
            destination = points[index + 1]
            segment = self._route_pair(origin, destination, normalized_mode)
            total_distance += int(segment["distance_meters"])
            total_duration += int(segment["duration_seconds"])
            for point in segment["polyline"]:
                if full_polyline and full_polyline[-1] == point:
                    continue
                full_polyline.append(point)
            segments.append(segment)

        return {
            "mode": normalized_mode,
            "distance_meters": total_distance,
            "duration_seconds": total_duration,
            "polyline": full_polyline,
            "segments": segments,
        }

    def _route_pair(self, origin: dict[str, Any], destination: dict[str, Any], mode: str) -> dict[str, Any]:
        data = self._request(
            DIRECTION_URLS[mode],
            {"origin": _format_point(origin), "destination": _format_point(destination)},
        )

        paths = (data.get("route") or {}).get("paths") or []
        if not paths:
            raise AmapServiceError("高德地图未返回可用路线")

        path = paths[0]
        polyline: list[list[float]] = []
        for step in path.get("steps") or []:
            _append_polyline(polyline, str(step.get("polyline") or ""))

        if not polyline:
            polyline = [
                [float(origin["longitude"]), float(origin["latitude"])],
                [float(destination["longitude"]), float(destination["latitude"])],
            ]

        return {
            "from": origin.get("name") or "起点",
            "to": destination.get("name") or "终点",
            "distance_meters": int(float(path.get("distance") or 0)),
            "duration_seconds": int(float(path.get("duration") or 0)),
            "polyline": polyline,
        }
