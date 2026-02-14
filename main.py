"""
Baidu search crawler -> MySQL saver.
"""

from __future__ import annotations

import argparse
import functools
import io
import json
import logging
import re
import secrets
import webbrowser
import zipfile
from http.cookies import SimpleCookie
from dataclasses import dataclass
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterable, List, Optional
from urllib.parse import parse_qs, quote, unquote, urlparse


DEFAULT_URL = (
    "https://www.baidu.com/s?"
    "wd=%E5%A4%96%E4%BA%A4%E9%83%A8%EF%BC%9A"
    "%E5%BC%BA%E7%83%88%E8%B0%B4%E8%B4%A3"
    "%E7%93%9C%E8%BE%BE%E5%B0%94%E6%B8%AF"
    "%E8%A2%AD%E5%87%BB%E4%BA%8B%E4%BB%B6"
    "&tn=15007414_23_dg"
)

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp"}
WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    "com1",
    "com2",
    "com3",
    "com4",
    "com5",
    "com6",
    "com7",
    "com8",
    "com9",
    "lpt1",
    "lpt2",
    "lpt3",
    "lpt4",
    "lpt5",
    "lpt6",
    "lpt7",
    "lpt8",
    "lpt9",
}


@dataclass
class SearchResult:
    rank: int
    title: str
    url: str
    display_url: str
    summary: str


def build_session() -> "requests.Session":
    import requests

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0 Safari/537.36"
            ),
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }
    )
    return session


def fetch_html(url: str, timeout: int = 12) -> str:
    session = build_session()
    response = session.get(url, timeout=timeout)
    response.raise_for_status()
    response.encoding = response.apparent_encoding or "utf-8"
    return response.text


def extract_text(node: Optional["BeautifulSoup"]) -> str:
    if not node:
        return ""
    return " ".join(node.stripped_strings)


def pick_first_text(node: "BeautifulSoup", selectors: Iterable[str]) -> str:
    for selector in selectors:
        text = extract_text(node.select_one(selector))
        if text:
            return text
    return ""


def parse_results(html: str) -> List[SearchResult]:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    container = soup.select_one("#content_left")
    nodes = container.select(".result") if container else soup.select(".result")
    results: List[SearchResult] = []
    rank = 0
    for node in nodes:
        title_tag = node.select_one("h3 a")
        if not title_tag:
            continue
        title = extract_text(title_tag)
        url = (title_tag.get("href") or "").strip()
        summary = pick_first_text(
            node,
            [
                ".c-abstract",
                ".c-span-last",
                ".content-right_8Zs40",
                ".c-color-text",
            ],
        )
        display_url = pick_first_text(
            node,
            [
                ".c-showurl",
                ".c-url",
                ".c-color-gray",
            ],
        )
        rank += 1
        results.append(
            SearchResult(
                rank=rank,
                title=title,
                url=url,
                display_url=display_url,
                summary=summary,
            )
        )
    return results


def parse_keyword_from_url(url: str) -> str:
    query = parse_qs(urlparse(url).query)
    keyword = query.get("wd", [""])[0]
    return keyword.strip()


def validate_identifier(name: str, label: str) -> str:
    if not re.match(r"^[A-Za-z0-9_]+$", name):
        raise ValueError(f"{label} can only include letters, numbers, and underscore.")
    return name


def build_server_config(args: argparse.Namespace) -> dict:
    return {
        "host": args.db_host,
        "port": args.db_port,
        "user": args.db_user,
        "password": args.db_password,
        "charset": "utf8mb4",
    }


def build_db_config(args: argparse.Namespace, db_name: str) -> dict:
    config = build_server_config(args)
    config["database"] = db_name
    return config


def ensure_database(config: dict, db_name: str) -> None:
    import pymysql

    conn = pymysql.connect(**config, autocommit=True)
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{db_name}` DEFAULT CHARACTER SET utf8mb4"
            )
    finally:
        conn.close()


def ensure_table(conn: "pymysql.connections.Connection", table: str) -> None:
    sql = f"""
    CREATE TABLE IF NOT EXISTS `{table}` (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        keyword VARCHAR(255) NOT NULL,
        rank_no INT NOT NULL,
        title VARCHAR(512) NOT NULL,
        url TEXT NOT NULL,
        display_url TEXT NULL,
        summary TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    with conn.cursor() as cursor:
        cursor.execute(sql)


def insert_results(
    conn: "pymysql.connections.Connection",
    table: str,
    keyword: str,
    results: Iterable[SearchResult],
) -> int:
    sql = f"""
    INSERT INTO `{table}` (keyword, rank_no, title, url, display_url, summary)
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    rows = 0
    with conn.cursor() as cursor:
        for item in results:
            cursor.execute(
                sql,
                (
                    keyword,
                    item.rank,
                    item.title,
                    item.url,
                    item.display_url,
                    item.summary,
                ),
            )
            rows += 1
    conn.commit()
    return rows


def ensure_danmu_table(conn: "pymysql.connections.Connection", table: str) -> None:
    sql = f"""
    CREATE TABLE IF NOT EXISTS `{table}` (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        content VARCHAR(120) NOT NULL,
        likes INT NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    with conn.cursor() as cursor:
        cursor.execute(sql)
    ensure_danmu_likes_column(conn, table)
    ensure_danmu_like_log_table(conn, f"{table}_likes")


def ensure_danmu_likes_column(
    conn: "pymysql.connections.Connection", table: str
) -> None:
    db_name = conn.db
    if isinstance(db_name, (bytes, bytearray)):
        db_name = db_name.decode("utf-8", errors="ignore")
    sql = """
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = %s AND table_name = %s AND column_name = 'likes'
    """
    with conn.cursor() as cursor:
        cursor.execute(sql, (db_name, table))
        count = cursor.fetchone()[0]
        if count == 0:
            cursor.execute(
                f"ALTER TABLE `{table}` ADD COLUMN likes INT NOT NULL DEFAULT 0"
            )


def ensure_danmu_like_log_table(
    conn: "pymysql.connections.Connection", table: str
) -> None:
    sql = f"""
    CREATE TABLE IF NOT EXISTS `{table}` (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        danmu_id BIGINT NOT NULL,
        ip VARCHAR(45) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_danmu_ip (danmu_id, ip)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    with conn.cursor() as cursor:
        cursor.execute(sql)


def fetch_danmu(
    conn: "pymysql.connections.Connection", table: str, limit: int
) -> List[dict]:
    sql = f"SELECT id, content, likes FROM `{table}` ORDER BY id DESC LIMIT %s"
    with conn.cursor() as cursor:
        cursor.execute(sql, (limit,))
        rows = cursor.fetchall()
    items = []
    for row in reversed(rows):
        items.append({"id": row[0], "text": row[1], "likes": row[2] or 0})
    return items


def insert_danmu(
    conn: "pymysql.connections.Connection", table: str, content: str
) -> int:
    sql = f"INSERT INTO `{table}` (content) VALUES (%s)"
    with conn.cursor() as cursor:
        cursor.execute(sql, (content,))
        row_id = cursor.lastrowid
    conn.commit()
    return row_id


def increment_danmu_like(
    conn: "pymysql.connections.Connection",
    table: str,
    like_table: str,
    danmu_id: int,
    ip: str,
) -> Optional[dict]:
    insert_like_sql = (
        f"INSERT IGNORE INTO `{like_table}` (danmu_id, ip) VALUES (%s, %s)"
    )
    update_sql = f"UPDATE `{table}` SET likes = likes + 1 WHERE id = %s"
    select_sql = f"SELECT likes FROM `{table}` WHERE id = %s"
    with conn.cursor() as cursor:
        cursor.execute(insert_like_sql, (danmu_id, ip))
        if cursor.rowcount == 0:
            cursor.execute(select_sql, (danmu_id,))
            row = cursor.fetchone()
            return {"liked": False, "likes": row[0] if row else None}
        cursor.execute(update_sql, (danmu_id,))
        if cursor.rowcount == 0:
            conn.rollback()
            return None
        conn.commit()
        cursor.execute(select_sql, (danmu_id,))
        row = cursor.fetchone()
    return {"liked": True, "likes": row[0] if row else None}


def has_column(
    conn: "pymysql.connections.Connection", table: str, column: str
) -> bool:
    db_name = conn.db
    if isinstance(db_name, (bytes, bytearray)):
        db_name = db_name.decode("utf-8", errors="ignore")
    sql = """
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = %s AND table_name = %s AND column_name = %s
    """
    with conn.cursor() as cursor:
        cursor.execute(sql, (db_name, table, column))
        return cursor.fetchone()[0] > 0


def ensure_auth_table(conn: "pymysql.connections.Connection", table: str) -> None:
    sql = f"""
    CREATE TABLE IF NOT EXISTS `{table}` (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    with conn.cursor() as cursor:
        cursor.execute(sql)

    if not has_column(conn, table, "password") and has_column(conn, table, "password_hash"):
        with conn.cursor() as cursor:
            cursor.execute(f"ALTER TABLE `{table}` ADD COLUMN password VARCHAR(255) NULL")
            cursor.execute(f"UPDATE `{table}` SET password = password_hash WHERE password IS NULL")
            cursor.execute(
                f"ALTER TABLE `{table}` MODIFY COLUMN password VARCHAR(255) NOT NULL"
            )
        conn.commit()


def password_exists(
    conn: "pymysql.connections.Connection", table: str, password: str
) -> bool:
    sql = f"SELECT 1 FROM `{table}` WHERE password = %s LIMIT 1"
    with conn.cursor() as cursor:
        cursor.execute(sql, (password,))
        return cursor.fetchone() is not None


def ensure_default_password(
    conn: "pymysql.connections.Connection", table: str, default_password: str
) -> None:
    sql_count = f"SELECT COUNT(*) FROM `{table}`"
    sql_insert = f"INSERT INTO `{table}` (password) VALUES (%s)"
    with conn.cursor() as cursor:
        cursor.execute(sql_count)
        count = int(cursor.fetchone()[0] or 0)
        if count == 0:
            cursor.execute(sql_insert, (default_password,))
    conn.commit()


def is_image_filename(name: str) -> bool:
    suffix = Path(name).suffix.lower()
    return suffix in IMAGE_EXTENSIONS


def sanitize_upload_filename(raw_name: str) -> str:
    name = (raw_name or "").strip().replace("\x00", "")
    if not name:
        return ""
    name = name.replace("\\", "/")
    name = name.split("/")[-1].strip()
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    name = name.rstrip(" .")
    if not name:
        return ""
    base = Path(name).stem.lower()
    if base in WINDOWS_RESERVED_NAMES:
        name = f"_{name}"
    return name


def build_unique_photo_path(photos_dir: Path, filename: str) -> Path:
    candidate = photos_dir / filename
    if not candidate.exists():
        return candidate
    stem = candidate.stem
    suffix = candidate.suffix
    for index in range(2, 100000):
        next_candidate = photos_dir / f"{stem}_{index}{suffix}"
        if not next_candidate.exists():
            return next_candidate
    raise RuntimeError("too many files with same name")


def photo_sort_key(path: Path) -> tuple[int, int, str]:
    stem = path.stem
    parts = stem.split("_")
    if len(parts) >= 3 and parts[2].isdigit():
        return (0, int(parts[2]), path.name.lower())
    return (1, 10**9, path.name.lower())


def import_zip_photos(archive_data: bytes, photos_dir: Path) -> int:
    saved = 0
    with zipfile.ZipFile(io.BytesIO(archive_data)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            safe_name = sanitize_upload_filename(info.filename)
            if not safe_name or not is_image_filename(safe_name):
                continue
            image_data = archive.read(info)
            target = build_unique_photo_path(photos_dir, safe_name)
            target.write_bytes(image_data)
            saved += 1
    return saved


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Crawl a Baidu search page and save results into MySQL."
    )
    parser.add_argument(
        "--mode",
        choices=("love", "crawl"),
        default="love",
        help="Run love page or crawler",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="Port for love page (0 picks a free port)",
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host for love page server"
    )
    parser.add_argument("--url", default=DEFAULT_URL, help="Baidu search URL")
    parser.add_argument("--keyword", default="", help="Override keyword")
    parser.add_argument("--table", default="baidu_search_results", help="Table name")
    parser.add_argument("--db-host", default="127.0.0.1", help="MySQL host")
    parser.add_argument("--db-port", type=int, default=3306, help="MySQL port")
    parser.add_argument("--db-user", default="root", help="MySQL user")
    parser.add_argument("--db-password", default="root", help="MySQL password")
    parser.add_argument("--db-name", default="baidu_search", help="MySQL database")
    parser.add_argument(
        "--danmu-db-name", default="love_page", help="MySQL database for danmu"
    )
    parser.add_argument(
        "--danmu-table", default="love_danmu", help="Danmu table name"
    )
    parser.add_argument(
        "--auth-table", default="love_auth", help="Password table name"
    )
    parser.add_argument(
        "--danmu-limit", type=int, default=50, help="Max danmu messages returned"
    )
    parser.add_argument("--dry-run", action="store_true", help="Print results only")
    return parser


def run_love_page(args: argparse.Namespace) -> None:
    import pymysql

    base_dir = Path(__file__).resolve().parent
    web_dir = base_dir / "docs"
    if not web_dir.exists():
        raise FileNotFoundError("docs directory is missing.")
    login_page = web_dir / "login.html"
    if not login_page.exists():
        raise FileNotFoundError("docs/login.html is missing.")
    photos_dir = web_dir / "photos"
    danmu_limit = max(1, args.danmu_limit)
    danmu_maxlen = 40
    danmu_ready = False
    danmu_error: Optional[str] = None
    auth_ready = False
    auth_error: Optional[str] = None
    session_cookie_name = "love_session"
    session_tokens: set[str] = set()

    danmu_db_name = validate_identifier(args.danmu_db_name, "Danmu database name")
    danmu_table = validate_identifier(args.danmu_table, "Danmu table name")
    auth_table = validate_identifier(args.auth_table, "Auth table name")

    try:
        ensure_database(build_server_config(args), danmu_db_name)
        conn = pymysql.connect(**build_db_config(args, danmu_db_name))
        try:
            ensure_danmu_table(conn, danmu_table)
            ensure_auth_table(conn, auth_table)
            ensure_default_password(conn, auth_table, "20231026")
        finally:
            conn.close()
        danmu_ready = True
        auth_ready = True
    except Exception as exc:
        message = str(exc)
        danmu_error = message
        auth_error = message
        logging.warning("Love page database unavailable: %s", exc)

    class QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            logging.info(format, *args)

        def _normalized_path(self) -> str:
            return urlparse(self.path).path.rstrip("/") or "/"

        def _send_json(
            self,
            payload: object,
            status: int = 200,
            extra_headers: Optional[dict] = None,
        ) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers", "Content-Type, X-File-Name"
            )
            if extra_headers:
                for key, value in extra_headers.items():
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_no_content(self) -> None:
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers", "Content-Type, X-File-Name"
            )
            self.end_headers()

        def _send_redirect(self, location: str) -> None:
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def _read_body(self) -> bytes:
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            if content_length <= 0:
                return b""
            return self.rfile.read(content_length)

        def _session_token(self) -> str:
            raw_cookie = self.headers.get("Cookie", "")
            if not raw_cookie:
                return ""
            cookie = SimpleCookie()
            cookie.load(raw_cookie)
            morsel = cookie.get(session_cookie_name)
            return morsel.value if morsel else ""

        def _is_authenticated(self) -> bool:
            token = self._session_token()
            return bool(token and token in session_tokens)

        def _set_login_cookie(self, token: str) -> str:
            return (
                f"{session_cookie_name}={token}; Path=/; HttpOnly; "
                "SameSite=Lax; Max-Age=2592000"
            )

        def _clear_login_cookie(self) -> str:
            return (
                f"{session_cookie_name}=; Path=/; HttpOnly; "
                "SameSite=Lax; Max-Age=0"
            )

        def do_OPTIONS(self) -> None:
            if self._normalized_path() in {
                "/auth/login",
                "/auth/logout",
                "/auth/status",
                "/photos/import",
                "/photos/upload",
                "/photos/upload-file",
                "/danmu",
                "/danmu/like",
            }:
                self._send_no_content()
                return
            super().do_OPTIONS()

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = self._normalized_path()

            if path == "/auth/status":
                if self._is_authenticated():
                    self._send_json({"authenticated": True})
                else:
                    self._send_json({"authenticated": False}, 401)
                return

            if path in {"/login", "/login.html"}:
                if self._is_authenticated():
                    self._send_redirect("/index.html")
                    return
                self.path = "/login.html"
                super().do_GET()
                return

            if path == "/":
                self._send_redirect("/index.html" if self._is_authenticated() else "/login.html")
                return

            if not self._is_authenticated():
                self._send_redirect("/login.html")
                return

            if path == "/photos.json":
                images: List[Path] = []
                if photos_dir.exists():
                    for item in photos_dir.iterdir():
                        if not item.is_file():
                            continue
                        if is_image_filename(item.name):
                            images.append(item)
                images.sort(key=photo_sort_key)
                payload = [f"photos/{quote(item.name)}" for item in images]
                self._send_json(payload)
                return
            if path == "/danmu":
                if not danmu_ready:
                    self._send_json({"error": danmu_error or "danmu unavailable"}, 503)
                    return
                limit = danmu_limit
                query = parse_qs(parsed.query)
                if "limit" in query and query["limit"]:
                    try:
                        limit = int(query["limit"][0])
                    except ValueError:
                        limit = danmu_limit
                limit = max(1, min(limit, danmu_limit))
                conn = pymysql.connect(**build_db_config(args, danmu_db_name))
                try:
                    items = fetch_danmu(conn, danmu_table, limit)
                finally:
                    conn.close()
                self._send_json(items)
                return
            super().do_GET()

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            path = self._normalized_path()

            if path == "/auth/login":
                if not auth_ready:
                    self._send_json({"error": auth_error or "auth unavailable"}, 503)
                    return
                body = self._read_body()
                body_text = body.decode("utf-8", errors="ignore")
                content_type = self.headers.get("Content-Type", "")
                password = ""
                if "application/json" in content_type:
                    try:
                        payload = json.loads(body_text or "{}")
                        password = str(payload.get("password", "")).strip()
                    except json.JSONDecodeError:
                        password = ""
                else:
                    password = parse_qs(body_text).get("password", [""])[0].strip()

                if not password:
                    self._send_json({"error": "请输入密码"}, 400)
                    return

                conn = pymysql.connect(**build_db_config(args, danmu_db_name))
                try:
                    ok = password_exists(conn, auth_table, password)
                finally:
                    conn.close()
                if not ok:
                    self._send_json({"error": "密码是我们故事开始的日子"}, 401)
                    return

                token = secrets.token_urlsafe(32)
                session_tokens.add(token)
                self._send_json(
                    {"ok": True},
                    extra_headers={"Set-Cookie": self._set_login_cookie(token)},
                )
                return

            if path == "/auth/logout":
                token = self._session_token()
                if token:
                    session_tokens.discard(token)
                self._send_json(
                    {"ok": True},
                    extra_headers={"Set-Cookie": self._clear_login_cookie()},
                )
                return

            if not self._is_authenticated():
                self._send_json({"error": "unauthorized"}, 401)
                return

            if path in {"/photos/upload-file", "/photos/upload"}:
                file_name = unquote(self.headers.get("X-File-Name", "").strip())
                safe_name = sanitize_upload_filename(file_name)
                if not safe_name:
                    self._send_json({"error": "missing file name"}, 400)
                    return
                if not is_image_filename(safe_name):
                    self._send_json({"error": "only image files are allowed"}, 400)
                    return
                file_data = self._read_body()
                if not file_data:
                    self._send_json({"error": "empty file"}, 400)
                    return
                photos_dir.mkdir(parents=True, exist_ok=True)
                target = build_unique_photo_path(photos_dir, safe_name)
                target.write_bytes(file_data)
                self._send_json(
                    {
                        "ok": True,
                        "saved": 1,
                        "name": target.name,
                        "original_name": safe_name,
                    }
                )
                return

            if path == "/photos/import":
                archive_data = self._read_body()
                if not archive_data:
                    self._send_json({"error": "empty upload"}, 400)
                    return
                photos_dir.mkdir(parents=True, exist_ok=True)
                try:
                    saved = import_zip_photos(archive_data, photos_dir)
                except zipfile.BadZipFile:
                    self._send_json({"error": "invalid zip file"}, 400)
                    return
                except Exception as exc:
                    self._send_json({"error": str(exc)}, 500)
                    return
                self._send_json({"ok": True, "saved": saved})
                return

            if path == "/danmu/like":
                if not danmu_ready:
                    self._send_json(
                        {"error": danmu_error or "danmu unavailable"}, 503
                    )
                    return
                body = self._read_body().decode("utf-8", errors="ignore")
                raw_id: Optional[str] = None
                content_type = self.headers.get("Content-Type", "")
                if "application/json" in content_type:
                    try:
                        payload = json.loads(body or "{}")
                        raw_id = str(payload.get("id", "")).strip()
                    except json.JSONDecodeError:
                        raw_id = None
                else:
                    raw_id = parse_qs(body).get("id", [""])[0].strip()
                try:
                    danmu_id = int(raw_id or "0")
                except ValueError:
                    danmu_id = 0
                if danmu_id <= 0:
                    self._send_json({"error": "invalid id"}, 400)
                    return
                conn = pymysql.connect(**build_db_config(args, danmu_db_name))
                try:
                    like_table = f"{danmu_table}_likes"
                    client_ip = (
                        self.headers.get("X-Real-IP")
                        or self.headers.get("X-Forwarded-For")
                        or ""
                    )
                    if "," in client_ip:
                        client_ip = client_ip.split(",", 1)[0].strip()
                    client_ip = client_ip.strip() or self.client_address[0]
                    result = increment_danmu_like(
                        conn, danmu_table, like_table, danmu_id, client_ip
                    )
                finally:
                    conn.close()
                if result is None:
                    self._send_json({"error": "not found"}, 404)
                    return
                self._send_json(
                    {
                        "ok": True,
                        "id": danmu_id,
                        "likes": result.get("likes"),
                        "liked": result.get("liked"),
                    }
                )
                return
            if path != "/danmu":
                super().do_POST()
                return
            if not danmu_ready:
                self._send_json({"error": danmu_error or "danmu unavailable"}, 503)
                return
            body = self._read_body().decode("utf-8", errors="ignore")
            text = ""
            content_type = self.headers.get("Content-Type", "")
            if "application/json" in content_type:
                try:
                    payload = json.loads(body or "{}")
                    text = str(payload.get("text", "")).strip()
                except json.JSONDecodeError:
                    text = ""
            else:
                text = parse_qs(body).get("text", [""])[0].strip()
            text = re.sub(r"\s+", " ", text).strip()
            if not text:
                self._send_json({"error": "empty"}, 400)
                return
            text = text[:danmu_maxlen]
            conn = pymysql.connect(**build_db_config(args, danmu_db_name))
            try:
                row_id = insert_danmu(conn, danmu_table, text)
            finally:
                conn.close()
            self._send_json({"ok": True, "id": row_id, "likes": 0, "text": text})

    handler = functools.partial(QuietHandler, directory=str(web_dir))
    with ThreadingHTTPServer((args.host, args.port), handler) as server:
        host, real_port = server.server_address
        display_host = "127.0.0.1" if host == "0.0.0.0" else host
        url = f"http://{display_host}:{real_port}/login.html"
        logging.info("Love page ready: %s", url)
        try:
            webbrowser.open(url, new=1)
        except Exception as exc:
            logging.warning("Failed to open browser: %s", exc)
        server.serve_forever()


def run_crawler(args: argparse.Namespace) -> None:
    import pymysql

    html = fetch_html(args.url)
    results = parse_results(html)
    keyword = args.keyword.strip() or parse_keyword_from_url(args.url)

    if not results:
        logging.warning("No results found. The page may require verification.")
        return

    if args.dry_run:
        for item in results:
            logging.info(
                "rank=%s title=%s url=%s",
                item.rank,
                item.title,
                item.url,
            )
        return

    table = validate_identifier(args.table, "Table name")
    db_name = validate_identifier(args.db_name, "Database name")
    ensure_database(build_server_config(args), db_name)
    conn = pymysql.connect(**build_db_config(args, db_name))
    try:
        ensure_table(conn, table)
        inserted = insert_results(conn, table, keyword, results)
        logging.info("Inserted %s rows into %s.", inserted, table)
    finally:
        conn.close()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    args = build_parser().parse_args()

    if args.mode == "love":
        run_love_page(args)
        return

    run_crawler(args)


if __name__ == "__main__":
    main()
