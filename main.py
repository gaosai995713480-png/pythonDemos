"""
Baidu search crawler -> MySQL saver.
"""

from __future__ import annotations

import argparse
import functools
import json
import logging
import re
import webbrowser
from dataclasses import dataclass
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterable, List, Optional
from urllib.parse import parse_qs, urlparse


DEFAULT_URL = (
    "https://www.baidu.com/s?"
    "wd=%E5%A4%96%E4%BA%A4%E9%83%A8%EF%BC%9A"
    "%E5%BC%BA%E7%83%88%E8%B0%B4%E8%B4%A3"
    "%E7%93%9C%E8%BE%BE%E5%B0%94%E6%B8%AF"
    "%E8%A2%AD%E5%87%BB%E4%BA%8B%E4%BB%B6"
    "&tn=15007414_23_dg"
)


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
    photos_dir = web_dir / "photos"
    danmu_limit = max(1, args.danmu_limit)
    danmu_maxlen = 40
    danmu_ready = False
    danmu_error: Optional[str] = None

    try:
        danmu_db_name = validate_identifier(args.danmu_db_name, "Danmu database name")
        danmu_table = validate_identifier(args.danmu_table, "Danmu table name")
        ensure_database(build_server_config(args), danmu_db_name)
        conn = pymysql.connect(**build_db_config(args, danmu_db_name))
        try:
            ensure_danmu_table(conn, danmu_table)
        finally:
            conn.close()
        danmu_ready = True
    except Exception as exc:
        danmu_error = str(exc)
        logging.warning("Danmu database unavailable: %s", exc)

    class QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            logging.info(format, *args)

        def _send_json(self, payload: object, status: int = 200) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_no_content(self) -> None:
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

        def do_OPTIONS(self) -> None:
            if urlparse(self.path).path.rstrip("/") in {"/danmu", "/danmu/like"}:
                self._send_no_content()
                return
            super().do_OPTIONS()

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            if path == "/photos.json":
                images: List[str] = []
                if photos_dir.exists():
                    for item in photos_dir.iterdir():
                        if not item.is_file():
                            continue
                        if item.suffix.lower() in {
                            ".jpg",
                            ".jpeg",
                            ".png",
                            ".webp",
                            ".gif",
                            ".bmp",
                        }:
                            images.append(f"photos/{item.name}")
                images.sort()
                self._send_json(images)
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
            path = parsed.path.rstrip("/")
            if path == "/danmu/like":
                if not danmu_ready:
                    self._send_json(
                        {"error": danmu_error or "danmu unavailable"}, 503
                    )
                    return
                content_length = int(self.headers.get("Content-Length", "0") or "0")
                body = self.rfile.read(content_length).decode(
                    "utf-8", errors="ignore"
                )
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
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
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
        url = f"http://{display_host}:{real_port}/index.html"
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
