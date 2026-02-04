"""
Baidu search crawler -> MySQL saver.
"""

from __future__ import annotations

import argparse
import functools
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
    parser.add_argument("--url", default=DEFAULT_URL, help="Baidu search URL")
    parser.add_argument("--keyword", default="", help="Override keyword")
    parser.add_argument("--table", default="baidu_search_results", help="Table name")
    parser.add_argument("--db-host", default="127.0.0.1", help="MySQL host")
    parser.add_argument("--db-port", type=int, default=3306, help="MySQL port")
    parser.add_argument("--db-user", default="root", help="MySQL user")
    parser.add_argument("--db-password", default="root", help="MySQL password")
    parser.add_argument("--db-name", default="baidu_search", help="MySQL database")
    parser.add_argument("--dry-run", action="store_true", help="Print results only")
    return parser


def run_love_page(port: int) -> None:
    base_dir = Path(__file__).resolve().parent
    static_dir = base_dir / "static"
    if not static_dir.exists():
        raise FileNotFoundError("static directory is missing.")

    class QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            logging.info(format, *args)

    handler = functools.partial(QuietHandler, directory=str(static_dir))
    with ThreadingHTTPServer(("127.0.0.1", port), handler) as server:
        host, real_port = server.server_address
        url = f"http://{host}:{real_port}/love.html"
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
        run_love_page(args.port)
        return

    run_crawler(args)


if __name__ == "__main__":
    main()
