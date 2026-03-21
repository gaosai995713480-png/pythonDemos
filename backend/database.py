"""
数据库连接管理 + 表初始化
使用 pymysql 同步连接（FastAPI 中通过 run_in_executor 或直接同步调用）
"""
import pymysql
import logging
from contextlib import contextmanager
from .config import settings

logger = logging.getLogger(__name__)

_TABLE_INIT_DONE = False


def _get_connection() -> pymysql.connections.Connection:
    return pymysql.connect(
        host=settings.db_host,
        port=settings.db_port,
        user=settings.db_user,
        password=settings.db_password,
        database=settings.db_name,
        charset="utf8mb4",
    )


@contextmanager
def get_db():
    """数据库连接上下文管理器"""
    conn = _get_connection()
    try:
        yield conn
    finally:
        conn.close()


def ensure_database():
    """确保数据库存在"""
    conn = pymysql.connect(
        host=settings.db_host,
        port=settings.db_port,
        user=settings.db_user,
        password=settings.db_password,
        charset="utf8mb4",
        autocommit=True,
    )
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{settings.db_name}` DEFAULT CHARACTER SET utf8mb4"
            )
    finally:
        conn.close()


def _has_column(conn, table: str, column: str) -> bool:
    sql = """
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = %s AND table_name = %s AND column_name = %s
    """
    with conn.cursor() as cursor:
        cursor.execute(sql, (settings.db_name, table, column))
        return cursor.fetchone()[0] > 0


def init_tables():
    """初始化所有数据表"""
    global _TABLE_INIT_DONE
    if _TABLE_INIT_DONE:
        return

    ensure_database()
    conn = _get_connection()
    try:
        tables = {
            settings.danmu_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.danmu_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    content VARCHAR(120) NOT NULL,
                    likes INT NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            f"{settings.danmu_table}_likes": f"""
                CREATE TABLE IF NOT EXISTS `{settings.danmu_table}_likes` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    danmu_id BIGINT NOT NULL,
                    ip VARCHAR(45) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_danmu_ip (danmu_id, ip)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            settings.auth_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.auth_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    password VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            settings.timeline_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.timeline_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    event_date DATE NOT NULL,
                    title VARCHAR(100) NOT NULL,
                    content TEXT,
                    photo_url VARCHAR(500),
                    icon VARCHAR(10) DEFAULT '💕',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            settings.capsule_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.capsule_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    content TEXT NOT NULL,
                    open_date DATE NOT NULL,
                    is_opened TINYINT NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            settings.mood_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.mood_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    mood_date DATE NOT NULL UNIQUE,
                    emoji VARCHAR(10) NOT NULL DEFAULT '😊',
                    note VARCHAR(200),
                    level TINYINT NOT NULL DEFAULT 3,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            settings.wish_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.wish_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    content VARCHAR(200) NOT NULL,
                    x FLOAT NOT NULL DEFAULT 0.5,
                    y FLOAT NOT NULL DEFAULT 0.5,
                    color VARCHAR(20) DEFAULT '#ffd700',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            settings.map_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.map_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(100) NOT NULL,
                    note TEXT,
                    photo_url VARCHAR(500),
                    lat DOUBLE NOT NULL,
                    lng DOUBLE NOT NULL,
                    visit_date DATE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            settings.music_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.music_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    song_name VARCHAR(100) NOT NULL,
                    artist VARCHAR(100) NOT NULL,
                    netease_id VARCHAR(20) NOT NULL,
                    platform VARCHAR(20) NOT NULL DEFAULT 'netease',
                    sort_order INT DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
        }

        with conn.cursor() as cursor:
            for name, sql in tables.items():
                cursor.execute(sql)

        # 确保 danmu 表有 likes 列
        if not _has_column(conn, settings.danmu_table, "likes"):
            with conn.cursor() as cursor:
                cursor.execute(
                    f"ALTER TABLE `{settings.danmu_table}` ADD COLUMN likes INT NOT NULL DEFAULT 0"
                )

        # 确保 music 表有 platform 列
        try:
            if not _has_column(conn, settings.music_table, "platform"):
                with conn.cursor() as cursor:
                    cursor.execute(
                        f"ALTER TABLE `{settings.music_table}` ADD COLUMN platform VARCHAR(20) NOT NULL DEFAULT 'netease'"
                    )
        except Exception:
            pass

        # 兼容 password_hash → password
        if not _has_column(conn, settings.auth_table, "password") and _has_column(conn, settings.auth_table, "password_hash"):
            with conn.cursor() as cursor:
                cursor.execute(f"ALTER TABLE `{settings.auth_table}` ADD COLUMN password VARCHAR(255) NULL")
                cursor.execute(f"UPDATE `{settings.auth_table}` SET password = password_hash WHERE password IS NULL")
                cursor.execute(f"ALTER TABLE `{settings.auth_table}` MODIFY COLUMN password VARCHAR(255) NOT NULL")

        # 确保默认密码
        with conn.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) FROM `{settings.auth_table}`")
            if cursor.fetchone()[0] == 0:
                cursor.execute(
                    f"INSERT INTO `{settings.auth_table}` (password) VALUES (%s)",
                    (settings.default_password,),
                )
        conn.commit()
        _TABLE_INIT_DONE = True
        logger.info("所有数据表初始化完成")
    except Exception as e:
        logger.warning("数据库初始化失败: %s", e)
        raise
    finally:
        conn.close()
