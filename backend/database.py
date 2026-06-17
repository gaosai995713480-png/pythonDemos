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
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '弹幕ID',
                    content VARCHAR(120) NOT NULL COMMENT '弹幕内容',
                    likes INT NOT NULL DEFAULT 0 COMMENT '点赞数',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='弹幕表'
            """,
            f"{settings.danmu_table}_likes": f"""
                CREATE TABLE IF NOT EXISTS `{settings.danmu_table}_likes` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '记录ID',
                    danmu_id BIGINT NOT NULL COMMENT '弹幕ID',
                    ip VARCHAR(45) NOT NULL COMMENT '点赞者IP',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '点赞时间',
                    UNIQUE KEY uniq_danmu_ip (danmu_id, ip)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='弹幕点赞记录'
            """,
            settings.timeline_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.timeline_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '事件ID',
                    event_date DATE NOT NULL COMMENT '事件日期',
                    title VARCHAR(100) NOT NULL COMMENT '事件标题',
                    content TEXT COMMENT '事件描述',
                    photo_url VARCHAR(500) COMMENT '配图URL',
                    icon VARCHAR(10) DEFAULT '💕' COMMENT '图标emoji',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='恋爱时间轴'
            """,
            settings.capsule_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.capsule_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '胶囊ID',
                    content TEXT NOT NULL COMMENT '胶囊内容',
                    open_date DATE NOT NULL COMMENT '开启日期',
                    is_opened TINYINT NOT NULL DEFAULT 0 COMMENT '是否已开启：0=未开, 1=已开',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='时间胶囊'
            """,
            settings.mood_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.mood_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '记录ID',
                    mood_date DATE NOT NULL UNIQUE COMMENT '心情日期，每天唯一',
                    emoji VARCHAR(10) NOT NULL DEFAULT '😊' COMMENT '心情emoji',
                    note VARCHAR(200) COMMENT '心情备注',
                    level TINYINT NOT NULL DEFAULT 3 COMMENT '心情等级：1-5',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='心情打卡'
            """,
            settings.wish_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.wish_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '愿望ID',
                    content VARCHAR(200) NOT NULL COMMENT '愿望内容',
                    x FLOAT NOT NULL DEFAULT 0.5 COMMENT '页面X坐标(0-1)',
                    y FLOAT NOT NULL DEFAULT 0.5 COMMENT '页面Y坐标(0-1)',
                    color VARCHAR(20) DEFAULT '#ffd700' COMMENT '愿望颜色',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='许愿墙'
            """,
            settings.map_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.map_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '标记ID',
                    title VARCHAR(100) NOT NULL COMMENT '地点名称',
                    note TEXT COMMENT '地点备注',
                    photo_url VARCHAR(500) COMMENT '照片URL',
                    lat DOUBLE NOT NULL COMMENT '纬度',
                    lng DOUBLE NOT NULL COMMENT '经度',
                    visit_date DATE COMMENT '到访日期',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='恋爱地图'
            """,
            settings.map_photos_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.map_photos_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '照片ID',
                    marker_id BIGINT NOT NULL COMMENT '关联 love_map.id',
                    photo_url VARCHAR(500) NOT NULL COMMENT 'OSS完整URL',
                    sort_order INT DEFAULT 0 COMMENT '排序',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    INDEX idx_marker_id (marker_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='足迹照片'
            """,
            settings.music_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.music_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '歌曲ID',
                    song_name VARCHAR(100) NOT NULL COMMENT '歌曲名',
                    artist VARCHAR(100) NOT NULL COMMENT '歌手',
                    netease_id VARCHAR(20) NOT NULL COMMENT '平台歌曲ID',
                    platform VARCHAR(20) NOT NULL DEFAULT 'netease' COMMENT '音乐平台：netease/tencent/kugou/kuwo',
                    sort_order INT DEFAULT 0 COMMENT '排序权重',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='歌单'
            """,
            settings.song_request_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.song_request_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '推荐ID',
                    song_id VARCHAR(20) NOT NULL COMMENT '平台歌曲ID',
                    song_name VARCHAR(100) NOT NULL COMMENT '歌曲名',
                    artist VARCHAR(100) NOT NULL COMMENT '歌手',
                    platform VARCHAR(20) NOT NULL DEFAULT 'netease' COMMENT '音乐平台',
                    nickname VARCHAR(30) DEFAULT '匿名访客' COMMENT '推荐人昵称',
                    message VARCHAR(100) DEFAULT '' COMMENT '推荐理由',
                    likes INT NOT NULL DEFAULT 0 COMMENT '点赞数',
                    ip VARCHAR(45) NOT NULL COMMENT '推荐者IP',
                    is_adopted TINYINT NOT NULL DEFAULT 0 COMMENT '是否已采纳：0=未采纳, 1=已采纳',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='点歌台推荐'
            """,
            f"{settings.song_request_table}_likes": f"""
                CREATE TABLE IF NOT EXISTS `{settings.song_request_table}_likes` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '记录ID',
                    request_id BIGINT NOT NULL COMMENT '推荐ID',
                    ip VARCHAR(45) NOT NULL COMMENT '点赞者IP',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '点赞时间',
                    UNIQUE KEY uniq_request_ip (request_id, ip)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='点歌台点赞记录'
            """,
            "love_config": """
                CREATE TABLE IF NOT EXISTS `love_config` (
                    config_key VARCHAR(50) PRIMARY KEY COMMENT '配置键，如 INVITE_CODE、METING_NETEASE_COOKIE',
                    config_value TEXT COMMENT '配置值',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='系统配置表'
            """,
            settings.page_password_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.page_password_table}` (
                    page_key VARCHAR(50) PRIMARY KEY COMMENT '页面标识，如 gallery、letter',
                    password VARCHAR(255) NOT NULL COMMENT '页面访问密码',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            settings.users_table: f"""
                CREATE TABLE IF NOT EXISTS `{settings.users_table}` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '用户ID',
                    username VARCHAR(50) UNIQUE NOT NULL COMMENT '用户名，唯一',
                    password VARCHAR(255) NOT NULL COMMENT '登录密码',
                    role VARCHAR(20) NOT NULL DEFAULT 'visitor' COMMENT '角色：admin=管理员, visitor=访客',
                    disabled TINYINT NOT NULL DEFAULT 0 COMMENT '是否禁用：0=正常, 1=禁用',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '注册时间',
                    last_login_at TIMESTAMP NULL DEFAULT NULL COMMENT '最后登录时间'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表'
            """,
            "ai_skill_presets": """
                CREATE TABLE IF NOT EXISTS `ai_skill_presets` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '技能ID',
                    username VARCHAR(50) NOT NULL COMMENT '所属用户名',
                    name VARCHAR(50) NOT NULL COMMENT '技能名称',
                    icon VARCHAR(10) DEFAULT '🤖' COMMENT '图标emoji',
                    system_prompt TEXT NOT NULL COMMENT '系统提示词',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    INDEX idx_username (username)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='AI技能预设'
            """,
            "ai_conversations": """
                CREATE TABLE IF NOT EXISTS `ai_conversations` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '会话ID',
                    username VARCHAR(50) NOT NULL COMMENT '所属用户名',
                    provider VARCHAR(20) NOT NULL COMMENT '供应商: codex/claude/glm/grok',
                    title VARCHAR(100) NOT NULL DEFAULT '新对话' COMMENT '会话标题',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '最后活跃',
                    INDEX idx_user_provider (username, provider, updated_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='AI对话会话'
            """,
            "ai_messages": """
                CREATE TABLE IF NOT EXISTS `ai_messages` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '消息ID',
                    conversation_id BIGINT NOT NULL COMMENT '所属会话ID',
                    role VARCHAR(20) NOT NULL COMMENT 'user/assistant/system',
                    content MEDIUMTEXT NOT NULL COMMENT '消息内容',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    INDEX idx_conv (conversation_id, created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='AI对话消息'
            """,
            "love_photos": """
                CREATE TABLE IF NOT EXISTS `love_photos` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '照片ID',
                    filename VARCHAR(255) UNIQUE NOT NULL COMMENT '文件名/OSS Key',
                    oss_url VARCHAR(1000) NOT NULL COMMENT 'OSS 访问地址或相对路径',
                    description TEXT COMMENT '照片描述或日记',
                    album_category VARCHAR(100) DEFAULT 'default' COMMENT '所属相册分类',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '上传或创建时间',
                    INDEX idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='相册元数据表'
            """,
            "user_facts": """
                CREATE TABLE IF NOT EXISTS `user_facts` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '事实ID',
                    username VARCHAR(50) NOT NULL COMMENT '所属用户',
                    fact_content TEXT NOT NULL COMMENT '事实内容',
                    category VARCHAR(50) DEFAULT 'general' COMMENT '分类: general/date/preference/person',
                    source VARCHAR(20) DEFAULT 'auto' COMMENT '来源: auto(异步提取)/tool(AI主动)/manual',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    INDEX idx_user (username, created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户长期记忆事实表'
            """,
            "love_recipes": """
                CREATE TABLE IF NOT EXISTS `love_recipes` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '菜谱ID',
                    source VARCHAR(30) NOT NULL DEFAULT 'howtocook' COMMENT '来源：howtocook/custom',
                    source_repo VARCHAR(255) DEFAULT '' COMMENT '来源仓库URL',
                    source_commit VARCHAR(80) DEFAULT '' COMMENT '来源commit',
                    source_path VARCHAR(500) NOT NULL COMMENT '来源文件路径',
                    source_hash CHAR(64) NOT NULL COMMENT '源文件内容SHA256',
                    title VARCHAR(120) NOT NULL COMMENT '菜名',
                    category VARCHAR(80) DEFAULT '' COMMENT '分类',
                    description VARCHAR(500) DEFAULT '' COMMENT '简介',
                    raw_markdown MEDIUMTEXT NOT NULL COMMENT '原始Markdown',
                    ingredients_json JSON NULL COMMENT '结构化材料',
                    steps_json JSON NULL COMMENT '结构化步骤',
                    tips TEXT NULL COMMENT '小贴士',
                    difficulty VARCHAR(20) DEFAULT 'unknown' COMMENT '难度',
                    cook_time_minutes INT DEFAULT NULL COMMENT '预计耗时分钟',
                    servings INT DEFAULT NULL COMMENT '份量',
                    tags_json JSON NULL COMMENT '标签',
                    is_enabled TINYINT NOT NULL DEFAULT 1 COMMENT '是否启用',
                    is_archived TINYINT NOT NULL DEFAULT 0 COMMENT '是否归档',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
                    UNIQUE KEY uniq_recipe_source_path (source, source_path),
                    KEY idx_recipe_category (category),
                    KEY idx_recipe_enabled (is_enabled),
                    KEY idx_recipe_source_hash (source_hash)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='做菜食谱表'
            """,
            "love_recipe_import_batches": """
                CREATE TABLE IF NOT EXISTS `love_recipe_import_batches` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '导入批次ID',
                    source VARCHAR(30) NOT NULL DEFAULT 'howtocook' COMMENT '来源',
                    source_repo VARCHAR(255) NOT NULL COMMENT '来源仓库URL',
                    source_commit VARCHAR(80) DEFAULT '' COMMENT '来源commit',
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '开始时间',
                    finished_at TIMESTAMP NULL DEFAULT NULL COMMENT '结束时间',
                    status VARCHAR(20) NOT NULL DEFAULT 'running' COMMENT '状态',
                    total_files INT NOT NULL DEFAULT 0 COMMENT '总文件数',
                    created_count INT NOT NULL DEFAULT 0 COMMENT '新增数量',
                    updated_count INT NOT NULL DEFAULT 0 COMMENT '更新数量',
                    skipped_count INT NOT NULL DEFAULT 0 COMMENT '跳过数量',
                    failed_count INT NOT NULL DEFAULT 0 COMMENT '失败数量',
                    error_message TEXT NULL COMMENT '批次错误信息',
                    created_by VARCHAR(50) DEFAULT 'system' COMMENT '触发人'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='食谱导入批次表'
            """,
            "love_recipe_import_errors": """
                CREATE TABLE IF NOT EXISTS `love_recipe_import_errors` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '导入错误ID',
                    batch_id BIGINT NOT NULL COMMENT '导入批次ID',
                    source_path VARCHAR(500) NOT NULL COMMENT '来源文件路径',
                    error_type VARCHAR(80) NOT NULL COMMENT '错误类型',
                    error_message TEXT NOT NULL COMMENT '错误信息',
                    raw_excerpt TEXT NULL COMMENT '原文片段',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    KEY idx_import_error_batch (batch_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='食谱导入错误表'
            """,
            "love_recipe_user_states": """
                CREATE TABLE IF NOT EXISTS `love_recipe_user_states` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '状态ID',
                    recipe_id BIGINT NOT NULL COMMENT '菜谱ID',
                    username VARCHAR(50) NOT NULL COMMENT '用户名',
                    is_favorite TINYINT NOT NULL DEFAULT 0 COMMENT '是否收藏',
                    want_to_cook TINYINT NOT NULL DEFAULT 0 COMMENT '是否想做',
                    cooked_count INT NOT NULL DEFAULT 0 COMMENT '做过次数',
                    last_cooked_at DATE NULL COMMENT '最近做过日期',
                    rating TINYINT NULL COMMENT '用户评分1-5',
                    note VARCHAR(500) DEFAULT '' COMMENT '用户备注',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
                    UNIQUE KEY uniq_recipe_user_state (recipe_id, username),
                    KEY idx_recipe_user_username (username),
                    KEY idx_recipe_user_flags (is_favorite, want_to_cook)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户食谱状态表'
            """,
            "love_cooking_records": """
                CREATE TABLE IF NOT EXISTS `love_cooking_records` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '做饭记录ID',
                    recipe_id BIGINT NOT NULL COMMENT '菜谱ID',
                    username VARCHAR(50) NOT NULL COMMENT '记录用户',
                    cooked_date DATE NOT NULL COMMENT '做饭日期',
                    rating TINYINT NULL COMMENT '评分1-5',
                    mood VARCHAR(30) DEFAULT '' COMMENT '心情',
                    photo_url VARCHAR(500) DEFAULT '' COMMENT '成品照片URL',
                    note TEXT NULL COMMENT '做饭备注',
                    next_time_improvement TEXT NULL COMMENT '下次改进',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
                    KEY idx_cooking_records_recipe (recipe_id),
                    KEY idx_cooking_records_user_date (username, cooked_date)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='做饭记录表'
            """,
            "love_cooking_menus": """
                CREATE TABLE IF NOT EXISTS `love_cooking_menus` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '菜单ID',
                    title VARCHAR(120) NOT NULL COMMENT '菜单标题',
                    menu_date DATE NULL COMMENT '菜单日期',
                    description VARCHAR(500) DEFAULT '' COMMENT '菜单描述',
                    status VARCHAR(20) NOT NULL DEFAULT 'planned' COMMENT 'planned/done/cancelled',
                    created_by VARCHAR(50) NOT NULL COMMENT '创建人',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
                    KEY idx_cooking_menus_user_date (created_by, menu_date),
                    KEY idx_cooking_menus_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='做饭菜单表'
            """,
            "love_cooking_menu_items": """
                CREATE TABLE IF NOT EXISTS `love_cooking_menu_items` (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '菜单明细ID',
                    menu_id BIGINT NOT NULL COMMENT '菜单ID',
                    recipe_id BIGINT NOT NULL COMMENT '菜谱ID',
                    sort_order INT NOT NULL DEFAULT 0 COMMENT '排序',
                    note VARCHAR(300) DEFAULT '' COMMENT '备注',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    UNIQUE KEY uniq_menu_recipe (menu_id, recipe_id),
                    KEY idx_menu_items_menu (menu_id),
                    KEY idx_menu_items_recipe (recipe_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='做饭菜单明细表'
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

        # 确保 users 表有 last_login_at 列
        if not _has_column(conn, settings.users_table, "last_login_at"):
            with conn.cursor() as cursor:
                cursor.execute(
                    f"ALTER TABLE `{settings.users_table}` ADD COLUMN last_login_at TIMESTAMP NULL DEFAULT NULL COMMENT '最后登录时间'"
                )

        # 确保画廊默认密码
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT COUNT(*) FROM `{settings.page_password_table}` WHERE page_key = 'gallery'"
            )
            if cursor.fetchone()[0] == 0:
                cursor.execute(
                    f"INSERT INTO `{settings.page_password_table}` (page_key, password) VALUES (%s, %s)",
                    ("gallery", "201220"),
                )

        # 确保默认 admin 用户
        with conn.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) FROM `{settings.users_table}`")
            if cursor.fetchone()[0] == 0:
                cursor.execute(
                    f"INSERT INTO `{settings.users_table}` (username, password, role) VALUES (%s, %s, %s)",
                    ("admin", "201220", "admin"),
                )

        # 确保默认邀请码及 OSS 配置项
        default_configs = [
            ("INVITE_CODE", "love2023"),
            ("OSS_ENDPOINT", ""),
            ("OSS_BUCKET_NAME", ""),
            ("OSS_ACCESS_KEY_ID", ""),
            ("OSS_ACCESS_KEY_SECRET", ""),
            ("CLAUDE_BASE_URL", ""),
            ("CLAUDE_API_KEY", ""),
            ("AGENT_SHOW_TOOL_PROCESS", "true"),
            ("AGENT_MAX_TOOL_ROUNDS", "5"),
            ("TRIPSTAR_ENABLED", "true"),
            ("TRIPSTAR_MOCK_MODE", "true"),
            ("TRIPSTAR_LLM_MODEL_ID", ""),
            ("TRIPSTAR_LLM_API_KEY", ""),
            ("TRIPSTAR_LLM_BASE_URL", ""),
            ("TRIPSTAR_LLM_TIMEOUT", "600"),
            ("TRIPSTAR_AMAP_WEB_KEY", ""),
            ("TRIPSTAR_ENABLE_XHS", "false"),
            ("TRIPSTAR_XHS_COOKIE", ""),
            ("TRIPSTAR_GOOGLE_MAPS_API_KEY", ""),
            ("TRIPSTAR_GOOGLE_MAPS_PROXY", ""),
            ("VITE_TRIPSTAR_AMAP_WEB_JS_KEY", ""),
            ("VITE_TRIPSTAR_AMAP_SECURITY_JS_CODE", ""),
        ]
        with conn.cursor() as cursor:
            for k, v in default_configs:
                cursor.execute("SELECT COUNT(*) FROM love_config WHERE config_key = %s", (k,))
                if cursor.fetchone()[0] == 0:
                    cursor.execute(
                        "INSERT INTO love_config (config_key, config_value) VALUES (%s, %s)",
                        (k, v),
                    )

        # 从 .env 迁移 Cookie 到数据库（仅当数据库中无记录时）
        _migrate_env_cookies(conn)

        conn.commit()
        _TABLE_INIT_DONE = True
        logger.info("所有数据表初始化完成")
    except Exception as e:
        logger.warning("数据库初始化失败: %s", e)
        raise
    finally:
        conn.close()


# ==================== 配置管理 ====================

_COOKIE_ENV_KEYS = [
    "METING_NETEASE_COOKIE",
    "METING_TENCENT_COOKIE",
    "METING_KUGOU_COOKIE",
    "METING_KUWO_COOKIE",
]


def _migrate_env_cookies(conn):
    """首次启动时，将 .env 中的 Cookie 迁移到数据库（仅当数据库中无记录时）"""
    import os
    with conn.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM love_config WHERE config_key LIKE 'METING_%'")
        if cursor.fetchone()[0] > 0:
            return  # 数据库中已有记录，不覆盖
        for key in _COOKIE_ENV_KEYS:
            value = os.environ.get(key, "")
            if value:
                cursor.execute(
                    "INSERT INTO love_config (config_key, config_value) VALUES (%s, %s) "
                    "ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)",
                    (key, value),
                )
                logger.info("已从环境变量迁移 %s 到数据库", key)


def get_config(key: str) -> str:
    """从数据库读取配置值"""
    try:
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT config_value FROM love_config WHERE config_key = %s", (key,)
                )
                row = cursor.fetchone()
                return row[0] if row and row[0] else ""
    except Exception:
        return ""


def get_all_cookies() -> dict:
    """从数据库读取所有 Meting Cookie 配置"""
    try:
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT config_key, config_value FROM love_config WHERE config_key LIKE 'METING_%'"
                )
                return {r[0]: r[1] for r in cursor.fetchall() if r[1]}
    except Exception:
        return {}


def get_all_configs() -> dict:
    """读取 love_config 中所有配置。"""
    try:
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT config_key, config_value FROM love_config ORDER BY config_key"
                )
                return {r[0]: r[1] or "" for r in cursor.fetchall()}
    except Exception:
        return {}


def set_config(key: str, value: str) -> None:
    """写入或更新配置值"""
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO love_config (config_key, config_value) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)",
                (key, value),
            )
        conn.commit()


def verify_page_password(page_key: str, password: str) -> bool:
    """验证页面密码（通用）"""
    import hmac
    try:
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    f"SELECT password FROM `{settings.page_password_table}` WHERE page_key = %s",
                    (page_key,),
                )
                row = cursor.fetchone()
                if not row:
                    return False
                return hmac.compare_digest(password, row[0])
    except Exception:
        return False
