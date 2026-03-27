import sys
import os
import re
from pathlib import Path
from datetime import datetime

project_root = Path(__file__).resolve().parent.parent
sys.path.append(str(project_root))

from backend.database import init_tables, get_db
from backend.services.oss_storage import get_oss_bucket, get_oss_domain
import oss2

def parse_time_from_filename(filename: str) -> str:
    """尝试从 微信图片_20260215030940_83_401.jpg 提取时间字符串，返回 YYYY-MM-DD HH:MM:SS"""
    match = re.search(r'_(\d{14})_', filename)
    if match:
        ts = match.group(1)
        try:
            dt = datetime.strptime(ts, "%Y%m%d%H%M%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def main():
    print(">>> 正在初始化数据表结构...")
    init_tables()
    
    print(">>> 正在获取 OSS 连接句柄...")
    bucket = get_oss_bucket()
    if not bucket:
        print("OSS 挂了或者没配置！")
        sys.exit(1)
        
    domain = get_oss_domain()
    
    print(">>> 开始扫描 OSS 图片清单...")
    prefix = "photos/"
    oss_objects = []
    
    for obj in oss2.ObjectIterator(bucket, prefix=prefix):
        if obj.key == prefix:
            continue
        oss_objects.append(obj.key)
        
    print(f"扫描到 {len(oss_objects)} 张图片，开始同步入库...")
    
    success_count = 0
    skip_count = 0
    
    try:
        with get_db() as conn:
            with conn.cursor() as cursor:
                for i, key in enumerate(oss_objects, 1):
                    filename = key.replace(prefix, "")
                    oss_url = f"{domain}/{key}"
                    created_at = parse_time_from_filename(filename)
                    
                    # Check exist
                    cursor.execute("SELECT id FROM love_photos WHERE filename = %s", (filename,))
                    if cursor.fetchone():
                        skip_count += 1
                        print(f"[{i}/{len(oss_objects)}] ⏭️ 已存在跳过: {filename}")
                        continue
                        
                    cursor.execute(
                        """
                        INSERT INTO love_photos (filename, oss_url, description, album_category, created_at) 
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (filename, oss_url, "", "default", created_at)
                    )
                    print(f"[{i}/{len(oss_objects)}] ✅ 入库成功: {filename} -> {created_at}")
                    success_count += 1
                    
            conn.commit()
    except Exception as e:
        print(f"数据库执行异常: {e}")
        
    print("\n===============================")
    print(f"🎉 存量元数据同步完成！")
    print(f"入库成功: {success_count} 条")
    print(f"忽略跳过: {skip_count} 条")
    print("===============================\n")

if __name__ == "__main__":
    main()
