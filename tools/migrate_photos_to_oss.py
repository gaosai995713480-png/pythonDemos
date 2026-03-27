import sys
import os
from pathlib import Path

# 将项目根目录加入模块检索路径
project_root = Path(__file__).resolve().parent.parent
sys.path.append(str(project_root))

from backend.config import settings
from backend.services.oss_storage import upload_to_oss, get_oss_bucket
from backend.utils import is_image_filename
from backend.database import init_tables

def main():
    print(">>> 正在连接数据库加载 OSS 配置...")
    # 触发数据库连接获取 config
    init_tables()
    
    print(">>> 正在校验 OSS 引擎权限...")
    bucket = get_oss_bucket()
    if not bucket:
        print("未检测到 OSS 动态配置。请确保你已经在 MySQL 的 `love_config` 表中填入了有效的 OSS 秘钥。")
        sys.exit(1)
        
    photos_dir = settings.photos_dir
    print(f">>> 正在扫描本地目录: {photos_dir}")
    if not photos_dir.exists():
        print(f"本地目录 {photos_dir} 不存在，未发现历史数据。")
        sys.exit(0)
        
    # 筛选所有图片文件
    images = [p for p in photos_dir.iterdir() if p.is_file() and is_image_filename(p.name)]
    if not images:
        print("未扫描到任何合法的图像文件遗产。")
        sys.exit(0)
        
    print(f"\n==========================================")
    print(f" 📦 发现历史遗产：总共 {len(images)} 张绝密照片")
    print(f" 🚀 OSS 引擎点火中... 启动跑批迁徙任务")
    print(f"==========================================\n")
    
    success_count = 0
    fail_count = 0
    
    for i, file_path in enumerate(images, 1):
        print(f"[{i}/{len(images)}] 正在抛掷 <{file_path.name}> 至云端... ", end="", flush=True)
        file_bytes = file_path.read_bytes()
        
        ok = upload_to_oss(file_path.name, file_bytes)
        if ok:
            print("🚀 穿梭成功")
            success_count += 1
        else:
            print("❌ 发动机故障")
            fail_count += 1
            
    print(f"\n==========================================")
    print(f"🎉 跑批迁徙作业全面结束！")
    print(f"✅ 成功着陆: {success_count} 张")
    print(f"💣 坠毁失败: {fail_count} 张")
    print(f"==========================================\n")

if __name__ == "__main__":
    main()
