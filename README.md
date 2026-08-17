# xiguasaiLove

一个集生活记录、旅行规划与 AI 助手于一体的个人全栈应用。

## ✨ 功能特性

- 📝 **时间线 / 弹幕**：记录生活点滴，支持弹幕互动
- 🕰️ **时间胶囊**：写给未来的信
- 📸 **照片 / 相册**：图片上传（阿里云 OSS 存储）与展示
- 🗺️ **地图足迹**：高德地图标记去过的地方，自动保存足迹图片
- 😊 **心情 / 许愿**：心情打卡与愿望清单
- 🎵 **音乐 / 点歌台**：Meting 音乐服务接入，在线点歌
- 📦 **快递查询**：快递100 接口，包裹跟踪
- 🌤️ **天气**：实时天气信息
- 🤖 **AI 助手**：AI 对话、技能调用、长期记忆（用户记忆服务）
- 🍳 **菜谱**：集成 HowToCook 做菜食谱
- ✈️ **TripStar**：小红书旅行推荐搜索与行程规划

## 🛠️ 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Python 3.11 · FastAPI · Uvicorn |
| 数据库 | MySQL（PyMySQL） |
| 存储 | 阿里云 OSS（oss2） |
| 前端 | Vue 3 · Vite · Pinia · Vue Router |
| 部署 | GitHub Actions（SSH 自动部署） |

## 📂 项目结构

```
├── backend/                 # FastAPI 后端
│   ├── main.py              # 应用入口（/docs/api 查看接口文档）
│   ├── config.py            # 配置
│   ├── database.py          # 数据库初始化
│   ├── routers/             # 业务路由（auth/danmu/timeline/photos/map/ai...）
│   ├── services/            # 服务层（高德/快递100/OSS/AI Agent...）
│   └── tripstar/            # TripStar 旅行规划模块
├── frontend/                # Vue 3 前端
│   └── src/                 # 组件与页面
├── tests/                   # 后端测试
├── data/                    # 数据目录
├── docs/                    # 文档
└── .github/workflows/       # CI/CD 流水线（push master 自动部署）
```

## 🚀 快速开始

### 后端

```bash
cd backend
pip install -r ../requirements.txt
cp ../.env.example ../.env   # 配置环境变量
uvicorn main:app --reload    # 开发模式，接口文档: http://localhost:8000/docs/api
```

### 前端

```bash
cd frontend
npm install
npm run dev                  # 开发模式
npm run build                # 生产构建
```

### 测试

```bash
python -m pytest tests/
```

## 🚢 部署

推送到 `master` 分支后，GitHub Actions 流水线（`.github/workflows/deploy.yml`）会自动通过 SSH 部署到服务器。

## 📄 环境变量

参考 `.env.example`，主要配置项：

- 数据库连接（`DB_HOST` / `DB_USER` / `DB_PASSWORD` 等）
- 阿里云 OSS 凭证（`OSS_*`）
- 高德地图 Key（`AMAP_KEY`）
- 快递100 配置（`KUAIDI100_*`）
- AI 服务配置（模型 API Key 等）

> ⚠️ 请勿将 `.env` 提交到仓库（已在 `.gitignore` 中排除）
