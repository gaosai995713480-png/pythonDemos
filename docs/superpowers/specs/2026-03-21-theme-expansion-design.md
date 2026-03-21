# 主题扩展设计文档

## 概述

为「心动告白」平台新增 5 个主题（森林、日落、薰衣草、焦糖、极光），其中森林和极光主题附带独立视觉特效组件。

## 现有主题系统

当前有 4 个主题：春樱、星空、海边、雪夜。通过 Pinia store (`theme.js`) 管理，切换时修改 7 个 CSS 变量（`--primary`、`--secondary`、`--accent`、`--bg-grad-1~4`），所有 UI 组件通过这些变量取色。`ThemeSwitcher.vue` 动态遍历主题数组，新主题自动出现在选择器中。

## 新增主题配色

| 主题 | emoji | primary | secondary | accent | bg-grad-1 | bg-grad-2 | bg-grad-3 | bg-grad-4 |
|------|-------|---------|-----------|--------|-----------|-----------|-----------|-----------|
| 森林 | 🌿 | #71b280 | #2d6a4f | #a7f3d0 | #134e5e | #71b280 | #2d5016 | #1a472a |
| 日落 | 🌅 | #f59e0b | #dc2626 | #fde68a | #f12711 | #f5af19 | #c33764 | #1d2671 |
| 薰衣草 | 💜 | #c084fc | #a855f7 | #f0abfc | #c471f5 | #fa71cd | #e8b4f8 | #ad5389 |
| 焦糖 | 🍂 | #d4a574 | #8b5e3c | #fbbf24 | #8B5E3C | #D4A574 | #5C3317 | #A0522D |
| 极光 | 🌌 | #34d399 | #6366f1 | #a78bfa | #0b3d0b | #1a0533 | #004d40 | #0d1b2a |

## 特效组件

### AuroraEffect.vue（极光主题专属）

- 纯 CSS 实现，2-3 条半透明渐变光带
- `@keyframes` 做缓慢水平漂移 + 透明度变化
- `position: fixed; inset: 0; z-index: 1; pointer-events: none`
- 颜色使用绿/紫/蓝半透明渐变
- 纯 CSS transform + opacity 动画，GPU 加速

### FallingLeaves.vue（森林主题专属）

- CSS 动画，10-15 个 emoji 叶子（🍃🌿🍀）
- 随机位置和延迟，从上往下飘落 + 左右摇摆
- `position: fixed; inset: 0; z-index: 1; pointer-events: none`
- 纯 CSS 实现，元素数量少

### 特效切换逻辑

在 `App.vue` 中根据 `themeStore.currentName` 条件渲染：

- FloatingHearts → 春樱、星空、海边、雪夜、日落、薰衣草、焦糖（默认）
- FallingLeaves → 森林
- AuroraEffect → 极光

## 文件改动

| 文件 | 操作 | 说明 |
|------|------|------|
| `frontend/src/stores/theme.js` | 修改 | THEMES 数组追加 5 个主题对象 |
| `frontend/src/components/AuroraEffect.vue` | 新增 | 极光光带特效组件 |
| `frontend/src/components/FallingLeaves.vue` | 新增 | 树叶飘落特效组件 |
| `frontend/src/App.vue` | 修改 | 引入特效组件，根据主题条件渲染 |

### 不改动的文件

- `ThemeSwitcher.vue` — 已动态遍历 themes 数组
- `variables.css` — CSS 变量默认值保持春樱
- 各视图文件 — 通过 CSS 变量取色，无需改动