# 主题扩展设计文档

## 概述

为「心动告白」平台新增 5 个主题（森林、日落、薰衣草、焦糖、极光），其中森林和极光主题附带独立视觉特效组件。

## 现有主题系统

当前有 4 个主题：春樱、星空、海边、雪夜。通过 Pinia store (`theme.js`) 管理，切换时修改 7 个 CSS 变量（`--primary`、`--secondary`、`--accent`、`--bg-grad-1~4`），所有 UI 组件通过这些变量取色。`ThemeSwitcher.vue` 动态遍历主题数组，新主题自动出现在选择器中。

现有 `FloatingHearts.vue` 分别在 `HomeView.vue` 和 `LoginView.vue` 中引入。本次改造将其统一提升到 `App.vue`，与新特效组件一起根据主题条件渲染。

## 主题数据结构

在 THEMES 对象中新增 `effect` 字段，用于在 `App.vue` 中决定渲染哪个特效组件：

```js
{ name, emoji, color, effect, vars }
```

- `effect: 'hearts'` — FloatingHearts（默认）
- `effect: 'leaves'` — FallingLeaves
- `effect: 'aurora'` — AuroraEffect

现有 4 个主题补充 `effect: 'hearts'`。

## 新增主题配色

| 主题 | emoji | color | effect | primary | secondary | accent | bg-grad-1 | bg-grad-2 | bg-grad-3 | bg-grad-4 |
|------|-------|-------|--------|---------|-----------|--------|-----------|-----------|-----------|-----------|
| 森林 | 🌿 | `linear-gradient(135deg, #134e5e, #71b280)` | leaves | #71b280 | #2d6a4f | #a7f3d0 | #134e5e | #71b280 | #2d5016 | #1a472a |
| 日落 | 🌅 | `linear-gradient(135deg, #f12711, #f5af19)` | hearts | #f59e0b | #dc2626 | #fde68a | #f12711 | #f5af19 | #c33764 | #1d2671 |
| 薰衣草 | 💜 | `linear-gradient(135deg, #c471f5, #fa71cd)` | hearts | #c084fc | #a855f7 | #f0abfc | #c471f5 | #fa71cd | #e8b4f8 | #ad5389 |
| 焦糖 | 🍂 | `linear-gradient(135deg, #8b5e3c, #d4a574)` | hearts | #d4a574 | #8b5e3c | #fbbf24 | #8b5e3c | #d4a574 | #5c3317 | #a0522d |
| 极光 | 🌌 | `linear-gradient(135deg, #0b3d0b, #1a0533)` | aurora | #34d399 | #6366f1 | #a78bfa | #0b3d0b | #1a0533 | #004d40 | #0d1b2a |

## 特效组件

### AuroraEffect.vue（极光主题专属）

- 纯 CSS 实现，2-3 条半透明渐变光带
- `@keyframes` 做缓慢水平漂移 + 透明度变化
- `position: fixed; inset: 0; z-index: 1; pointer-events: none`
- 颜色使用绿/紫/蓝半透明渐变
- 纯 CSS transform + opacity 动画，GPU 加速
- `prefers-reduced-motion: reduce` 时禁用动画

### FallingLeaves.vue（森林主题专属）

- CSS 动画，10-15 个 emoji 叶子（🍃🌿🍀）
- 随机位置和延迟，从上往下飘落 + 左右摇摆
- `position: fixed; inset: 0; z-index: 1; pointer-events: none`
- 纯 CSS 实现，元素数量少
- 支持 `visible` prop，与 FloatingHearts 一致
- `prefers-reduced-motion: reduce` 时禁用动画

### 特效切换逻辑

在 `App.vue` 中读取当前主题的 `effect` 字段，用 `v-if` 条件渲染：

- `effect === 'hearts'` → `<FloatingHearts />`
- `effect === 'leaves'` → `<FallingLeaves />`
- `effect === 'aurora'` → `<AuroraEffect />`

切换主题时 Vue 的 `v-if` 会自动卸载旧组件、挂载新组件，各组件在 `onUnmounted` 中清理定时器和动态 DOM 元素。

### ThemeSwitcher 布局适配

9 个主题色块在移动端可能溢出，下拉面板增加 `flex-wrap: wrap` 和合理的 `max-width`，确保在窄屏幕上自动换行。

## 文件改动

| 文件 | 操作 | 说明 |
|------|------|------|
| `frontend/src/stores/theme.js` | 修改 | THEMES 数组：现有 4 个主题补充 `effect` 和 `color` 字段，追加 5 个新主题 |
| `frontend/src/components/AuroraEffect.vue` | 新增 | 极光光带特效组件 |
| `frontend/src/components/FallingLeaves.vue` | 新增 | 树叶飘落特效组件 |
| `frontend/src/App.vue` | 修改 | 引入三个特效组件，根据 `effect` 字段条件渲染 |
| `frontend/src/views/HomeView.vue` | 修改 | 移除 FloatingHearts 引用（已提升到 App.vue） |
| `frontend/src/views/LoginView.vue` | 修改 | 移除 FloatingHearts 引用（已提升到 App.vue） |
| `frontend/src/components/ThemeSwitcher.vue` | 修改 | 下拉面板增加 `flex-wrap: wrap` 适配 9 个主题 |

### 不改动的文件

- `variables.css` — CSS 变量默认值保持春樱
- 其他视图文件 — 通过 CSS 变量取色，无需改动