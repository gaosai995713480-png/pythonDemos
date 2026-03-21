# 主题扩展实施计划

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为「心动告白」平台新增 5 个主题（森林、日落、薰衣草、焦糖、极光），其中森林和极光带独立特效组件。

**Architecture:** 在现有 CSS 变量驱动的主题系统上扩展，为 THEMES 数据结构新增 `effect` 字段以驱动特效组件切换。将 FloatingHearts 从视图层提升到 App.vue，与新增的 FallingLeaves、AuroraEffect 组件统一条件渲染。ThemeSwitcher 布局适配 9 个主题。

**Tech Stack:** Vue 3, Pinia, CSS animations, Vite, Vitest

**Spec:** `docs/superpowers/specs/2026-03-21-theme-expansion-design.md`

---

## 文件结构

| 文件 | 职责 |
|------|------|
| `frontend/src/stores/theme.js` | 主题数据定义（THEMES 数组）+ 主题切换逻辑 |
| `frontend/src/components/FallingLeaves.vue` | 森林主题树叶飘落特效（新增） |
| `frontend/src/components/AuroraEffect.vue` | 极光主题光带特效（新增） |
| `frontend/src/App.vue` | 根组件，统一管理特效组件的条件渲染 |
| `frontend/src/views/HomeView.vue` | 首页，移除 FloatingHearts 引用 |
| `frontend/src/views/LoginView.vue` | 登录页，移除 FloatingHearts 引用 |
| `frontend/src/components/ThemeSwitcher.vue` | 主题切换器，布局适配 9 个主题 |

---

## Chunk 1: 主题数据 + 特效组件

### Task 1: 更新 theme store，扩展主题数据

**Files:**
- Modify: `frontend/src/stores/theme.js:1-73`

- [ ] **Step 1: 为现有 4 个主题补充 `effect` 字段，追加 5 个新主题**

将 `frontend/src/stores/theme.js` 的 `THEMES` 数组替换为：

```js
const THEMES = [
  {
    name: '春樱', emoji: '🌸', effect: 'hearts',
    color: 'linear-gradient(135deg, #ee7752, #e73c7e)',
    vars: {
      '--primary': '#ff6b9d', '--secondary': '#c44569', '--accent': '#ffc048',
      '--bg-grad-1': '#ee7752', '--bg-grad-2': '#e73c7e',
      '--bg-grad-3': '#23a6d5', '--bg-grad-4': '#23d5ab',
    }
  },
  {
    name: '星空', emoji: '✨', effect: 'hearts',
    color: 'linear-gradient(135deg, #0f0c29, #302b63)',
    vars: {
      '--primary': '#a78bfa', '--secondary': '#7c3aed', '--accent': '#f9a8d4',
      '--bg-grad-1': '#0f0c29', '--bg-grad-2': '#302b63',
      '--bg-grad-3': '#24243e', '--bg-grad-4': '#0f0c29',
    }
  },
  {
    name: '海边', emoji: '🌊', effect: 'hearts',
    color: 'linear-gradient(135deg, #1cb5e0, #000851)',
    vars: {
      '--primary': '#38bdf8', '--secondary': '#0284c7', '--accent': '#fbbf24',
      '--bg-grad-1': '#1cb5e0', '--bg-grad-2': '#000851',
      '--bg-grad-3': '#0ea5e9', '--bg-grad-4': '#0369a1',
    }
  },
  {
    name: '雪夜', emoji: '❄️', effect: 'hearts',
    color: 'linear-gradient(135deg, #e6dada, #274046)',
    vars: {
      '--primary': '#94a3b8', '--secondary': '#475569', '--accent': '#e2e8f0',
      '--bg-grad-1': '#e6dada', '--bg-grad-2': '#274046',
      '--bg-grad-3': '#536976', '--bg-grad-4': '#292e49',
    }
  },
  {
    name: '森林', emoji: '🌿', effect: 'leaves',
    color: 'linear-gradient(135deg, #134e5e, #71b280)',
    vars: {
      '--primary': '#71b280', '--secondary': '#2d6a4f', '--accent': '#a7f3d0',
      '--bg-grad-1': '#134e5e', '--bg-grad-2': '#71b280',
      '--bg-grad-3': '#2d5016', '--bg-grad-4': '#1a472a',
    }
  },
  {
    name: '日落', emoji: '🌅', effect: 'hearts',
    color: 'linear-gradient(135deg, #f12711, #f5af19)',
    vars: {
      '--primary': '#f59e0b', '--secondary': '#dc2626', '--accent': '#fde68a',
      '--bg-grad-1': '#f12711', '--bg-grad-2': '#f5af19',
      '--bg-grad-3': '#c33764', '--bg-grad-4': '#1d2671',
    }
  },
  {
    name: '薰衣草', emoji: '💜', effect: 'hearts',
    color: 'linear-gradient(135deg, #c471f5, #fa71cd)',
    vars: {
      '--primary': '#c084fc', '--secondary': '#a855f7', '--accent': '#f0abfc',
      '--bg-grad-1': '#c471f5', '--bg-grad-2': '#fa71cd',
      '--bg-grad-3': '#e8b4f8', '--bg-grad-4': '#ad5389',
    }
  },
  {
    name: '焦糖', emoji: '🍂', effect: 'hearts',
    color: 'linear-gradient(135deg, #8b5e3c, #d4a574)',
    vars: {
      '--primary': '#d4a574', '--secondary': '#8b5e3c', '--accent': '#fbbf24',
      '--bg-grad-1': '#8b5e3c', '--bg-grad-2': '#d4a574',
      '--bg-grad-3': '#5c3317', '--bg-grad-4': '#a0522d',
    }
  },
  {
    name: '极光', emoji: '🌌', effect: 'aurora',
    color: 'linear-gradient(135deg, #0b3d0b, #1a0533)',
    vars: {
      '--primary': '#34d399', '--secondary': '#6366f1', '--accent': '#a78bfa',
      '--bg-grad-1': '#0b3d0b', '--bg-grad-2': '#1a0533',
      '--bg-grad-3': '#004d40', '--bg-grad-4': '#0d1b2a',
    }
  },
]
```

同时在 store 的 return 中导出一个 computed，方便 App.vue 获取当前 effect：

```js
const currentEffect = computed(() => {
  const theme = THEMES.find(t => t.name === currentName.value)
  return theme?.effect || 'hearts'
})

return { currentName, currentEffect, themes, init, applyTheme }
```

- [ ] **Step 2: 验证开发服务器无报错**

Run: `cd frontend && npm run dev`（手动在浏览器中确认主题切换器显示 9 个主题）

- [ ] **Step 3: 提交**

```bash
git add frontend/src/stores/theme.js
git commit -m "✨ feat(theme): 扩展THEMES数据，新增5个主题和effect字段"
```

---

### Task 2: 创建 FallingLeaves 组件

**Files:**
- Create: `frontend/src/components/FallingLeaves.vue`

- [ ] **Step 1: 创建 FallingLeaves.vue**

```vue
<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

defineProps({
  visible: { type: Boolean, default: true },
})

const leaves = ref([])
const LEAF_EMOJIS = ['🍃', '🌿', '🍀']
let timer = null

function spawnLeaf() {
  const id = Date.now() + Math.random()
  leaves.value.push({
    id,
    emoji: LEAF_EMOJIS[Math.floor(Math.random() * LEAF_EMOJIS.length)],
    left: Math.random() * 100,
    delay: 0,
    duration: Math.random() * 6 + 8,
    swayAmount: Math.random() * 60 + 30,
    size: Math.random() * 10 + 16,
  })
  setTimeout(() => {
    leaves.value = leaves.value.filter(l => l.id !== id)
  }, 16000)
}

onMounted(() => {
  // 初始批量生成，错开时间
  for (let i = 0; i < 8; i++) {
    setTimeout(spawnLeaf, i * 600)
  }
  timer = setInterval(spawnLeaf, 1800)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
  leaves.value = []
})
</script>

<template>
  <div v-if="visible" class="falling-layer">
    <span
      v-for="leaf in leaves"
      :key="leaf.id"
      class="leaf"
      :style="{
        left: leaf.left + '%',
        animationDuration: leaf.duration + 's',
        animationDelay: leaf.delay + 's',
        '--sway': leaf.swayAmount + 'px',
        fontSize: leaf.size + 'px',
      }"
    >{{ leaf.emoji }}</span>
  </div>
</template>

<style scoped>
.falling-layer {
  position: fixed;
  inset: 0;
  overflow: hidden;
  pointer-events: none;
  z-index: 1;
}

.leaf {
  position: absolute;
  top: -40px;
  animation: leaf-fall linear forwards;
  will-change: transform;
}

@keyframes leaf-fall {
  0% {
    transform: translateY(0) translateX(0) rotate(0deg);
    opacity: 0.9;
  }
  25% {
    transform: translateY(25vh) translateX(var(--sway)) rotate(90deg);
  }
  50% {
    transform: translateY(50vh) translateX(calc(var(--sway) * -0.5)) rotate(180deg);
  }
  75% {
    transform: translateY(75vh) translateX(var(--sway)) rotate(270deg);
    opacity: 0.7;
  }
  100% {
    transform: translateY(110vh) translateX(0) rotate(360deg);
    opacity: 0;
  }
}

@media (prefers-reduced-motion: reduce) {
  .leaf { animation: none; opacity: 0.5; top: 50%; }
}
</style>
```

- [ ] **Step 2: 提交**

```bash
git add frontend/src/components/FallingLeaves.vue
git commit -m "✨ feat(theme): 新增FallingLeaves树叶飘落特效组件"
```

---

### Task 3: 创建 AuroraEffect 组件

**Files:**
- Create: `frontend/src/components/AuroraEffect.vue`

- [ ] **Step 1: 创建 AuroraEffect.vue**

```vue
<template>
  <div class="aurora-layer">
    <div class="aurora-band band-1"></div>
    <div class="aurora-band band-2"></div>
    <div class="aurora-band band-3"></div>
  </div>
</template>

<style scoped>
.aurora-layer {
  position: fixed;
  inset: 0;
  overflow: hidden;
  pointer-events: none;
  z-index: 1;
}

.aurora-band {
  position: absolute;
  width: 200%;
  height: 40%;
  border-radius: 50%;
  filter: blur(80px);
  opacity: 0.3;
  will-change: transform, opacity;
}

.band-1 {
  top: -10%;
  left: -50%;
  background: linear-gradient(90deg, transparent, rgba(52, 211, 153, 0.4), rgba(99, 102, 241, 0.3), transparent);
  animation: aurora-drift-1 12s ease-in-out infinite alternate;
}

.band-2 {
  top: 10%;
  left: -30%;
  background: linear-gradient(90deg, transparent, rgba(167, 139, 250, 0.35), rgba(52, 211, 153, 0.25), transparent);
  animation: aurora-drift-2 16s ease-in-out infinite alternate;
}

.band-3 {
  top: -5%;
  left: -40%;
  background: linear-gradient(90deg, transparent, rgba(99, 102, 241, 0.3), rgba(167, 139, 250, 0.2), transparent);
  animation: aurora-drift-3 20s ease-in-out infinite alternate;
}

@keyframes aurora-drift-1 {
  0% { transform: translateX(0) translateY(0) rotate(-5deg); opacity: 0.25; }
  100% { transform: translateX(25%) translateY(10%) rotate(5deg); opacity: 0.4; }
}

@keyframes aurora-drift-2 {
  0% { transform: translateX(0) translateY(0) rotate(3deg); opacity: 0.2; }
  100% { transform: translateX(-20%) translateY(-5%) rotate(-3deg); opacity: 0.35; }
}

@keyframes aurora-drift-3 {
  0% { transform: translateX(10%) translateY(5%) rotate(-2deg); opacity: 0.15; }
  100% { transform: translateX(-15%) translateY(-8%) rotate(4deg); opacity: 0.3; }
}

@media (prefers-reduced-motion: reduce) {
  .aurora-band { animation: none; }
}
</style>
```

- [ ] **Step 2: 提交**

```bash
git add frontend/src/components/AuroraEffect.vue
git commit -m "✨ feat(theme): 新增AuroraEffect极光光带特效组件"
```

---

## Chunk 2: 组件整合 + 布局适配

### Task 4: 提升特效到 App.vue，从视图中移除 FloatingHearts

**Files:**
- Modify: `frontend/src/App.vue:1-9`
- Modify: `frontend/src/views/HomeView.vue:7,48`
- Modify: `frontend/src/views/LoginView.vue:5,36`

- [ ] **Step 1: 修改 App.vue，引入三个特效组件并条件渲染**

将 `App.vue` 替换为：

```vue
<template>
  <FloatingHearts v-if="currentEffect === 'hearts'" />
  <FallingLeaves v-if="currentEffect === 'leaves'" />
  <AuroraEffect v-if="currentEffect === 'aurora'" />
  <AppToast />
  <router-view />
</template>

<script setup>
import { computed } from 'vue'
import { useThemeStore } from './stores/theme'
import AppToast from './components/AppToast.vue'
import FloatingHearts from './components/FloatingHearts.vue'
import FallingLeaves from './components/FallingLeaves.vue'
import AuroraEffect from './components/AuroraEffect.vue'

const themeStore = useThemeStore()
const currentEffect = computed(() => themeStore.currentEffect)
</script>
```

- [ ] **Step 2: 从 HomeView.vue 中移除 FloatingHearts**

在 `frontend/src/views/HomeView.vue` 中：
- 删除第 7 行：`import FloatingHearts from '../components/FloatingHearts.vue'`
- 删除第 48 行：`<FloatingHearts />`

- [ ] **Step 3: 从 LoginView.vue 中移除 FloatingHearts**

在 `frontend/src/views/LoginView.vue` 中：
- 删除第 5 行：`import FloatingHearts from '../components/FloatingHearts.vue'`
- 删除第 36 行：`<FloatingHearts />`

- [ ] **Step 4: 验证开发服务器无报错**

Run: `cd frontend && npm run dev`（手动确认切换主题时特效正确切换）

- [ ] **Step 5: 提交**

```bash
git add frontend/src/App.vue frontend/src/views/HomeView.vue frontend/src/views/LoginView.vue
git commit -m "♻️ refactor(theme): 将特效组件统一提升到App.vue条件渲染"
```

---

### Task 5: ThemeSwitcher 布局适配

**Files:**
- Modify: `frontend/src/components/ThemeSwitcher.vue:68-84`

- [ ] **Step 1: 修改下拉面板样式**

在 `ThemeSwitcher.vue` 的 `.ts-dropdown` 样式中增加 `flex-wrap: wrap` 和 `max-width`：

```css
.ts-dropdown {
  position: absolute;
  top: calc(100% + 8px);
  right: 0;
  background: rgba(20, 20, 30, 0.92);
  backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.15);
  border-radius: 14px;
  padding: 10px;
  display: flex;
  flex-wrap: wrap;
  max-width: 220px;
  gap: 8px;
  opacity: 0;
  pointer-events: none;
  transform: translateY(-6px);
  transition: all 0.2s ease;
  z-index: 50;
}
```

`max-width: 220px` 可以容纳每行 4 个色块（4×36px + 3×8px = 168px + padding），9 个主题分 3 行显示。

- [ ] **Step 2: 验证**

Run: `cd frontend && npm run dev`（手动确认下拉面板在桌面端和移动端视口宽度下显示正常）

- [ ] **Step 3: 提交**

```bash
git add frontend/src/components/ThemeSwitcher.vue
git commit -m "💄 style(theme): ThemeSwitcher下拉面板适配9个主题换行布局"
```

---

### Task 6: 最终验证

- [ ] **Step 1: 运行前端测试**

Run: `cd frontend && npm run test:run`

确认所有现有测试通过，无回归。

- [ ] **Step 2: 全功能手动验证**

在浏览器中逐一切换 9 个主题，确认：
- 背景渐变正确变化
- 主题色块在切换器中正确显示
- 春樱/星空/海边/雪夜/日落/薰衣草/焦糖 → 爱心飘浮
- 森林 → 树叶飘落
- 极光 → 光带漂移
- 刷新页面后主题持久化正确
- 登录页和首页都有特效显示

- [ ] **Step 3: 提交**

如果有任何修复，提交修复。否则此步骤跳过。