<script setup>
/**
 * 弹幕栏组件 — 从 HomeView 拆出
 * 完全自治：管理弹幕数据、DOM 操作、定时器
 */
import { ref, onMounted, onUnmounted } from 'vue'
import { danmuApi } from '../api'
import { useToast } from '../composables/useToast'

const { error: toastError } = useToast()

const danmuInput = ref('')
const danmuList = ref([])
const MAX_LEN = 50
const settingsOpen = ref(false)
const danmuEnabled = ref(true)
const danmuPanelOpen = ref(false)
const danmuSpeed = ref(12)
const danmuDensity = ref(8)
let danmuMainTimer = null
let danmuIndex = 0

async function loadDanmu() {
  try { danmuList.value = await danmuApi.list(50) } catch { /* API layer handles toast */ }
}

async function handleLike(item, likeEl) {
  if (item._liked) return
  try {
    const res = await danmuApi.like(item.id)
    const found = danmuList.value.find(d => d.id === item.id)
    if (found) {
      found.likes = res.likes
      if (res.liked === false) found._liked = true
    }
    item.likes = res.likes
    if (res.liked === false) item._liked = true
    if (likeEl) {
      likeEl.textContent = `❤️ ${res.likes}`
      likeEl.classList.add('is-pop')
      if (res.liked) likeEl.classList.add('is-liked')
      setTimeout(() => likeEl.classList.remove('is-pop'), 400)
    }
  } catch { /* API layer handles toast */ }
}

async function handlePanelLike(item, event) {
  const btn = event.currentTarget
  await handleLike(item, btn)
}

function spawnDanmu(item, fresh = false) {
  const layer = document.getElementById('danmu-layer')
  if (!layer) return
  const el = document.createElement('div')
  el.className = 'danmu-item' + (fresh ? ' is-fresh' : '')
  const isEmoji = /^[\p{Emoji}\s]+$/u.test(item.text)
  if (isEmoji) el.classList.add('is-emoji')
  el.style.top = (Math.random() * 70 + 5) + '%'
  el.style.setProperty('--duration', danmuSpeed.value + 's')
  el.innerHTML = `<span>${item.text}</span><span class="danmu-like" data-id="${item.id}">❤️ ${item.likes || 0}</span>`
  el.querySelector('.danmu-like').addEventListener('click', async (ev) => {
    ev.stopPropagation()
    const likeEl = el.querySelector('.danmu-like')
    await handleLike(item, likeEl)
  })
  el.addEventListener('touchstart', () => {
    el.style.animationPlayState = 'paused'
  }, { passive: true })
  el.addEventListener('touchend', () => {
    el.style.animationPlayState = ''
  }, { passive: true })
  layer.appendChild(el)
  // 弹幕飘完后自动回收 DOM，无需全局清空
  setTimeout(() => el.remove(), danmuSpeed.value * 1000 + 500)
}

/** 启动连续流式弹幕引擎 */
function startStream() {
  stopStream()
  if (!danmuEnabled.value) return
  if (!danmuList.value.length) return
  // 每隔 (speed / density) 秒发射一条，形成均匀的弹幕流
  const intervalMs = (danmuSpeed.value / danmuDensity.value) * 1000
  danmuMainTimer = setInterval(() => {
    if (!danmuList.value.length || !danmuEnabled.value) return
    const item = danmuList.value[danmuIndex % danmuList.value.length]
    danmuIndex++
    spawnDanmu(item)
  }, intervalMs)
}

function stopStream() {
  if (danmuMainTimer) {
    clearInterval(danmuMainTimer)
    danmuMainTimer = null
  }
}

function toggleDanmu(val) {
  danmuEnabled.value = val
  if (val) {
    startStream()
  } else {
    stopStream()
    const layer = document.getElementById('danmu-layer')
    if (layer) layer.innerHTML = ''
  }
}

async function sendDanmu() {
  const text = danmuInput.value.trim()
  if (!text) return
  try {
    const res = await danmuApi.send(text)
    danmuInput.value = ''
    if (res.ok) spawnDanmu({ text, id: res.id, likes: 0 }, true)
    loadDanmu()
  } catch { /* API layer handles toast */ }
}

function cleanup() {
  stopStream()
  const layer = document.getElementById('danmu-layer')
  if (layer) layer.innerHTML = ''
}

defineExpose({ cleanup })

onMounted(async () => {
  await loadDanmu()
  startStream()
})

onUnmounted(() => {
  cleanup()
})
</script>

<template>
  <div id="danmu-layer" class="danmu-layer"></div>

  <!-- 弹幕列表面板 -->
  <div class="danmu-panel" :class="{ 'is-open': danmuPanelOpen }">
    <div class="danmu-panel-header">
      <h3>💬 弹幕列表</h3>
      <button class="danmu-panel-close" @click="danmuPanelOpen = false">✕</button>
    </div>
    <div class="danmu-panel-body">
      <div v-if="!danmuList.length" class="danmu-panel-empty">还没有弹幕哦~</div>
      <div v-for="item in danmuList" :key="item.id" class="danmu-panel-item">
        <span class="danmu-panel-text">{{ item.text }}</span>
        <button
          class="danmu-panel-like"
          :class="{ 'is-liked': item._liked }"
          @click="handlePanelLike(item, $event)"
        >
          ❤️ {{ item.likes || 0 }}
        </button>
      </div>
    </div>
  </div>

  <!-- 弹幕输入栏 -->
  <div class="danmu-bar">
    <button class="danmu-settings-toggle" @click="settingsOpen = !settingsOpen" title="弹幕设置">⚙️</button>
    <button class="danmu-settings-toggle" @click="danmuPanelOpen = !danmuPanelOpen" title="弹幕列表">📋</button>
    <input
      v-model="danmuInput"
      :maxlength="MAX_LEN"
      placeholder="说点什么..."
      @keydown.enter="sendDanmu"
    />
    <small class="danmu-counter">{{ danmuInput.length }}/{{ MAX_LEN }}</small>
    <button @click="sendDanmu">发射 💕</button>
  </div>

  <!-- 弹幕设置面板 -->
  <div class="danmu-settings" :class="{ 'is-visible': settingsOpen }">
    <h3>弹幕设置</h3>
    <div class="danmu-settings-row">
      <span>开关</span>
      <label class="danmu-switch">
        <input type="checkbox" :checked="danmuEnabled" @change="toggleDanmu($event.target.checked)" />
        <span class="danmu-switch-slider"></span>
      </label>
      <output>{{ danmuEnabled ? '开' : '关' }}</output>
    </div>
    <div class="danmu-settings-row">
      <span>速度</span>
      <input type="range" v-model.number="danmuSpeed" min="6" max="24" />
      <output>{{ danmuSpeed }}s</output>
    </div>
    <div class="danmu-settings-row">
      <span>密度</span>
      <input type="range" v-model.number="danmuDensity" min="2" max="15" />
      <output>{{ danmuDensity }}条</output>
    </div>
  </div>
</template>

<style scoped>
/* Danmu Layer */
:deep(.danmu-layer) {
  position: fixed; inset: 0; pointer-events: none; overflow: hidden; z-index: 3;
}

:deep(.danmu-item) {
  position: fixed; left: calc(100vw + 20px); top: 0;
  padding: 10px 18px; border-radius: 16px;
  background: var(--glass-bg); backdrop-filter: blur(20px);
  border: 1px solid var(--glass-border); color: var(--text-primary);
  font-size: 15px; white-space: nowrap;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
  animation: danmu-move var(--duration, 12s) linear forwards;
  display: inline-flex; align-items: center; gap: 10px;
  pointer-events: auto; cursor: pointer;
}

:deep(.danmu-item:hover) {
  animation-play-state: paused;
  filter: brightness(1.2);
  transform: scale(1.05);
  z-index: 10;
  box-shadow: 0 0 20px rgba(255, 107, 157, 0.4), 0 4px 16px rgba(0, 0, 0, 0.3);
}
:deep(.danmu-item.is-emoji) { font-size: 16px; letter-spacing: 1px; }
:deep(.danmu-item.is-fresh) {
  background: linear-gradient(135deg, rgba(255, 107, 157, 0.2), rgba(196, 69, 105, 0.2));
  border-color: rgba(255, 107, 157, 0.4);
  box-shadow: 0 0 20px rgba(255, 107, 157, 0.5), 0 4px 16px rgba(0, 0, 0, 0.3);
}

:deep(.danmu-like) {
  font-size: 13px; color: var(--text-primary); opacity: 0.9; transition: all 0.3s;
  padding: 4px 8px; border-radius: 8px; cursor: pointer; user-select: none;
}
:deep(.danmu-like:hover) { background: rgba(255, 107, 157, 0.2); color: var(--accent); }
:deep(.danmu-like.is-pop) { transform: scale(1.3); color: var(--accent); }
:deep(.danmu-like.is-liked) { color: var(--accent); }

@keyframes danmu-move {
  0% { transform: translateX(0); opacity: 0; }
  3% { opacity: 1; }
  95% { opacity: 1; }
  100% { transform: translateX(calc(-100vw - 100% - 40px)); opacity: 0; }
}

/* Danmu Bar */
.danmu-bar {
  position: fixed; left: 32px; right: 120px; bottom: 32px; z-index: 4;
  display: flex; align-items: center; gap: 12px; padding: 14px 18px;
  border-radius: 20px; background: var(--glass-bg); backdrop-filter: blur(30px);
  border: 1px solid var(--glass-border); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
}

.danmu-bar input {
  flex: 1; border: none; background: transparent;
  font-size: 15px; color: var(--text-primary); outline: none;
}
.danmu-bar input::placeholder { color: var(--text-secondary); }
.danmu-counter { font-size: 12px; color: var(--text-secondary); white-space: nowrap; }
.danmu-bar button:last-child {
  border: none; padding: 8px 20px; border-radius: 12px;
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  color: #fff; font-weight: 500; cursor: pointer;
  box-shadow: 0 4px 12px rgba(255, 107, 157, 0.3); transition: all 0.2s;
}
.danmu-bar button:last-child:hover { transform: translateY(-2px); }

.danmu-settings-toggle {
  width: 40px; height: 40px; padding: 0; border-radius: 12px;
  font-size: 18px; display: flex; align-items: center; justify-content: center;
  border: none; background: transparent; color: #fff; cursor: pointer;
  transition: all 0.2s;
}
.danmu-settings-toggle:hover { background: rgba(255, 255, 255, 0.1); }

/* Settings panel */
.danmu-settings {
  position: fixed; left: 32px; bottom: 100px; z-index: 4;
  width: min(320px, 86vw); padding: 20px; border-radius: 20px;
  background: var(--glass-bg); backdrop-filter: blur(30px);
  border: 1px solid var(--glass-border);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
  opacity: 0; pointer-events: none; transform: translateY(10px);
  transition: all 0.3s;
}
.danmu-settings.is-visible { opacity: 1; pointer-events: auto; transform: translateY(0); }
.danmu-settings h3 { margin: 0 0 16px; font-size: 16px; font-weight: 600; }
.danmu-settings-row { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; font-size: 14px; }
.danmu-settings-row span { width: 60px; opacity: 0.85; font-weight: 500; }
.danmu-settings-row output { min-width: 52px; text-align: right; font-size: 13px; color: var(--text-secondary); }
.danmu-settings-row input[type="range"] {
  flex: 1; height: 6px; border-radius: 3px;
  background: rgba(255, 255, 255, 0.15); outline: none; appearance: none; -webkit-appearance: none;
}
.danmu-settings-row input[type="range"]::-webkit-slider-thumb {
  -webkit-appearance: none; width: 16px; height: 16px; border-radius: 50%;
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  box-shadow: 0 2px 6px rgba(255, 107, 157, 0.4); cursor: pointer;
}

/* Toggle Switch */
.danmu-switch {
  position: relative; display: inline-block; width: 44px; height: 24px; flex-shrink: 0;
}
.danmu-switch input { opacity: 0; width: 0; height: 0; }
.danmu-switch-slider {
  position: absolute; inset: 0; cursor: pointer; border-radius: 24px;
  background: rgba(255, 255, 255, 0.12); transition: all 0.3s;
}
.danmu-switch-slider::before {
  content: ''; position: absolute; left: 3px; top: 3px;
  width: 18px; height: 18px; border-radius: 50%;
  background: rgba(255, 255, 255, 0.6); transition: all 0.3s;
}
.danmu-switch input:checked + .danmu-switch-slider {
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  box-shadow: 0 0 10px rgba(255, 107, 157, 0.4);
}
.danmu-switch input:checked + .danmu-switch-slider::before {
  transform: translateX(20px); background: #fff;
}

/* Danmu Panel */
.danmu-panel {
  position: fixed; left: 32px; right: 120px; bottom: 90px;
  max-height: 50vh; z-index: 5; border-radius: 20px;
  background: var(--glass-bg); backdrop-filter: blur(30px);
  border: 1px solid var(--glass-border);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
  opacity: 0; pointer-events: none; transform: translateY(20px);
  transition: all 0.3s ease; display: flex; flex-direction: column; overflow: hidden;
}
.danmu-panel.is-open { opacity: 1; pointer-events: auto; transform: translateY(0); }
.danmu-panel-header {
  display: flex; justify-content: space-between; align-items: center;
  padding: 16px 20px 12px; border-bottom: 1px solid var(--glass-border);
}
.danmu-panel-header h3 { margin: 0; font-size: 16px; font-weight: 600; }
.danmu-panel-close {
  background: none; border: none; color: var(--text-secondary);
  font-size: 16px; cursor: pointer; padding: 4px 8px; border-radius: 8px;
  transition: all 0.2s;
}
.danmu-panel-close:hover { background: rgba(255, 255, 255, 0.1); color: var(--text-primary); }
.danmu-panel-body { overflow-y: auto; padding: 12px 20px; flex: 1; }
.danmu-panel-empty { text-align: center; color: var(--text-secondary); padding: 24px; font-size: 14px; }
.danmu-panel-item {
  display: flex; justify-content: space-between; align-items: center;
  padding: 10px 12px; border-radius: 12px; transition: background 0.2s; gap: 12px;
}
.danmu-panel-item:hover { background: rgba(255, 255, 255, 0.05); }
.danmu-panel-text {
  flex: 1; font-size: 14px; color: var(--text-primary);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.danmu-panel-like {
  background: none; border: 1px solid transparent; color: var(--text-secondary);
  font-size: 13px; cursor: pointer; padding: 6px 12px; border-radius: 10px;
  transition: all 0.2s; white-space: nowrap; flex-shrink: 0;
}
.danmu-panel-like:hover {
  background: rgba(255, 107, 157, 0.15);
  border-color: rgba(255, 107, 157, 0.3); color: var(--accent);
}
.danmu-panel-like.is-liked { color: var(--accent); }

@media (max-width: 720px) {
  .danmu-bar {
    left: 12px;
    right: 80px;
    bottom: 16px;
    padding: 10px 12px;
    gap: 8px;
  }

  .danmu-bar input {
    font-size: 14px;
  }

  .danmu-counter {
    display: none;
  }

  .danmu-bar button:last-child {
    padding: 6px 14px;
    font-size: 13px;
  }

  .danmu-settings-toggle {
    width: 34px;
    height: 34px;
    font-size: 16px;
  }

  .danmu-settings {
    left: 12px;
    width: calc(100vw - 24px);
    bottom: 84px;
  }

  .danmu-panel {
    left: 8px;
    right: 8px;
    bottom: 80px;
    max-height: 45vh;
    border-radius: 16px;
  }

  .danmu-panel-header {
    padding: 12px 16px 10px;
  }

  .danmu-panel-body {
    padding: 8px 12px;
  }

  .danmu-panel-item {
    padding: 8px 10px;
  }
}
</style>
