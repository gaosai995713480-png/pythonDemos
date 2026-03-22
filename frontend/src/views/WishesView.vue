<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import TopBar from '../components/TopBar.vue'
import { wishApi } from '../api'

const router = useRouter()
const wishes = ref([])
const modalVisible = ref(false)
const modalPos = ref({ left: '0', top: '0' })
const wishInput = ref('')
let pendingPos = null

function createBackgroundStars() {
  const sky = document.getElementById('sky')
  if (!sky) return
  for (let i = 0; i < 200; i++) {
    const s = document.createElement('div')
    s.className = 'bg-star'
    s.style.left = Math.random() * 100 + '%'
    s.style.top = Math.random() * 100 + '%'
    s.style.setProperty('--dur', (1.5 + Math.random() * 3) + 's')
    s.style.animationDelay = (Math.random() * 3) + 's'
    sky.appendChild(s)
  }
}

function spawnShootingStar() {
  const el = document.createElement('div')
  el.className = 'shooting-star'
  el.style.left = (Math.random() * 60 + 10) + '%'
  el.style.top = (Math.random() * 40 + 5) + '%'
  document.body.appendChild(el)
  setTimeout(() => el.remove(), 1400)
}

function onSkyClick(e) {
  if (e.target.closest('.star') || e.target.closest('.top-bar')) return
  pendingPos = {
    x: e.clientX / window.innerWidth,
    y: e.clientY / window.innerHeight,
  }
  const isMobile = window.innerWidth <= 720
  if (isMobile) {
    modalPos.value = { left: '16px', right: '16px', bottom: '20px', top: 'auto' }
  } else {
    modalPos.value = {
      left: Math.min(e.clientX, window.innerWidth - 240) + 'px',
      top: Math.min(e.clientY + 20, window.innerHeight - 100) + 'px',
    }
  }
  modalVisible.value = true
  wishInput.value = ''
}

async function submitWish() {
  const content = wishInput.value.trim()
  if (!content || !pendingPos) return
  const colors = ['#ffd700', '#ff6b9d', '#a78bfa', '#60a5fa', '#34d399', '#f472b6']
  const color = colors[Math.floor(Math.random() * colors.length)]
  try {
    const data = await wishApi.create({ content, x: pendingPos.x, y: pendingPos.y, color })
    if (data.ok) {
      wishes.value.push({ id: data.id, content, x: pendingPos.x, y: pendingPos.y, color })
    }
  } catch { /* ignore */ }
  modalVisible.value = false
  pendingPos = null
}

function onInputKeydown(e) {
  if (e.key === 'Enter') submitWish()
  if (e.key === 'Escape') modalVisible.value = false
}

async function loadWishes() {
  try {
    wishes.value = await wishApi.list()
  } catch { /* ignore */ }
}

let shootingStarTimer = null

onMounted(() => {
  loadWishes()
  createBackgroundStars()
  spawnShootingStar()
  shootingStarTimer = setInterval(spawnShootingStar, 5000 + Math.random() * 8000)
})

onUnmounted(() => {
  if (shootingStarTimer) clearInterval(shootingStarTimer)
})
</script>

<template>
  <TopBar title="⭐ 星空许愿" @back="router.push('/')">
    <span class="count">{{ wishes.length }} 颗星</span>
  </TopBar>

  <div class="sky" id="sky" @click="onSkyClick">
    <div
      v-for="w in wishes"
      :key="w.id"
      class="star"
      :style="{ left: (w.x * 100) + '%', top: (w.y * 100) + '%' }"
    >
      <div class="star-dot" :style="{ color: w.color, background: w.color }"></div>
      <div class="star-text">{{ w.content }}</div>
    </div>
  </div>

  <div class="hint">✨ 点击星空，许一个心愿</div>

  <div
    class="wish-modal"
    :class="{ 'is-visible': modalVisible }"
    :style="modalPos"
  >
    <input
      v-model="wishInput"
      type="text"
      placeholder="写下你的心愿..."
      maxlength="50"
      @keydown="onInputKeydown"
    />
    <button @click="submitWish">许愿 ⭐</button>
  </div>
</template>

<style scoped>
.count { margin-left: auto; font-size: 13px; color: rgba(255, 255, 255, 0.5); }

/* Override body for this page */
:deep(body) { overflow: hidden; }

.sky { position: fixed; inset: 0; z-index: 1; cursor: crosshair;
  background: radial-gradient(ellipse at 20% 50%, #0d1b2a 0%, #0a0e1a 50%, #020408 100%);
}

.hint {
  position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
  font-size: 13px; color: rgba(255, 255, 255, 0.35); z-index: 5;
  pointer-events: none; animation: pulse 3s ease-in-out infinite;
}

.star {
  position: absolute; z-index: 2; text-align: center; cursor: default;
  transform: translate(-50%, -50%);
}

.star-dot {
  width: 6px; height: 6px; border-radius: 50%;
  animation: twinkle 2s ease-in-out infinite alternate;
  box-shadow: 0 0 8px 2px currentColor; margin: 0 auto 4px;
}

.star-text {
  font-size: 11px; color: rgba(255, 255, 255, 0.7);
  max-width: 120px; word-break: break-all;
  opacity: 0; transition: opacity 0.3s;
  text-shadow: 0 0 8px rgba(255, 255, 255, 0.3);
}

.star:hover .star-text { opacity: 1; }

:deep(.bg-star) {
  position: absolute; width: 2px; height: 2px; border-radius: 50%;
  background: rgba(255, 255, 255, 0.5);
  animation: twinkle-bg var(--dur) ease-in-out infinite alternate;
}

@keyframes twinkle-bg { 0% { opacity: 0.2; } 100% { opacity: 0.8; } }

:deep(.shooting-star) {
  position: fixed; width: 80px; height: 1px; z-index: 0;
  background: linear-gradient(90deg, rgba(255, 255, 255, 0.8), transparent);
  animation: shoot 1.2s linear forwards; transform-origin: left center;
}

@keyframes shoot {
  0% { transform: translateX(0) translateY(0) rotate(-20deg); opacity: 1; }
  100% { transform: translateX(300px) translateY(120px) rotate(-20deg); opacity: 0; }
}

.wish-modal {
  position: fixed; z-index: 20; padding: 16px; border-radius: 16px;
  background: rgba(10, 14, 26, 0.9); backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 215, 0, 0.2);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
  opacity: 0; pointer-events: none; transition: all 0.3s; transform: scale(0.9);
}

.wish-modal.is-visible { opacity: 1; pointer-events: auto; transform: scale(1); }

.wish-modal input {
  width: 200px; padding: 8px 12px; border-radius: 8px;
  border: 1px solid rgba(255, 215, 0, 0.3); background: rgba(255, 255, 255, 0.05);
  color: #ffd700; font-size: 14px; outline: none;
}

.wish-modal input::placeholder { color: rgba(255, 215, 0, 0.4); }
.wish-modal input:focus { border-color: #ffd700; }

.wish-modal button {
  margin-top: 8px; width: 100%; padding: 6px; border-radius: 8px; border: none;
  background: linear-gradient(135deg, #ffd700, #ffaa00);
  color: #1a0e2e; font-weight: 700; font-size: 13px; cursor: pointer;
}

@media (max-width: 720px) {
  .wish-modal {
    left: 16px !important;
    right: 16px !important;
    top: auto !important;
    bottom: 20px !important;
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .wish-modal input {
    width: auto;
    flex: 1;
  }

  .wish-modal button {
    margin-top: 0;
    width: auto;
    padding: 8px 16px;
    white-space: nowrap;
  }

  .hint {
    bottom: 80px;
  }
}
</style>
