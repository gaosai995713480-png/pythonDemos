<script setup>
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { useMusicStore } from '../stores/music'
import { useThemeStore } from '../stores/theme'
import ThemeSwitcher from '../components/ThemeSwitcher.vue'
import WeatherCard from '../components/WeatherCard.vue'
import DanmuBar from '../components/DanmuBar.vue'
import CapsuleSection from '../components/CapsuleSection.vue'
import NavSidebar from '../components/NavSidebar.vue'

const router = useRouter()
const authStore = useAuthStore()
const musicStore = useMusicStore()
const themeStore = useThemeStore()

const weatherRef = ref(null)
const danmuRef = ref(null)

// ===== Together Days =====
const startDate = new Date('2023-10-26')
const togetherDays = computed(() => {
  const now = new Date()
  return Math.floor((now - startDate) / (1000 * 60 * 60 * 24))
})

// ===== Lyrics display =====
const currentLyric = computed(() => {
  if (musicStore.currentLyricIndex >= 0 && musicStore.lyricLines.length) {
    return musicStore.lyricLines[musicStore.currentLyricIndex]?.text || ''
  }
  return ''
})

// ===== Logout =====
async function logout() {
  // 组件级资源清理
  weatherRef.value?.cleanup()
  danmuRef.value?.cleanup()
  // Store 级重置由 auth.logout() 统一触发
  await authStore.logout()
  router.replace('/login')
}
</script>

<template>
  <DanmuBar ref="danmuRef" />

  <!-- 主场景 -->
  <main class="stage">
    <!-- 右上角工具栏 -->
    <div class="corner-actions">
      <ThemeSwitcher />
      <button class="btn-ghost" title="登出" @click="logout">退出</button>
    </div>

    <h1>心动告白</h1>
    <p class="signature">在一起 {{ togetherDays }} 天 ❤️</p>

    <div class="heart-container">
      <div class="heart">
        <span class="glow-ring"></span>
      </div>
    </div>

    <!-- 歌词 -->
    <div class="lyrics" v-if="currentLyric">{{ currentLyric }}</div>

    <!-- 侧边导航栏 -->
    <NavSidebar />

    <!-- 天气卡片 -->
    <WeatherCard ref="weatherRef" />

    <!-- 时间胶囊 -->
    <CapsuleSection />
  </main>

  <!-- 音乐播放按钮 -->
  <button class="play-button" :class="{ 'is-playing': musicStore.isPlaying }" @click="musicStore.togglePlay">
    <span>{{ musicStore.isPlaying ? '⏸' : '▶' }}</span>
  </button>
</template>

<style scoped>
.stage {
  position: relative;
  text-align: center;
  padding: 36px 24px 200px;
  z-index: 2;
  max-width: 800px;
  margin: 0 auto;
}

.corner-actions {
  position: fixed;
  top: 16px;
  right: 20px;
  z-index: 10;
  display: flex;
  gap: 8px;
  align-items: center;
}

h1 {
  margin: 0 0 8px;
  font-size: clamp(42px, 6vw, 72px);
  font-weight: 700;
  letter-spacing: -1px;
  background: linear-gradient(135deg, #fff 0%, rgba(255, 255, 255, 0.7) 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  animation: title-glow 3s ease-in-out infinite;
}

.signature {
  font-size: clamp(18px, 3vw, 24px);
  opacity: 0.9;
  line-height: 1.6;
  font-weight: 300;
  margin-bottom: 20px;
}

/* Heart */
.heart-container {
  display: flex;
  justify-content: center;
  margin: 40px 0;
}

.heart {
  position: relative;
  width: 100px; height: 100px;
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  transform: rotate(45deg);
  border-radius: 16px;
  box-shadow: 0 0 60px rgba(255, 107, 157, 0.6);
  animation: heartbeat 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}

.heart::before,
.heart::after {
  content: "";
  position: absolute;
  width: 100px; height: 100px;
  border-radius: 50%;
  background: inherit;
}
.heart::before { top: -50px; left: 0; }
.heart::after { top: 0; left: -50px; }

.glow-ring {
  position: absolute;
  inset: -20px;
  border-radius: 50%;
  border: 2px solid rgba(255, 107, 157, 0.3);
  animation: glow-pulse 2s ease-in-out infinite;
}

@keyframes heartbeat {
  0%, 100% { transform: rotate(45deg) scale(1); }
  14% { transform: rotate(45deg) scale(1.15); }
  28% { transform: rotate(45deg) scale(1); }
  42% { transform: rotate(45deg) scale(1.1); }
}

@keyframes glow-pulse {
  0%, 100% { opacity: 0.4; transform: scale(1); }
  50% { opacity: 0.8; transform: scale(1.15); }
}

@keyframes title-glow {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.85; filter: brightness(1.2); }
}

@keyframes spin { to { transform: rotate(360deg); } }

.lyrics {
  margin: 0 auto 32px;
  max-width: 600px;
  min-height: 32px;
  font-size: clamp(18px, 3.2vw, 26px);
  letter-spacing: 1px;
  color: var(--text-primary);
  text-shadow: 0 2px 20px rgba(0, 0, 0, 0.4);
  font-weight: 300;
  line-height: 1.5;
  padding: 16px 24px;
  background: var(--glass-bg);
  backdrop-filter: blur(20px);
  border-radius: 16px;
  border: 1px solid var(--glass-border);
}



/* Play Button */
.play-button {
  position: fixed; right: 32px; bottom: 32px; z-index: 4;
  width: 64px; height: 64px; border-radius: 50%; border: none;
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  color: #fff; font-size: 24px; cursor: pointer;
  box-shadow: 0 8px 24px rgba(255, 107, 157, 0.5);
  display: flex; align-items: center; justify-content: center;
  overflow: hidden; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.play-button:hover {
  transform: translateY(-4px) scale(1.05);
  box-shadow: 0 12px 32px rgba(255, 107, 157, 0.6);
}

.play-button::before {
  content: ""; position: absolute; inset: 12px; border-radius: 50%;
  background: conic-gradient(from 0deg, rgba(255, 255, 255, 0.4), transparent 60deg, transparent 300deg, rgba(255, 255, 255, 0.4));
  opacity: 0.6;
}

.play-button.is-playing::before { animation: spin 3s linear infinite; }
.play-button span { position: relative; z-index: 1; }

/* Mobile */
@media (max-width: 720px) {
  .stage {
    padding: 24px 16px 160px;
  }

  .corner-actions {
    top: 10px;
    right: 12px;
  }

  .heart-container {
    margin: 24px 0;
  }

  .heart {
    width: 70px;
    height: 70px;
  }

  .heart::before,
  .heart::after {
    width: 70px;
    height: 70px;
  }

  .heart::before {
    top: -35px;
  }

  .heart::after {
    left: -35px;
  }

  .lyrics {
    padding: 12px 16px;
    font-size: 15px;
  }

  .play-button {
    right: 16px;
    bottom: 16px;
    width: 52px;
    height: 52px;
    font-size: 20px;
  }
}
</style>
