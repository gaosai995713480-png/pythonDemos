<script setup>
import { computed, ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { useMusicStore } from '../stores/music'
import { useThemeStore } from '../stores/theme'
import { useLyricFxStore } from '../stores/lyricFx'
import ThemeSwitcher from '../components/ThemeSwitcher.vue'
import LyricFxSwitcher from '../components/LyricFxSwitcher.vue'
import WeatherCard from '../components/WeatherCard.vue'
import DanmuBar from '../components/DanmuBar.vue'
import CapsuleSection from '../components/CapsuleSection.vue'
import NavSidebar from '../components/NavSidebar.vue'

const router = useRouter()
const authStore = useAuthStore()
const musicStore = useMusicStore()
const themeStore = useThemeStore()
const lyricFxStore = useLyricFxStore()

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

// 逐字动画需要把歌词拆成单字，其余效果直接渲染整行文本
const lyricChars = computed(() => (lyricFxStore.isPerChar ? [...currentLyric.value] : []))

// ===== 首页背景音乐 =====
// 管理员设置的全局 BGM，任何账号进首页都自动播放
onMounted(() => {
  musicStore.startBgm()
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
      <LyricFxSwitcher />
      <ThemeSwitcher />
      <button v-if="authStore.isAdmin" class="btn-ghost" title="用户管理与邀请码" @click="router.push('/users')">👥 管理</button>
      <button class="btn-ghost" title="登出" @click="logout">退出</button>
    </div>

    <h1>心动告白</h1>
    <p class="signature">在一起 {{ togetherDays }} 天 ❤️</p>

    <div class="heart-container">
      <div class="heart">
        <span class="glow-ring"></span>
      </div>
    </div>

    <!-- 歌词：外层负责漂浮位移，内层负责卡片与换句动画，避免两者争夺 transform -->
    <div class="lyrics-float" :class="lyricFxStore.cssClass" v-if="currentLyric">
      <!-- key 用索引而非文本：副歌重复句时文本相同，只有索引变化才能重放换句动画 -->
      <div class="lyrics" :key="musicStore.currentLyricIndex">
        <template v-if="lyricFxStore.isPerChar">
          <span
            v-for="(ch, i) in lyricChars"
            :key="i"
            class="lyric-char"
            :style="{ '--i': i }"
          >{{ ch }}</span>
        </template>
        <template v-else>{{ currentLyric }}</template>
      </div>
    </div>

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

  <!-- 自动播放被浏览器拦截时的提示，点一下即可开始 -->
  <div v-if="musicStore.bgmBlocked" class="bgm-hint" @click="musicStore.resumeBgm">
    🎵 点击播放 {{ musicStore.bgm?.title || '背景音乐' }}
  </div>
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

.lyrics-float {
  margin: 0 auto 32px;
  max-width: 600px;
  width: fit-content;
}

.lyrics {
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

/* 拆字后空格会被折叠，保留原样才不会把词粘在一起 */
.lyric-char {
  display: inline-block;
  white-space: pre;
}

/* ===== 歌词漂浮效果，由右上角 LyricFxSwitcher 切换 ===== */

/* 整卡轻浮：卡片整体浮动 + 投影同步呼吸 */
.fx-float {
  animation: lyric-float-card 6s ease-in-out infinite;
}
.fx-float .lyrics {
  animation: lyric-float-shadow 6s ease-in-out infinite;
}

@keyframes lyric-float-card {
  0%, 100% { transform: translateY(0) rotate(0deg); }
  33% { transform: translateY(-11px) rotate(-0.7deg); }
  66% { transform: translateY(7px) rotate(0.55deg); }
}

@keyframes lyric-float-shadow {
  0%, 100% { box-shadow: 0 10px 26px rgba(0, 0, 0, 0.28); }
  33% { box-shadow: 0 22px 40px rgba(0, 0, 0, 0.36); }
  66% { box-shadow: 0 7px 20px rgba(0, 0, 0, 0.24); }
}

/* 逐字波浪：卡片不动，每个字错峰起伏 */
.fx-wave .lyric-char {
  animation: lyric-char-wave 2.4s ease-in-out infinite;
  animation-delay: calc(var(--i) * 0.09s);
}

@keyframes lyric-char-wave {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-9px); }
}

/* 自由漂浮：脱开玻璃卡，文字发光并沿 XY 双轴慢漂，两轴周期错开使轨迹不重复 */
.fx-drift,
.fx-dream {
  animation: lyric-drift-x 13s ease-in-out infinite;
}

.fx-drift .lyrics,
.fx-dream .lyrics {
  background: none;
  border: none;
  backdrop-filter: none;
  padding: 10px 16px;
  font-weight: 400;
  text-shadow:
    0 0 18px rgba(255, 255, 255, 0.45),
    0 0 42px rgba(255, 107, 157, 0.35),
    0 2px 16px rgba(0, 0, 0, 0.45);
}

.fx-drift .lyrics {
  animation: lyric-drift-y 8s ease-in-out infinite;
}

@keyframes lyric-drift-x {
  0%, 100% { transform: translateX(-14px); }
  50% { transform: translateX(14px); }
}

@keyframes lyric-drift-y {
  0%, 100% { transform: translateY(0) scale(1); }
  50% { transform: translateY(-16px) scale(1.03); }
}

/* 气泡上升：换句时从下方带模糊浮上来，两侧伴随升起的光点 */
.fx-bubble {
  position: relative;
}

.fx-bubble .lyrics {
  animation: lyric-bubble-in 0.9s cubic-bezier(0.22, 1, 0.36, 1);
}

.fx-bubble::before,
.fx-bubble::after {
  content: "";
  position: absolute;
  bottom: 0;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.55);
  box-shadow: 0 0 12px rgba(255, 255, 255, 0.7);
  animation: lyric-bubble-rise 4.5s ease-in infinite;
  pointer-events: none;
}

.fx-bubble::before { left: 12%; }
.fx-bubble::after { right: 16%; animation-delay: 2.2s; }

@keyframes lyric-bubble-in {
  0% { opacity: 0; transform: translateY(28px) scale(0.94); filter: blur(8px); }
  60% { opacity: 1; filter: blur(0); }
  100% { opacity: 1; transform: translateY(0) scale(1); filter: blur(0); }
}

@keyframes lyric-bubble-rise {
  0% { opacity: 0; transform: translateY(10px) scale(0.6); }
  20% { opacity: 0.9; }
  100% { opacity: 0; transform: translateY(-110px) scale(1.25); }
}

/* 梦幻组合：自由漂浮 + 逐字波浪 + 换句柔化淡入 */
.fx-dream .lyrics {
  animation: lyric-drift-y 9s ease-in-out infinite, lyric-soft-in 0.8s ease-out;
}

.fx-dream .lyric-char {
  animation: lyric-char-wave 3s ease-in-out infinite;
  animation-delay: calc(var(--i) * 0.11s);
}

@keyframes lyric-soft-in {
  from { opacity: 0; filter: blur(6px); }
  to { opacity: 1; filter: blur(0); }
}

/* 系统开启「减少动态效果」时歌词保持静止 */
@media (prefers-reduced-motion: reduce) {
  .lyrics-float,
  .lyrics-float .lyrics,
  .lyrics-float .lyric-char,
  .lyrics-float::before,
  .lyrics-float::after {
    animation: none;
  }
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

.bgm-hint {
  position: fixed; right: 108px; bottom: 44px; z-index: 4;
  padding: 8px 14px; border-radius: 999px;
  background: rgba(0, 0, 0, 0.55); color: #fff; font-size: 13px;
  cursor: pointer; backdrop-filter: blur(6px);
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
}

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
