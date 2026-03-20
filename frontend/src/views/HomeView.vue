<script setup>
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { useMusicStore } from '../stores/music'
import { useThemeStore } from '../stores/theme'
import FloatingHearts from '../components/FloatingHearts.vue'
import ThemeSwitcher from '../components/ThemeSwitcher.vue'
import { danmuApi, capsuleApi, weatherApi } from '../api'

const router = useRouter()
const authStore = useAuthStore()
const musicStore = useMusicStore()
const themeStore = useThemeStore()

// ===== Danmu =====
const danmuInput = ref('')
const danmuList = ref([])
const MAX_LEN = 50
const settingsOpen = ref(false)
const danmuSpeed = ref(12)
const danmuDensity = ref(8)
let danmuTimers = []

async function loadDanmu() {
  try { danmuList.value = await danmuApi.list(50) } catch { /* ignore */ }
}

function spawnDanmu(item, delay = 0, fresh = false) {
  const layer = document.getElementById('danmu-layer')
  if (!layer) return
  const el = document.createElement('div')
  el.className = 'danmu-item' + (fresh ? ' is-fresh' : '')
  const isEmoji = /^[\p{Emoji}\s]+$/u.test(item.text)
  if (isEmoji) el.classList.add('is-emoji')
  el.style.top = (Math.random() * 70 + 5) + '%'
  el.style.setProperty('--duration', danmuSpeed.value + 's')
  el.style.setProperty('--delay', delay + 's')
  el.innerHTML = `<span>${item.text}</span><span class="danmu-like" data-id="${item.id}">❤️ ${item.likes || 0}</span>`
  el.querySelector('.danmu-like').addEventListener('click', async (ev) => {
    ev.stopPropagation()
    try {
      const res = await danmuApi.like(item.id)
      const likeEl = el.querySelector('.danmu-like')
      likeEl.textContent = `❤️ ${res.likes}`
      likeEl.classList.add('is-pop')
      setTimeout(() => likeEl.classList.remove('is-pop'), 400)
    } catch { /* ignore */ }
  })
  layer.appendChild(el)
  const timer = setTimeout(() => el.remove(), (danmuSpeed.value + delay) * 1000 + 500)
  danmuTimers.push(timer)
}

function launchAllDanmu() {
  clearDanmuTimers()
  const items = danmuList.value.slice(0, danmuDensity.value * 5)
  items.forEach((item, i) => {
    spawnDanmu(item, i * (danmuSpeed.value / danmuDensity.value))
  })
}

function clearDanmuTimers() {
  danmuTimers.forEach(t => clearTimeout(t))
  danmuTimers = []
  const layer = document.getElementById('danmu-layer')
  if (layer) layer.innerHTML = ''
}

async function sendDanmu() {
  const text = danmuInput.value.trim()
  if (!text) return
  try {
    const res = await danmuApi.send(text)
    danmuInput.value = ''
    if (res.ok) spawnDanmu({ text, id: res.id, likes: 0 }, 0, true)
    loadDanmu()
  } catch { /* ignore */ }
}

// ===== Weather =====
const DEFAULT_ADCODE = '420100' // 武汉

const weatherData = ref(null)
const forecastData = ref([])
const weatherCity = ref(localStorage.getItem('weather_adcode') || '')
const showCitySearch = ref(false)
const citySearchQuery = ref('')
const citySearchResults = ref([])
const weatherCardRef = ref(null)
const districtList = ref([])
const breadcrumb = ref([])
const districtLoading = ref(false)
const weatherLoading = ref(false)
const weatherError = ref(null)
let searchTimer = null
const WEATHER_REFRESH_MS = 30 * 60 * 1000
let weatherRefreshTimer = null

function weatherIcon(weather) {
  const map = {
    '晴': '☀️', '多云': '⛅', '阴': '☁️',
    '小雨': '🌦️', '中雨': '🌧️', '大雨': '🌧️', '暴雨': '⛈️',
    '雷阵雨': '⛈️', '小雪': '🌨️', '中雪': '❄️', '大雪': '❄️',
    '雾': '🌫️', '霾': '🌫️', '浮尘': '🌫️', '沙尘暴': '🌪️',
  }
  for (const [k, v] of Object.entries(map)) {
    if (weather?.includes(k)) return v
  }
  return '🌤️'
}

function formatForecastDate(dateStr) {
  if (!dateStr) return ''
  const d = new Date(dateStr)
  const today = new Date()
  const tomorrow = new Date(today)
  tomorrow.setDate(today.getDate() + 1)
  if (d.toDateString() === today.toDateString()) return '今天'
  if (d.toDateString() === tomorrow.toDateString()) return '明天'
  return `${d.getMonth() + 1}/${d.getDate()}`
}

async function autoLocate() {
  try {
    const loc = await weatherApi.locate()
    if (loc.adcode) {
      weatherCity.value = loc.adcode
      localStorage.setItem('weather_adcode', loc.adcode)
    } else {
      weatherCity.value = DEFAULT_ADCODE
    }
  } catch {
    weatherCity.value = DEFAULT_ADCODE
  }
}

async function loadWeather(adcode) {
  const code = adcode || weatherCity.value || DEFAULT_ADCODE
  weatherLoading.value = true
  weatherError.value = null
  try {
    // 并行请求：base 获取实时天气，all 获取预报
    const [baseData, allData] = await Promise.all([
      weatherApi.weather(code, 'base'),
      weatherApi.weather(code, 'all'),
    ])
    // 实时天气
    if (baseData.status === '1' && baseData.lives?.length > 0) {
      weatherData.value = baseData.lives[0]
    }
    // 3日预报
    if (allData.status === '1' && allData.forecasts?.length > 0) {
      forecastData.value = allData.forecasts[0].casts || []
      // 如果实时数据没拿到城市名，用预报的
      if (weatherData.value && !weatherData.value.city && allData.forecasts[0].city) {
        weatherData.value.city = allData.forecasts[0].city
      }
    }
    if (!weatherData.value) {
      weatherError.value = baseData.info || '天气加载失败'
    }
  } catch (e) {
    weatherError.value = '网络错误，无法加载天气'
  } finally {
    weatherLoading.value = false
  }
}

function onCitySearch(keyword) {
  clearTimeout(searchTimer)
  if (!keyword.trim()) { citySearchResults.value = []; return }
  searchTimer = setTimeout(async () => {
    try {
      const data = await weatherApi.district(keyword, 0)
      if (data.status === '1') {
        citySearchResults.value = data.districts || []
      }
    } catch { /* ignore */ }
  }, 300)
}

function selectCity(district) {
  weatherCity.value = district.adcode
  localStorage.setItem('weather_adcode', district.adcode)
  showCitySearch.value = false
  citySearchQuery.value = ''
  citySearchResults.value = []
  loadWeather(district.adcode)
}

async function loadDistricts(keyword = '中国') {
  districtLoading.value = true
  try {
    const data = await weatherApi.district(keyword, 1)
    if (data.status === '1' && data.districts?.length > 0) {
      districtList.value = data.districts[0].districts || []
    }
  } catch { /* ignore */ }
  districtLoading.value = false
}

function drillDown(district) {
  if (district.level === 'city' || district.level === 'district' || district.level === 'street') {
    selectCity(district)
    return
  }
  breadcrumb.value.push({ name: district.name, adcode: district.adcode })
  loadDistricts(district.name)
}

function goToBreadcrumb(index) {
  if (index < 0) {
    breadcrumb.value = []
    loadDistricts('中国')
  } else {
    const item = breadcrumb.value[index]
    breadcrumb.value = breadcrumb.value.slice(0, index + 1)
    loadDistricts(item.name)
  }
}

function toggleCityPanel() {
  showCitySearch.value = !showCitySearch.value
  if (showCitySearch.value && districtList.value.length === 0) {
    breadcrumb.value = []
    loadDistricts('中国')
  }
}

function levelLabel(level) {
  const map = { country: '国', province: '省', city: '市', district: '区/县', street: '街道' }
  return map[level] || level
}

function closeCitySearch(e) {
  if (weatherCardRef.value && !weatherCardRef.value.contains(e.target)) {
    showCitySearch.value = false
  }
}

onMounted(() => { document.addEventListener('click', closeCitySearch) })
onUnmounted(() => {
  document.removeEventListener('click', closeCitySearch)
  if (weatherRefreshTimer) clearInterval(weatherRefreshTimer)
})


// ===== Time Capsules =====
const capsules = ref([])
const capsuleModal = ref(false)
const capsuleForm = ref({ content: '', open_date: '' })

async function loadCapsules() {
  try { capsules.value = await capsuleApi.list() } catch { /* ignore */ }
}

async function saveCapsule() {
  if (!capsuleForm.value.content || !capsuleForm.value.open_date) { alert('请填写内容和开启日期'); return }
  try {
    await capsuleApi.create(capsuleForm.value)
    capsuleModal.value = false
    capsuleForm.value = { content: '', open_date: '' }
    loadCapsules()
  } catch { alert('保存失败') }
}

async function openCapsule(id) {
  try { await capsuleApi.open(id); loadCapsules() } catch { /* ignore */ }
}

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
  await authStore.logout()
  router.replace('/login')
}

// ===== Lifecycle =====
onMounted(async () => {
  loadDanmu()
  // 天气：若无保存的城市则自动定位
  if (!weatherCity.value) {
    await autoLocate()
  }
  loadWeather()
  weatherRefreshTimer = setInterval(() => loadWeather(), WEATHER_REFRESH_MS)
  loadCapsules()
  musicStore.loadSongs()
  // Launch danmu after loading
  setTimeout(launchAllDanmu, 1500)
  // Re-launch every cycle
  danmuTimers.push(setInterval(launchAllDanmu, danmuSpeed.value * 1000 + 2000))
})

onUnmounted(() => {
  clearDanmuTimers()
})
</script>

<template>
  <FloatingHearts />
  <div id="danmu-layer" class="danmu-layer"></div>

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

    <!-- 功能卡片导航网格 -->
    <nav class="nav-grid">
      <router-link to="/gallery" class="nav-card">
        <span class="nav-icon">📸</span><span class="nav-label">心动画廊</span>
      </router-link>
      <router-link to="/timeline" class="nav-card">
        <span class="nav-icon">📖</span><span class="nav-label">时间轴</span>
      </router-link>
      <router-link to="/music" class="nav-card">
        <span class="nav-icon">🎵</span><span class="nav-label">音乐时光</span>
      </router-link>
      <router-link to="/letter" class="nav-card">
        <span class="nav-icon">💌</span><span class="nav-label">表白信</span>
      </router-link>
      <router-link to="/mood" class="nav-card">
        <span class="nav-icon">😊</span><span class="nav-label">心情日历</span>
      </router-link>
      <router-link to="/wishes" class="nav-card">
        <span class="nav-icon">⭐</span><span class="nav-label">星空许愿</span>
      </router-link>
      <router-link to="/map" class="nav-card">
        <span class="nav-icon">🗺️</span><span class="nav-label">恋爱地图</span>
      </router-link>
    </nav>

    <!-- 天气卡片 -->
    <div class="weather-card" v-if="weatherData || weatherLoading || weatherError" ref="weatherCardRef">
      <!-- 加载中 -->
      <div v-if="weatherLoading && !weatherData" class="weather-status">
        <span class="weather-loading-spinner">⏳</span> 加载天气中...
      </div>
      <!-- 错误 -->
      <div v-else-if="weatherError && !weatherData" class="weather-status weather-status--error">
        <span>⚠️ {{ weatherError }}</span>
        <button class="weather-retry-btn" @click="loadWeather()">重试</button>
      </div>
      <!-- 正常展示 -->
      <template v-else-if="weatherData">
        <div class="weather-city" @click.stop="toggleCityPanel()">
          📍 {{ weatherData.city || '未知' }}
          <span class="city-search-icon">▾</span>
        </div>
        <!-- 城市选择面板 -->
        <div class="city-search-dropdown" :class="{ 'is-active': showCitySearch }" v-if="showCitySearch" @click.stop>
          <div class="city-panel-handle"></div>
          <input
            v-model="citySearchQuery"
            @input="onCitySearch(citySearchQuery)"
            placeholder="搜索省/市/区/县..."
            class="city-search-input"
          />
          <ul class="city-search-results" v-if="citySearchQuery && citySearchResults.length">
            <li v-for="d in citySearchResults" :key="d.adcode" @click="selectCity(d)">
              <span>{{ d.name }}</span>
              <span class="city-level">{{ levelLabel(d.level) }}</span>
            </li>
          </ul>
          <template v-if="!citySearchQuery">
            <div class="city-breadcrumb">
              <span @click="goToBreadcrumb(-1)" class="crumb">全国</span>
              <template v-for="(b, i) in breadcrumb" :key="i">
                <span class="crumb-sep">›</span>
                <span @click="goToBreadcrumb(i)" class="crumb">{{ b.name }}</span>
              </template>
            </div>
            <ul class="city-search-results" v-if="districtList.length">
              <li v-for="d in districtList" :key="d.adcode" @click="drillDown(d)">
                <span>{{ d.name }}</span>
                <span class="city-level">{{ levelLabel(d.level) }} ›</span>
              </li>
            </ul>
            <div v-else-if="districtLoading" class="city-loading">加载中...</div>
          </template>
        </div>
        <!-- 主体天气 -->
        <div class="weather-main">
          <span class="weather-emoji">{{ weatherIcon(weatherData.weather) }}</span>
          <span class="weather-temp">{{ weatherData.temperature || '--' }}°</span>
        </div>
        <div class="weather-desc">{{ weatherData.weather || '' }}</div>
        <div class="weather-detail" v-if="weatherData.winddirection">
          <span>💨 {{ weatherData.winddirection }}风 {{ weatherData.windpower }}级</span>
          <span v-if="weatherData.humidity">💧 {{ weatherData.humidity }}%</span>
        </div>
        <div class="weather-update" v-if="weatherData.reporttime">
          更新: {{ weatherData.reporttime?.slice(5) }}
        </div>
        <!-- 3日预报 -->
        <div class="weather-forecast" v-if="forecastData?.length">
          <div v-for="f in forecastData.slice(0, 3)" :key="f.date" class="forecast-day">
            <div class="forecast-date">{{ formatForecastDate(f.date) }}</div>
            <div class="forecast-icon">{{ weatherIcon(f.dayweather) }}</div>
            <div class="forecast-temp">{{ f.nighttemp }}°~{{ f.daytemp }}°</div>
          </div>
        </div>
      </template>
    </div>
    <!-- 城市选择遮罩(移动端) -->
    <div class="city-overlay" v-if="showCitySearch" @click="showCitySearch = false"></div>


    <!-- 时间胶囊 -->
    <section class="capsule-section" v-if="capsules.length">
      <h3>⏰ 时间胶囊</h3>
      <div class="capsule-list">
        <div v-for="c in capsules.slice(0, 5)" :key="c.id" class="capsule-card">
          <template v-if="c.is_opened">
            <div class="capsule-content">{{ c.content }}</div>
            <div class="capsule-date">{{ c.open_date }} 已开启</div>
          </template>
          <template v-else>
            <div class="capsule-locked">🔒 {{ c.open_date }} 开启</div>
            <button v-if="new Date(c.open_date) <= new Date()" class="btn-primary btn-small" @click="openCapsule(c.id)">开启</button>
          </template>
        </div>
      </div>
    </section>
  </main>

  <!-- 弹幕输入栏 -->
  <div class="danmu-bar">
    <button class="danmu-settings-toggle" @click="settingsOpen = !settingsOpen" title="弹幕设置">⚙️</button>
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
  width: clamp(140px, 22vw, 200px);
  height: clamp(140px, 22vw, 200px);
  position: relative;
  transform: rotate(-45deg);
  background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
  animation: beat 1.5s ease-in-out infinite;
  box-shadow:
    0 0 60px rgba(255, 107, 157, 0.6),
    0 20px 40px rgba(0, 0, 0, 0.3),
    inset 0 -8px 16px rgba(0, 0, 0, 0.2),
    inset 0 8px 16px rgba(255, 255, 255, 0.15);
  border-radius: 8px;
}

.heart::before, .heart::after {
  content: ""; width: 100%; height: 100%;
  position: absolute; background: inherit; border-radius: 50%; box-shadow: inherit;
}
.heart::before { top: -50%; left: 0; }
.heart::after { left: 50%; top: 0; }

.glow-ring {
  position: absolute; inset: -20%; border-radius: 50%;
  border: 3px solid rgba(255, 255, 255, 0.3);
  animation: ripple 3s ease-out infinite; filter: blur(1px);
}

/* Lyrics */
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

/* Nav Grid */
.nav-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 14px;
  margin: 24px 0;
}

.nav-card {
  display: flex; flex-direction: column; align-items: center; gap: 8px;
  padding: 18px 10px; border-radius: 16px;
  background: var(--glass-bg); backdrop-filter: blur(20px);
  border: 1px solid var(--glass-border);
  text-decoration: none; color: var(--text-primary);
  transition: all 0.25s; cursor: pointer;
}

.nav-card:hover { transform: translateY(-4px); box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3); background: rgba(255, 255, 255, 0.12); }
.nav-icon { font-size: 28px; }
.nav-label { font-size: 13px; font-weight: 600; }

/* Weather */
.weather-card {
  position: fixed; left: 24px; top: 24px; z-index: 3;
  padding: 16px 20px; border-radius: 16px;
  background: var(--glass-bg); backdrop-filter: blur(20px);
  border: 1px solid var(--glass-border);
  text-align: left; min-width: 140px; max-width: 220px;
}
.weather-city {
  font-size: 13px; color: var(--text-secondary); cursor: pointer;
  display: flex; align-items: center; gap: 4px;
  transition: color 0.2s;
}
.weather-city:hover { color: var(--text-primary); }
.city-search-icon { font-size: 10px; opacity: 0.6; transition: transform 0.2s; }
.weather-temp { font-size: 32px; font-weight: 700; }
.weather-desc { font-size: 13px; color: var(--text-secondary); }
.weather-status {
  font-size: 13px; color: var(--text-secondary);
  display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
}
.weather-status--error { color: var(--error); }
.weather-loading-spinner { animation: spin 2s linear infinite; display: inline-block; }
.weather-retry-btn {
  margin-top: 6px; padding: 4px 12px; border-radius: 8px;
  border: 1px solid var(--glass-border); background: rgba(255,255,255,0.1);
  color: var(--text-primary); font-size: 12px; cursor: pointer;
  transition: background 0.2s;
}
.weather-retry-btn:hover { background: rgba(255,255,255,0.2); }
.weather-main {
  display: flex; align-items: center; gap: 6px; margin: 4px 0 2px;
}
.weather-emoji { font-size: 28px; line-height: 1; }
.weather-detail {
  display: flex; gap: 10px; font-size: 12px; color: var(--text-secondary);
  margin-top: 6px;
}
.weather-update {
  font-size: 11px; color: var(--text-secondary); opacity: 0.6;
  margin-top: 4px;
}
.weather-forecast {
  display: flex; gap: 8px; margin-top: 10px;
  padding-top: 10px; border-top: 1px solid var(--glass-border);
}
.forecast-day { flex: 1; text-align: center; min-width: 0; }
.forecast-date { font-size: 11px; color: var(--text-secondary); margin-bottom: 2px; }
.forecast-icon { font-size: 18px; margin-bottom: 2px; }
.forecast-temp { font-size: 11px; color: var(--text-secondary); white-space: nowrap; }

.city-search-dropdown { margin-top: 8px; }
.city-search-input {
  width: 100%; padding: 6px 10px; border-radius: 8px;
  border: 1px solid rgba(255,255,255,0.2); box-sizing: border-box;
  background: rgba(0,0,0,0.2); color: #fff;
  font-size: 13px; outline: none; transition: border-color 0.2s;
}
.city-search-input:focus { border-color: var(--accent); }
.city-search-input::placeholder { color: rgba(255,255,255,0.4); }
.city-search-results {
  list-style: none; margin: 4px 0 0; padding: 0;
  max-height: 160px; overflow-y: auto;
}
.city-search-results li {
  padding: 6px 10px; cursor: pointer;
  border-radius: 6px; font-size: 13px;
  display: flex; justify-content: space-between; align-items: center;
  transition: background 0.15s;
}
.city-search-results li:hover { background: rgba(255,255,255,0.15); }
.city-level { font-size: 11px; opacity: 0.5; }

.city-breadcrumb {
  display: flex; align-items: center; gap: 2px;
  font-size: 11px; color: var(--text-secondary);
  padding: 4px 0; margin-bottom: 4px; flex-wrap: wrap;
}
.crumb { cursor: pointer; padding: 2px 4px; border-radius: 4px; transition: all 0.15s; }
.crumb:hover { background: rgba(255,255,255,0.1); color: var(--text-primary); }
.crumb-sep { opacity: 0.4; }
.city-loading { font-size: 12px; color: var(--text-secondary); padding: 8px; text-align: center; }
.city-panel-handle { display: none; }
.city-overlay { display: none; }

/* Capsule Section */
.capsule-section { margin: 32px 0; text-align: left; }
.capsule-section h3 { font-size: 18px; margin-bottom: 14px; }
.capsule-list { display: flex; gap: 12px; overflow-x: auto; padding: 4px 0; }
.capsule-card {
  min-width: 200px; padding: 16px; border-radius: 16px;
  background: var(--glass-bg); backdrop-filter: blur(20px);
  border: 1px solid var(--glass-border); flex-shrink: 0;
}
.capsule-content { font-size: 14px; line-height: 1.5; margin-bottom: 8px; }
.capsule-date { font-size: 12px; color: var(--accent); }
.capsule-locked { font-size: 14px; color: var(--text-secondary); }
.btn-small { padding: 6px 14px; font-size: 12px; margin-top: 8px; }

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
  animation: danmu-move linear forwards;
  animation-duration: var(--duration, 12s);
  animation-delay: var(--delay, 0s);
  display: inline-flex; align-items: center; gap: 10px;
  pointer-events: auto; cursor: pointer;
}

:deep(.danmu-item:hover) { filter: brightness(1.2); }
:deep(.danmu-item.is-emoji) { font-size: 16px; letter-spacing: 1px; }
:deep(.danmu-item.is-fresh) {
  background: linear-gradient(135deg, rgba(255, 107, 157, 0.2), rgba(196, 69, 105, 0.2));
  border-color: rgba(255, 107, 157, 0.4);
  box-shadow: 0 0 20px rgba(255, 107, 157, 0.5), 0 4px 16px rgba(0, 0, 0, 0.3);
}

:deep(.danmu-like) { font-size: 13px; color: var(--text-primary); opacity: 0.9; transition: all 0.3s; }
:deep(.danmu-like.is-pop) { transform: scale(1.3); color: var(--accent); }

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
  .weather-card {
    position: relative; left: auto; top: auto;
    margin: 0 auto 16px; text-align: center;
    max-width: 100%;
    display: flex; flex-direction: column; align-items: center;
  }
  .weather-main { justify-content: center; }
  .weather-detail { justify-content: center; }
  .weather-forecast { justify-content: center; overflow-x: auto; }
  .city-search-dropdown {
    position: fixed; bottom: 0; left: 0; right: 0; z-index: 101;
    max-height: 55vh; border-radius: 20px 20px 0 0;
    background: var(--glass-bg); backdrop-filter: blur(30px);
    border: 1px solid var(--glass-border);
    padding: 12px 20px 20px; margin-top: 0;
    box-shadow: 0 -8px 32px rgba(0,0,0,0.4);
    overflow-y: auto;
  }
  .city-panel-handle {
    display: block; width: 40px; height: 4px; border-radius: 2px;
    background: rgba(255,255,255,0.3); margin: 0 auto 12px;
  }
  .city-search-results { max-height: 35vh; }
  .city-overlay {
    display: block; position: fixed; inset: 0; z-index: 100;
    background: rgba(0,0,0,0.4); backdrop-filter: blur(4px);
  }
  .danmu-bar { left: 12px; right: 90px; bottom: 16px; padding: 10px 14px; }
  .play-button { right: 16px; bottom: 16px; width: 52px; height: 52px; font-size: 20px; }
  .nav-grid { grid-template-columns: repeat(3, 1fr); gap: 10px; }
}
</style>
