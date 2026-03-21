<script setup>
/**
 * 天气卡片组件 — 从 HomeView 拆出
 * 完全自治：管理自己的数据、定时器、生命周期
 */
import { ref, onMounted, onUnmounted } from 'vue'
import { weatherApi } from '../api'

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
    const results = await Promise.allSettled([
      weatherApi.weather(code, 'base'),
      weatherApi.weather(code, 'all'),
    ])
    const baseData = results[0].status === 'fulfilled' ? results[0].value : {}
    const allData = results[1].status === 'fulfilled' ? results[1].value : {}
    if (baseData.status === '1' && baseData.lives?.length > 0) {
      weatherData.value = baseData.lives[0]
    }
    if (allData.status === '1' && allData.forecasts?.length > 0) {
      forecastData.value = allData.forecasts[0].casts || []
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
    } catch { /* toast handled by API layer */ }
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
  } catch { /* toast handled by API layer */ }
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

function cleanup() {
  if (weatherRefreshTimer) clearInterval(weatherRefreshTimer)
  if (searchTimer) clearTimeout(searchTimer)
}

defineExpose({ cleanup })

onMounted(async () => {
  document.addEventListener('click', closeCitySearch)
  if (!weatherCity.value) {
    await autoLocate()
  }
  loadWeather()
  weatherRefreshTimer = setInterval(() => loadWeather(), WEATHER_REFRESH_MS)
})

onUnmounted(() => {
  document.removeEventListener('click', closeCitySearch)
  cleanup()
})
</script>

<template>
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
</template>

<style scoped>
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
}
</style>
