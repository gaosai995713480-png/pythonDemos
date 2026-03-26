<script setup>
import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import TopBar from '../components/TopBar.vue'
import { expressApi } from '../api'
import { useAuthStore } from '../stores/auth'
const authStore = useAuthStore()

const router = useRouter()

// 表单状态
const trackingNum = ref('')
const selectedCom = ref('')
const phone = ref('')
const companies = ref([])
const detectedCompanies = ref([])
const loading = ref(false)
const detecting = ref(false)

// 查询结果
const result = ref(null)
const errorMsg = ref('')

// 地图相关
let map = null
let mapMarkers = []
let polyline = null
const showMap = ref(false)

// 状态码映射
const stateMap = {
  '0': { text: '在途', icon: '🚚', color: '#3b82f6' },
  '1': { text: '揽收', icon: '📦', color: '#8b5cf6' },
  '2': { text: '疑难', icon: '⚠️', color: '#f59e0b' },
  '3': { text: '签收', icon: '✅', color: '#10b981' },
  '4': { text: '退签', icon: '↩️', color: '#ef4444' },
  '5': { text: '派件', icon: '🏃', color: '#06b6d4' },
  '6': { text: '退回', icon: '🔙', color: '#f97316' },
  '7': { text: '转投', icon: '🔄', color: '#6366f1' },
  '10': { text: '待清关', icon: '🛃', color: '#a855f7' },
  '11': { text: '清关中', icon: '📋', color: '#14b8a6' },
  '12': { text: '已清关', icon: '🎉', color: '#22c55e' },
  '13': { text: '清关异常', icon: '❌', color: '#dc2626' },
  '14': { text: '拒签', icon: '🚫', color: '#b91c1c' },
}

function getState(code) {
  return stateMap[String(code)] || { text: '未知', icon: '📍', color: '#94a3b8' }
}

// 加载快递公司列表
async function loadCompanies() {
  try {
    const data = await expressApi.companies()
    companies.value = data.companies || []
  } catch { /* ignore */ }
}

// 自动识别快递公司
let detectTimer = null
let detectRequestId = 0
function onNumInput() {
  clearTimeout(detectTimer)
  detectRequestId += 1
  const currentRequestId = detectRequestId
  const num = trackingNum.value.trim()
  if (num.length < 6) {
    detectedCompanies.value = []
    detecting.value = false
    return
  }
  detecting.value = true
  detectTimer = setTimeout(async () => {
    try {
      const data = await expressApi.detect(num)
      if (currentRequestId !== detectRequestId) return
      detectedCompanies.value = data.auto || []
      // 自动选中第一个
      if (detectedCompanies.value.length > 0 && !selectedCom.value) {
        selectedCom.value = detectedCompanies.value[0].comCode
        onComChange()
      }
    } catch { /* ignore */ }
    if (currentRequestId !== detectRequestId) return
    detecting.value = false
  }, 500)
}

// 查询物流
async function queryExpress() {
  const num = trackingNum.value.trim()
  if (!num) { errorMsg.value = '请输入快递单号'; return }
  if (!selectedCom.value) { errorMsg.value = '请选择快递公司'; return }

  errorMsg.value = ''
  loading.value = true
  result.value = null
  // 销毁旧地图实例，防止二次查询时 DOM 重建但 map 实例脱离
  clearMap()
  if (map) { map.destroy(); map = null }
  showMap.value = false

  try {
    const data = await expressApi.query(num, selectedCom.value, phone.value.trim())

    if (data.status === 'error') {
      errorMsg.value = data.message || '查询失败'
    } else if (data.message === 'ok' || data.status === '200') {
      result.value = data
      // 查询成功后尝试渲染地图
      await nextTick()
      initMapRoute(data.data || [])
    } else {
      errorMsg.value = data.message || '未查询到物流信息'
    }
  } catch (e) {
    errorMsg.value = '网络错误，请重试'
  }
  loading.value = false
}

// 需要手机号的快递公司
const needPhoneCompanies = ['shunfeng', 'zhongtong']
const needPhone = ref(false)
function onComChange() {
  needPhone.value = needPhoneCompanies.includes(selectedCom.value)
}

// ===== 地图路线可视化 =====

function loadAmapSDK() {
  return new Promise((resolve) => {
    if (window.AMap) { resolve(); return }
    window._AMapSecurityConfig = { securityJsCode: 'ca6c1f4b7f9f6da24ab08e9f5497621a' }
    const script = document.createElement('script')
    script.src = 'https://webapi.amap.com/maps?v=2.0&key=5bf41e2540a12180a9208bbcaea7c696&plugin=AMap.Geocoder,AMap.Driving,AMap.CitySearch'
    script.onload = resolve
    document.head.appendChild(script)
  })
}

function extractCityFromArea(areaName) {
  // 从 areaName 提取城市，如 "安徽,芜湖市,鸠江区" → "芜湖"
  if (!areaName) return null
  const parts = areaName.split(',')
  if (parts.length >= 2) {
    return parts[1].replace(/(市|区|县)$/, '')
  }
  return parts[0].replace(/(省|市|区|县)$/, '')
}

function extractCitiesFromContext(context) {
  // 从物流描述中提取所有城市名（【xxx中心】【xxx网点】等）
  if (!context) return []
  const cities = []
  const matches = context.matchAll(/【(.+?)】/g)
  for (const m of matches) {
    // 清洗："芜湖转运中心" → "芜湖"，"武汉转运中心" → "武汉"
    const raw = m[1]
    const clean = raw.replace(/(转运中心|分拣中心|营业部|中心|网点|站|公司|集散|仓|处)$/g, '')
      .replace(/(市|区|县|镇)$/, '')
    if (clean && clean.length >= 2 && clean.length <= 6) {
      cities.push(clean)
    }
  }
  return cities
}

async function geocodeCity(city) {
  return new Promise((resolve) => {
    if (!window.AMap) { resolve(null); return }
    const geocoder = new AMap.Geocoder()
    geocoder.getLocation(city, (status, result) => {
      if (status === 'complete' && result.geocodes && result.geocodes.length > 0) {
        const loc = result.geocodes[0].location
        resolve([loc.lng, loc.lat])
      } else {
        resolve(null)
      }
    })
  })
}

function clearMap() {
  if (!map) return
  mapMarkers.forEach(m => map.remove(m))
  mapMarkers = []
  if (polyline) {
    if (Array.isArray(polyline)) {
      polyline.forEach(p => map.remove(p))
    } else {
      map.remove(polyline)
    }
    polyline = null
  }
}

async function initMapRoute(trackData) {
  if (!trackData || trackData.length === 0) return

  // 从时间正序遍历（API 返回倒序，所以 reverse）
  const reversed = [...trackData].reverse()
  const cityList = [] // 保持顺序的城市列表
  const seen = new Set()

  for (const item of reversed) {
    const candidates = []

    // 优先使用 API 返回的 areaName
    const areaCity = extractCityFromArea(item.areaName)
    if (areaCity) candidates.push(areaCity)

    // 从物流描述补充
    const ctxCities = extractCitiesFromContext(item.context)
    candidates.push(...ctxCities)

    // 去重并按顺序加入（含模糊去重：如 "芜湖鸠江惠众" 包含已有的 "芜湖" 则跳过）
    for (const city of candidates) {
      if (seen.has(city)) continue
      // 模糊去重：如果已有城市是 city 的前缀，或 city 是已有城市的前缀
      let dup = false
      for (const s of seen) {
        if (city.startsWith(s) || s.startsWith(city)) { dup = true; break }
      }
      if (dup) continue
      seen.add(city)
      cityList.push({ city, time: item.ftime || item.time, context: item.context })
    }
  }

  if (cityList.length < 2) return

  await loadAmapSDK()
  showMap.value = true
  await nextTick()

  if (!map) {
    map = new AMap.Map('express-map', {
      zoom: 5,
      center: [114.3, 30.6],
      mapStyle: 'amap://styles/dark',
      viewMode: '2D',
    })
  }
  clearMap()

  // 地理编码所有城市
  const points = []
  for (const info of cityList) {
    const coords = await geocodeCity(info.city)
    if (coords) {
      points.push({ ...info, coords })
    }
  }

  if (points.length < 2) return

  // 画标记
  points.forEach((p, i) => {
    const isFirst = i === 0
    const isLast = i === points.length - 1
    const content = document.createElement('div')
    content.className = 'express-marker'

    if (isFirst) {
      // 起点 — "发" 标记
      content.innerHTML = '<span class="origin-tag">发</span>'
    } else if (isLast) {
      // 当前位置 — 快递车
      content.innerHTML = '<span class="truck-marker">🚚</span><span class="pulse-dot truck-pulse"></span>'
    } else {
      // 中间节点
      content.innerHTML = '<span class="mid-dot"></span>'
    }

    const labelText = isLast
      ? `<div class="marker-label current-label">📍 ${p.city}（当前）</div>`
      : `<div class="marker-label">${isFirst ? '发 ' : ''}${p.city}</div>`

    const marker = new AMap.Marker({
      position: p.coords,
      content,
      offset: new AMap.Pixel(-12, -12),
      label: {
        content: labelText,
        direction: 'top',
      },
    })
    map.add(marker)
    mapMarkers.push(marker)
  })

  // 绘制沿公路的路线（AMap.Driving）
  const origin = points[0].coords
  const destination = points[points.length - 1].coords
  const waypoints = points.slice(1, -1).map(p => new AMap.LngLat(p.coords[0], p.coords[1]))

  try {
    const driving = new AMap.Driving({
      map: null, // 不自动渲染，手动画
      policy: AMap.DrivingPolicy.LEAST_DISTANCE,
    })

    driving.search(
      new AMap.LngLat(origin[0], origin[1]),
      new AMap.LngLat(destination[0], destination[1]),
      { waypoints },
      (status, result) => {
        if (status === 'complete' && result.routes && result.routes.length > 0) {
          // 提取路线坐标
          const routePath = []
          const route = result.routes[0]
          for (const step of route.steps) {
            routePath.push(...step.path.map(p => [p.lng, p.lat]))
          }
          // 绘制路线
          polyline = new AMap.Polyline({
            path: routePath,
            strokeColor: '#ef4444',
            strokeWeight: 4,
            strokeStyle: 'solid',
            lineJoin: 'round',
            strokeOpacity: 0.9,
            showDir: true,
          })
          map.add(polyline)
          map.setFitView([...mapMarkers, polyline], false, [60, 60, 60, 60])
        } else {
          // 驾车路线失败，回退到直线
          drawFallbackLine(points)
        }
      }
    )
  } catch {
    drawFallbackLine(points)
  }

  map.setFitView(mapMarkers, false, [60, 60, 60, 60])

  // ===== 方案E：自动推断收货地 =====
  const inferredDest = inferDestCity(trackData, cityList)
  let destCityName = inferredDest
  if (!destCityName) {
    destCityName = await detectUserCity()
  }
  // 确保目的地不是已在地图上的最后一个城市（避免重复标记）
  const lastCity = cityList[cityList.length - 1]?.city
  if (destCityName && destCityName !== lastCity && !lastCity?.startsWith(destCityName) && !destCityName.startsWith(lastCity || '')) {
    const destCoords = await geocodeCity(destCityName)
    if (destCoords) {
      const lastPoint = points[points.length - 1]
      // 目的地 "收" 标记
      const destContent = document.createElement('div')
      destContent.className = 'express-marker'
      destContent.innerHTML = '<span class="dest-tag">收</span>'
      const destMarker = new AMap.Marker({
        position: destCoords,
        content: destContent,
        offset: new AMap.Pixel(-12, -12),
        label: {
          content: `<div class="marker-label dest-label">收 ${destCityName}</div>`,
          direction: 'top',
        },
      })
      map.add(destMarker)
      mapMarkers.push(destMarker)

      // 剩余路线（灰色虚线）
      const remainLine = new AMap.Polyline({
        path: [lastPoint.coords, destCoords],
        strokeColor: '#94a3b8',
        strokeWeight: 2,
        strokeStyle: 'dashed',
        lineJoin: 'round',
        strokeOpacity: 0.6,
      })
      map.add(remainLine)
      mapMarkers.push(remainLine)

      map.setFitView(mapMarkers, false, [60, 60, 60, 60])
    }
  }
}

// 从物流文本推断目的地城市
function inferDestCity(trackData, cityList) {
  // 策略：找时间最早的一条"已发往"信息中的目标城市，或物流信息显示的最终目的地
  // 按时间正序遍历（最早到最晚）
  const reversed = [...trackData].reverse()
  let lastDest = null

  for (const item of reversed) {
    const ctx = item.context || ''
    // 匹配"已发往【xxx】"或"发往【xxx】"
    const m = ctx.match(/发往[《【](.+?)[》】]/)
    if (m) {
      const raw = m[1].replace(/(转运中心|分拣中心|营业部|中心|网点|站|公司|集散|仓|处)$/g, '').replace(/(市|区|县|镇)$/, '')
      if (raw && raw.length >= 2 && raw.length <= 6) {
        lastDest = raw
      }
    }
  }
  return lastDest
}

// IP 定位获取用户所在城市（兆底）
async function detectUserCity() {
  return new Promise((resolve) => {
    try {
      const citySearch = new AMap.CitySearch()
      citySearch.getLocalCity((status, result) => {
        if (status === 'complete' && result.city) {
          resolve(result.city.replace(/市$/, ''))
        } else {
          resolve(null)
        }
      })
    } catch {
      resolve(null)
    }
  })
}

function drawFallbackLine(points) {
  const path = points.map(p => p.coords)
  polyline = new AMap.Polyline({
    path,
    strokeColor: '#ef4444',
    strokeWeight: 3,
    strokeStyle: 'dashed',
    lineJoin: 'round',
    strokeOpacity: 0.8,
    showDir: true,
  })
  map.add(polyline)
}

// 历史记录
const historyList = ref([])
const HISTORY_KEY = 'express_history'

function loadHistory() {
  try {
    const data = localStorage.getItem(HISTORY_KEY)
    historyList.value = data ? JSON.parse(data) : []
  } catch { historyList.value = [] }
}

function saveHistory(num, com, comName) {
  const list = historyList.value.filter(h => h.num !== num)
  list.unshift({ num, com, comName, phone: phone.value.trim(), time: new Date().toLocaleString() })
  historyList.value = list.slice(0, 10) // 最多保留10条
  localStorage.setItem(HISTORY_KEY, JSON.stringify(historyList.value))
}

function useHistory(h) {
  trackingNum.value = h.num
  selectedCom.value = h.com
  phone.value = h.phone || ''
  onComChange()
  queryExpress()
}

function clearHistory() {
  historyList.value = []
  localStorage.removeItem(HISTORY_KEY)
}

// 查询成功时保存历史
const originalQuery = queryExpress
queryExpress = async function () {
  await originalQuery()
  if (result.value && (result.value.message === 'ok' || result.value.status === '200')) {
    const comName = companies.value.find(c => c.code === selectedCom.value)?.name || selectedCom.value
    saveHistory(trackingNum.value.trim(), selectedCom.value, comName)
  }
}

// ===== 密钥配置管理（仅管理员） =====
const showConfig = ref(false)
const configStatus = ref({ customer_configured: false, key_configured: false })
const configForm = ref({ customer: '', key: '' })
const configSaving = ref(false)
const configMsg = ref('')

async function loadConfigStatus() {
  if (!authStore.isAdmin) return
  try {
    configStatus.value = await expressApi.getConfig()
  } catch { /* ignore */ }
}

async function saveConfig() {
  if (!configForm.value.customer.trim() && !configForm.value.key.trim()) {
    configMsg.value = '请至少填写一项'
    return
  }
  configSaving.value = true
  configMsg.value = ''
  try {
    await expressApi.updateConfig(configForm.value)
    configMsg.value = '✅ 保存成功'
    configForm.value = { customer: '', key: '' }
    await loadConfigStatus()
    setTimeout(() => { configMsg.value = '' }, 2000)
  } catch {
    configMsg.value = '保存失败，请重试'
  }
  configSaving.value = false
}

onMounted(() => {
  loadCompanies()
  loadHistory()
  loadConfigStatus()
})

onUnmounted(() => {
  clearMap()
  if (map) { map.destroy(); map = null }
})
</script>

<template>
  <TopBar title="📦 快递查询" @back="router.push('/')">
    <span class="subtitle">实时物流追踪</span>
  </TopBar>

  <div class="express-page">
    <!-- 查询卡片 -->
    <div class="query-card glass-card">
      <div class="query-header">
        <span class="query-icon">🔍</span>
        <span class="query-title">查询快递</span>
      </div>

      <div class="form-group">
        <label>快递单号</label>
        <div class="input-wrap">
          <input
            id="express-num-input"
            v-model="trackingNum"
            @input="onNumInput"
            placeholder="请输入快递单号"
            maxlength="32"
          />
          <span v-if="detecting" class="input-suffix spin">⏳</span>
        </div>
      </div>

      <!-- 自动识别提示 -->
      <div v-if="detectedCompanies.length > 0" class="detect-hint">
        <span class="detect-label">识别结果：</span>
        <button
          v-for="c in detectedCompanies.slice(0, 3)"
          :key="c.comCode"
          class="detect-chip"
          :class="{ active: selectedCom === c.comCode }"
          @click="selectedCom = c.comCode; onComChange()"
        >
          {{ companies.find(cc => cc.code === c.comCode)?.name || c.comCode }}
        </button>
      </div>

      <div class="form-group">
        <label>快递公司</label>
        <select id="express-com-select" v-model="selectedCom" @change="onComChange">
          <option value="">请选择快递公司</option>
          <option v-for="c in companies" :key="c.code" :value="c.code">{{ c.name }}</option>
        </select>
      </div>

      <div v-if="needPhone" class="form-group">
        <label>手机号后4位 <span class="hint">（该快递公司需要）</span></label>
        <input
          id="express-phone-input"
          v-model="phone"
          placeholder="如：1234"
          maxlength="4"
        />
      </div>

      <div v-if="errorMsg" class="error-msg">{{ errorMsg }}</div>

      <button
        id="express-query-btn"
        class="btn-query"
        :class="{ loading }"
        :disabled="loading"
        @click="queryExpress"
      >
        <span v-if="loading" class="spin">⏳</span>
        <span v-else>🔍</span>
        {{ loading ? '查询中...' : '查询物流' }}
      </button>
    </div>

    <!-- 查询结果 -->
    <div v-if="result" class="result-section">
      <!-- 状态概览 -->
      <div class="status-card glass-card">
        <div class="status-header">
          <span class="status-icon">{{ getState(result.state).icon }}</span>
          <div class="status-info">
            <div class="status-text" :style="{ color: getState(result.state).color }">
              {{ getState(result.state).text }}
            </div>
            <div class="status-com">{{ result.com }} · {{ result.nu }}</div>
          </div>
        </div>
      </div>

      <!-- 地图路线 -->
      <div v-if="showMap" class="map-card glass-card">
        <div class="map-header">
          <span>🗺️</span>
          <span>物流路线</span>
        </div>
        <div id="express-map"></div>
      </div>

      <!-- 物流时间轴 -->
      <div class="timeline-card glass-card">
        <div class="timeline-header">
          <span>📋</span>
          <span>物流详情</span>
          <span class="timeline-count">共 {{ result.data?.length || 0 }} 条</span>
        </div>
        <div class="timeline-list">
          <div
            v-for="(item, idx) in result.data"
            :key="idx"
            class="timeline-item"
            :class="{ 'is-latest': idx === 0 }"
          >
            <div class="tl-dot" :class="{ 'is-latest': idx === 0 }"></div>
            <div class="tl-line" v-if="idx < result.data.length - 1"></div>
            <div class="tl-content">
              <div class="tl-time">{{ item.ftime || item.time }}</div>
              <div class="tl-text">{{ item.context }}</div>
              <div v-if="item.areaName" class="tl-area">📍 {{ item.areaName }}</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 历史记录 -->
    <div v-if="historyList.length > 0 && !result" class="history-card glass-card">
      <div class="history-header">
        <span>🕐</span>
        <span>查询历史</span>
        <button class="history-clear" @click="clearHistory">清空</button>
      </div>
      <div class="history-list">
        <div
          v-for="h in historyList"
          :key="h.num"
          class="history-item"
          @click="useHistory(h)"
        >
          <div class="h-info">
            <div class="h-num">{{ h.num }}</div>
            <div class="h-meta">{{ h.comName }} · {{ h.time }}</div>
          </div>
          <span class="h-arrow">→</span>
        </div>
      </div>
    </div>

    <!-- 密钥配置（仅管理员） -->
    <div v-if="authStore.isAdmin" class="config-card glass-card">
      <div class="config-header" @click="showConfig = !showConfig">
        <span>⚙️</span>
        <span>快递100 API 配置</span>
        <div class="config-status">
          <span class="status-dot" :class="configStatus.customer_configured && configStatus.key_configured ? 'ok' : 'warn'"></span>
          {{ configStatus.customer_configured && configStatus.key_configured ? '已配置' : '未配置' }}
        </div>
        <span class="config-toggle">{{ showConfig ? '▲' : '▼' }}</span>
      </div>
      <div v-if="showConfig" class="config-body">
        <p class="config-tip">在 <a href="https://api.kuaidi100.com/" target="_blank">快递100开放平台</a> 注册获取授权码和密钥，配置后即可查询物流。</p>
        <div class="form-group">
          <label>授权码 customer <span class="hint">（约12位字母数字）</span> <span v-if="configStatus.customer_configured" class="configured-badge">✅ 已配置</span></label>
          <input v-model="configForm.customer" placeholder="如：WBzoCdXX7794（留空不更新）" />
        </div>
        <div class="form-group">
          <label>密钥 key <span class="hint">（32位大写字母数字）</span> <span v-if="configStatus.key_configured" class="configured-badge">✅ 已配置</span></label>
          <input v-model="configForm.key" type="password" placeholder="如：A99D0DF7XXXX...（留空不更新）" />
        </div>
        <div v-if="configMsg" class="config-msg" :class="{ success: configMsg.startsWith('✅') }">{{ configMsg }}</div>
        <button class="btn-save" :disabled="configSaving" @click="saveConfig">
          {{ configSaving ? '保存中...' : '💾 保存配置' }}
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.subtitle {
  margin-left: auto;
  font-size: 13px;
  color: var(--text-secondary);
  white-space: nowrap;
}

.express-page {
  max-width: 640px;
  margin: 72px auto 40px;
  padding: 0 16px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

/* 玻璃卡片 */
.glass-card {
  background: var(--glass-bg);
  backdrop-filter: blur(24px);
  border: 1px solid var(--glass-border);
  border-radius: 20px;
  padding: 24px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
}

/* 查询卡片 */
.query-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 20px;
}
.query-icon { font-size: 24px; }
.query-title {
  font-size: 18px;
  font-weight: 700;
  background: linear-gradient(135deg, var(--primary), var(--accent, #a78bfa));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.form-group {
  margin-bottom: 14px;
}
.form-group label {
  display: block;
  font-size: 13px;
  color: var(--text-secondary);
  margin-bottom: 6px;
  font-weight: 500;
}
.hint { font-size: 11px; color: var(--text-secondary); opacity: 0.7; }

.input-wrap {
  position: relative;
}
.input-wrap input {
  width: 100%;
  padding: 12px 40px 12px 14px;
  border-radius: 12px;
  border: 1px solid var(--glass-border);
  background: rgba(255, 255, 255, 0.06);
  color: var(--text-primary);
  font-size: 15px;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.input-wrap input:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(255, 107, 157, 0.15);
}
.input-suffix {
  position: absolute;
  right: 12px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 16px;
}

.form-group input:not(.input-wrap input),
.form-group select {
  width: 100%;
  padding: 12px 14px;
  border-radius: 12px;
  border: 1px solid var(--glass-border);
  background: rgba(255, 255, 255, 0.06);
  color: var(--text-primary);
  font-size: 14px;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
  appearance: none;
}
.form-group select {
  cursor: pointer;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23999' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 14px center;
  padding-right: 36px;
}
.form-group select option {
  background: #1e1e3e;
  color: #fff;
}
.form-group input:focus,
.form-group select:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(255, 107, 157, 0.15);
}

/* 自动识别 */
.detect-hint {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}
.detect-label {
  font-size: 12px;
  color: var(--text-secondary);
}
.detect-chip {
  padding: 4px 12px;
  border-radius: 20px;
  border: 1px solid var(--glass-border);
  background: rgba(255, 255, 255, 0.06);
  color: var(--text-secondary);
  font-size: 12px;
  cursor: pointer;
  transition: all 0.2s;
}
.detect-chip:hover {
  background: rgba(255, 255, 255, 0.12);
}
.detect-chip.active {
  background: rgba(99, 102, 241, 0.2);
  border-color: #6366f1;
  color: #a5b4fc;
}

/* 错误提示 */
.error-msg {
  padding: 10px 14px;
  border-radius: 10px;
  background: rgba(239, 68, 68, 0.15);
  color: #f87171;
  font-size: 13px;
  margin-bottom: 14px;
  border: 1px solid rgba(239, 68, 68, 0.2);
}

/* 查询按钮 */
.btn-query {
  width: 100%;
  padding: 14px;
  border-radius: 14px;
  border: none;
  background: linear-gradient(135deg, #6366f1, #8b5cf6);
  color: #fff;
  font-size: 15px;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.25s;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  box-shadow: 0 4px 16px rgba(99, 102, 241, 0.3);
}
.btn-query:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 8px 28px rgba(99, 102, 241, 0.45);
}
.btn-query:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

/* 旋转动画 */
.spin {
  display: inline-block;
  animation: spin 1s linear infinite;
}
@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

/* 状态卡片 */
.status-header {
  display: flex;
  align-items: center;
  gap: 14px;
}
.status-icon { font-size: 40px; }
.status-text {
  font-size: 20px;
  font-weight: 700;
}
.status-com {
  font-size: 13px;
  color: var(--text-secondary);
  margin-top: 4px;
}

/* 地图 */
.map-card {
  overflow: hidden;
}
.map-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 15px;
  font-weight: 600;
  margin-bottom: 14px;
}
#express-map {
  width: 100%;
  height: 280px;
  border-radius: 14px;
  overflow: hidden;
}

/* 时间轴 */
.timeline-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 15px;
  font-weight: 600;
  margin-bottom: 18px;
}
.timeline-count {
  margin-left: auto;
  font-size: 12px;
  color: var(--text-secondary);
  font-weight: 400;
}

.timeline-list {
  display: flex;
  flex-direction: column;
}

.timeline-item {
  position: relative;
  padding-left: 28px;
  padding-bottom: 20px;
}
.timeline-item:last-child {
  padding-bottom: 0;
}

.tl-dot {
  position: absolute;
  left: 0;
  top: 4px;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.2);
  border: 2px solid rgba(255, 255, 255, 0.3);
}
.tl-dot.is-latest {
  background: #6366f1;
  border-color: #818cf8;
  box-shadow: 0 0 12px rgba(99, 102, 241, 0.5);
}

.tl-line {
  position: absolute;
  left: 5px;
  top: 18px;
  bottom: 0;
  width: 2px;
  background: rgba(255, 255, 255, 0.08);
}

.tl-content {
  animation: fadeSlideIn 0.3s ease;
}
.tl-time {
  font-size: 12px;
  color: var(--text-secondary);
  margin-bottom: 4px;
}
.tl-text {
  font-size: 14px;
  line-height: 1.6;
  color: var(--text-primary);
}
.timeline-item.is-latest .tl-text {
  color: #a5b4fc;
  font-weight: 600;
}
.tl-area {
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 4px;
}

@keyframes fadeSlideIn {
  from { opacity: 0; transform: translateX(-8px); }
  to { opacity: 1; transform: translateX(0); }
}

/* 当前位置脉冲动画 */
:global(.pulse-dot) {
  display: block;
  width: 14px;
  height: 14px;
  background: #6366f1;
  border-radius: 50%;
  position: relative;
  box-shadow: 0 0 8px rgba(99, 102, 241, 0.6);
}
:global(.pulse-dot::after) {
  content: '';
  position: absolute;
  inset: -6px;
  border-radius: 50%;
  border: 2px solid #818cf8;
  animation: pulse-ring 1.5s ease-out infinite;
}
@keyframes pulse-ring {
  0% { transform: scale(0.6); opacity: 1; }
  100% { transform: scale(1.6); opacity: 0; }
}

/* 发/收 标签 */
:global(.origin-tag),
:global(.dest-tag) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  border-radius: 50%;
  font-size: 11px;
  font-weight: 700;
  color: #fff;
}
:global(.origin-tag) {
  background: #6366f1;
  box-shadow: 0 2px 8px rgba(99, 102, 241, 0.4);
}
:global(.dest-tag) {
  background: #ef4444;
  box-shadow: 0 2px 8px rgba(239, 68, 68, 0.4);
  position: relative;
  z-index: 2;
}
:global(.express-marker) {
  display: flex;
  align-items: center;
  gap: 4px;
}
:global(.mid-dot) {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.5);
  border: 1px solid rgba(255, 255, 255, 0.3);
}
:global(.truck-marker) {
  font-size: 26px;
  filter: drop-shadow(0 2px 6px rgba(0,0,0,0.5));
  position: relative;
  z-index: 2;
}
:global(.truck-pulse) {
  position: absolute;
  left: 6px;
  top: 6px;
  z-index: 1;
}

/* 地图标记标签 */
:global(.marker-label) {
  background: rgba(30, 30, 62, 0.85);
  color: #e2e8f0;
  padding: 2px 8px;
  border-radius: 6px;
  font-size: 11px;
  white-space: nowrap;
  border: 1px solid rgba(255, 255, 255, 0.15);
}
:global(.current-label) {
  background: rgba(99, 102, 241, 0.3);
  border-color: #818cf8;
  color: #c7d2fe;
  font-weight: 600;
  font-size: 12px;
  padding: 3px 10px;
}
:global(.dest-label) {
  background: rgba(239, 68, 68, 0.3);
  border-color: #f87171;
  color: #fca5a5;
  font-weight: 600;
  font-size: 12px;
  padding: 3px 10px;
}

/* 历史记录 */
.history-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 15px;
  font-weight: 600;
  margin-bottom: 14px;
}
.history-clear {
  margin-left: auto;
  padding: 4px 10px;
  border-radius: 8px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  background: transparent;
  color: var(--text-secondary);
  font-size: 12px;
  cursor: pointer;
  transition: all 0.2s;
}
.history-clear:hover {
  background: rgba(239, 68, 68, 0.15);
  color: #f87171;
}

.history-item {
  display: flex;
  align-items: center;
  padding: 14px 16px;
  border-radius: 14px;
  border: 1px solid rgba(255, 255, 255, 0.04);
  background: rgba(255, 255, 255, 0.02);
  cursor: pointer;
  transition: all 0.2s;
  margin-bottom: 8px;
}
.history-item:last-child { margin-bottom: 0; }
.history-item:hover {
  background: rgba(255, 255, 255, 0.08);
  border-color: rgba(255, 255, 255, 0.1);
  transform: translateX(4px);
}

.h-num {
  font-size: 14px;
  font-weight: 600;
  font-family: 'Courier New', monospace;
  letter-spacing: 0.5px;
}
.h-meta {
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 2px;
}
.h-arrow {
  margin-left: auto;
  color: var(--text-secondary);
  font-size: 18px;
}

/* 地图标记样式 */
:deep(.express-marker) {
  cursor: pointer;
  filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.3));
}
:deep(.marker-label) {
  background: rgba(30, 30, 50, 0.85);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.15);
  border-radius: 8px;
  padding: 4px 10px;
  font-size: 12px;
  color: #e2e8f0;
  white-space: nowrap;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}

/* 密钥配置 */
.config-card {
  border: 1px dashed rgba(255, 255, 255, 0.1);
}
.config-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 15px;
  font-weight: 600;
  cursor: pointer;
  user-select: none;
}
.config-status {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--text-secondary);
  font-weight: 400;
}
.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.status-dot.ok { background: #10b981; }
.status-dot.warn { background: #f59e0b; }
.config-toggle {
  font-size: 12px;
  color: var(--text-secondary);
  margin-left: 8px;
}
.config-body {
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid rgba(255, 255, 255, 0.06);
}
.config-tip {
  font-size: 13px;
  color: var(--text-secondary);
  margin-bottom: 14px;
  line-height: 1.5;
}
.config-tip a {
  color: #818cf8;
  text-decoration: none;
}
.config-tip a:hover { text-decoration: underline; }
.configured-badge {
  font-size: 11px;
  color: #10b981;
}
.config-msg {
  padding: 8px 12px;
  border-radius: 8px;
  font-size: 13px;
  margin-bottom: 12px;
  background: rgba(239, 68, 68, 0.15);
  color: #f87171;
}
.config-msg.success {
  background: rgba(16, 185, 129, 0.15);
  color: #34d399;
}
.btn-save {
  width: 100%;
  padding: 12px;
  border-radius: 12px;
  border: none;
  background: rgba(99, 102, 241, 0.2);
  color: #a5b4fc;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}
.btn-save:hover:not(:disabled) {
  background: rgba(99, 102, 241, 0.35);
}
.btn-save:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* 移动端适配 */
@media (max-width: 720px) {
  .express-page {
    margin-top: 60px;
    padding: 0 12px;
    gap: 12px;
  }

  .glass-card {
    padding: 18px;
    border-radius: 16px;
  }

  .query-title { font-size: 16px; }

  .btn-query {
    padding: 12px;
    font-size: 14px;
  }

  .status-icon { font-size: 32px; }
  .status-text { font-size: 18px; }

  #express-map { height: 220px; }

  .timeline-item { padding-left: 24px; }
  .tl-text { font-size: 13px; }
}
</style>
