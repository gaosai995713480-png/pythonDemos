<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { tripstarApi } from '../../api'

const props = defineProps({
  plan: {
    type: Object,
    required: true,
  },
})

const mapEl = ref(null)
const loading = ref(false)
const ready = ref(false)
const errorMsg = ref('')
const errorType = ref('')

let mapInstance = null
let overlays = []
let destroyed = false

const AMAP_CALLBACK_NAME = '__tripstarAmapReady'
const dayColors = ['#38bdf8', '#a78bfa', '#34d399', '#f59e0b', '#fb7185', '#22c55e']

function normalizeLocation(location) {
  if (!location) return null
  const longitude = Number(location.longitude ?? location.lng)
  const latitude = Number(location.latitude ?? location.lat)
  if (!Number.isFinite(longitude) || !Number.isFinite(latitude)) return null
  return { longitude, latitude }
}

const attractions = computed(() => {
  const items = []
  for (const day of props.plan?.days || []) {
    for (const attraction of day.attractions || []) {
      const location = normalizeLocation(attraction.location)
      if (!location) continue
      items.push({
        ...attraction,
        day: day.day,
        dayTitle: day.title,
        location,
      })
    }
  }
  return items
})

const routeLines = computed(() => {
  const routes = props.plan?.map_routes || []
  if (routes.length) {
    return routes
      .map((route, index) => ({
        day: route.day ?? index + 1,
        path: (route.polyline || [])
          .map((point) => {
            if (Array.isArray(point)) return [Number(point[0]), Number(point[1])]
            const location = normalizeLocation(point)
            return location ? [location.longitude, location.latitude] : null
          })
          .filter(Boolean),
      }))
      .filter((route) => route.path.length >= 2)
  }

  return (props.plan?.days || [])
    .map((day) => ({
      day: day.day,
      path: (day.attractions || [])
        .map((attraction) => normalizeLocation(attraction.location))
        .filter(Boolean)
        .map((location) => [location.longitude, location.latitude]),
    }))
    .filter((route) => route.path.length >= 2)
})

const center = computed(() => {
  const configuredCenter = normalizeLocation(props.plan?.map_center)
  if (configuredCenter) return [configuredCenter.longitude, configuredCenter.latitude]
  const first = attractions.value[0]?.location
  if (first) return [first.longitude, first.latitude]
  return [116.397128, 39.916527]
})

const stateLabel = computed(() => {
  if (ready.value) return '已加载'
  if (loading.value) return '加载中'
  if (errorType.value === 'config') return '需要配置'
  if (errorType.value) return '加载失败'
  return '待加载'
})

const routeSummaries = computed(() => (props.plan?.map_routes || []).map((route, index) => ({
  day: route.day ?? index + 1,
  names: (route.points || []).map((point) => point.name).filter(Boolean),
  distance: formatDistance(route.distance_meters),
  duration: formatDuration(route.duration_seconds),
})))

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function markerLabel(item) {
  return `
    <div class="tripstar-amap-label" style="
      display:inline-flex;
      align-items:center;
      gap:6px;
      padding:7px 10px;
      border-radius:999px;
      background:rgba(24,24,37,0.92);
      border:1px solid rgba(167,139,250,0.72);
      box-shadow:0 8px 22px rgba(0,0,0,0.25);
      color:#ffffff;
      font-size:12px;
      font-weight:800;
      white-space:nowrap;
    ">
      <span style="color:#a78bfa;">Day ${escapeHtml(item.day)}</span>
      <span>${escapeHtml(item.name)}</span>
    </div>
  `
}

function formatDistance(value) {
  const meters = Number(value || 0)
  if (!Number.isFinite(meters) || meters <= 0) return ''
  if (meters < 1000) return `${Math.round(meters)}米`
  return `${(meters / 1000).toFixed(1)}公里`
}

function formatDuration(value) {
  const seconds = Number(value || 0)
  if (!Number.isFinite(seconds) || seconds <= 0) return ''
  const minutes = Math.max(1, Math.round(seconds / 60))
  if (minutes < 60) return `${minutes}分钟`
  const hours = Math.floor(minutes / 60)
  const rest = minutes % 60
  return rest ? `${hours}小时${rest}分钟` : `${hours}小时`
}

function loadAmapSdk(config) {
  window._AMapSecurityConfig = {
    ...(window._AMapSecurityConfig || {}),
    securityJsCode: config.amap_security_js_code,
  }

  if (window.AMap?.Map) return Promise.resolve(window.AMap)

  const key = config.amap_web_js_key
  const securityCode = config.amap_security_js_code
  const params = new URLSearchParams({
    v: '2.0',
    key,
    plugin: 'AMap.Scale,AMap.ToolBar',
    callback: AMAP_CALLBACK_NAME,
  })
  const scriptSrc = `https://webapi.amap.com/maps?${params.toString()}`
  const existing = document.getElementById('tripstar-amap-js-sdk')
  if (existing) {
    const existingKey = existing.dataset.tripstarAmapKey || new URL(existing.src).searchParams.get('key')
    const existingSecurityCode = existing.dataset.tripstarAmapSecurityJsCode || ''
    if (
      existingKey === key
      && existingSecurityCode === securityCode
      && existing.src.includes(`callback=${AMAP_CALLBACK_NAME}`)
    ) {
      return waitForAmapScript(existing)
    }
    existing.remove()
  }

  const script = document.createElement('script')
  script.id = 'tripstar-amap-js-sdk'
  script.async = true
  script.dataset.tripstarAmapKey = key
  script.dataset.tripstarAmapSecurityJsCode = securityCode
  script.src = scriptSrc
  const promise = waitForAmapScript(script)
  document.head.appendChild(script)
  return promise
}

function waitForAmapScript(script) {
  return new Promise((resolve, reject) => {
    let settled = false
    const previousCallback = window[AMAP_CALLBACK_NAME]
    const settle = (handler, value) => {
      if (settled) return
      settled = true
      window.clearTimeout(timer)
      if (window[AMAP_CALLBACK_NAME] === onAmapReady) {
        if (previousCallback === undefined) {
          delete window[AMAP_CALLBACK_NAME]
        } else {
          window[AMAP_CALLBACK_NAME] = previousCallback
        }
      }
      handler(value)
    }
    const onAmapReady = () => {
      if (window.AMap?.Map) {
        settle(resolve, window.AMap)
        return
      }
      settle(reject, new Error('高德地图 SDK 初始化失败，请检查高德 Web端 Key、安全密钥、应用服务类型和域名白名单'))
    }
    window[AMAP_CALLBACK_NAME] = onAmapReady

    const timer = window.setTimeout(() => {
      settle(reject, new Error('高德地图 SDK 初始化超时，请检查高德 Web端 Key、安全密钥、应用服务类型和域名白名单'))
    }, 12000)
    script.addEventListener(
      'load',
      () => {
        if (window.AMap?.Map) {
          settle(resolve, window.AMap)
        }
      },
      { once: true },
    )
    script.addEventListener(
      'error',
      () => {
        settle(reject, new Error('高德地图 SDK 加载失败，请检查高德 Web端 Key、安全密钥、应用服务类型和域名白名单'))
      },
      { once: true },
    )
  })
}

function clearOverlays() {
  if (mapInstance?.remove && overlays.length) {
    mapInstance.remove(overlays)
  }
  overlays = []
}

function renderMap(AMap) {
  if (!mapEl.value) return
  if (!attractions.value.length) {
    errorMsg.value = '当前计划暂无可渲染地图点位'
    errorType.value = 'data'
    ready.value = false
    return
  }

  if (!mapInstance) {
    mapInstance = new AMap.Map(mapEl.value, {
      zoom: 12,
      center: center.value,
      viewMode: '2D',
    })
  }

  clearOverlays()

  const markers = attractions.value.map((item) => {
    const marker = new AMap.Marker({
      position: [item.location.longitude, item.location.latitude],
      title: item.name,
      label: {
        content: markerLabel(item),
        direction: 'top',
      },
      anchor: 'bottom-center',
    })
    mapInstance.add?.(marker)
    return marker
  })

  const polylines = routeLines.value.map((route, index) => {
    const polyline = new AMap.Polyline({
      path: route.path,
      strokeColor: dayColors[index % dayColors.length],
      strokeWeight: 5,
      strokeOpacity: 0.88,
      lineJoin: 'round',
      lineCap: 'round',
      showDir: true,
    })
    mapInstance.add?.(polyline)
    return polyline
  })

  overlays = [...markers, ...polylines]
  if (mapInstance.setFitView && overlays.length) {
    mapInstance.setFitView(overlays, false, [48, 48, 48, 48])
  }
  ready.value = true
  errorType.value = ''
}

async function initializeMap() {
  loading.value = true
  ready.value = false
  errorMsg.value = ''
  errorType.value = ''
  try {
    const config = await tripstarApi.getMapConfig()
    if (!config.configured || !config.amap_web_js_key || !config.amap_security_js_code) {
      errorMsg.value = config.message || '请先配置高德 Web端 Key 和安全密钥'
      errorType.value = 'config'
      return
    }
    await nextTick()
    const AMap = await loadAmapSdk(config)
    if (destroyed) return
    renderMap(AMap)
  } catch (error) {
    errorType.value = 'sdk'
    errorMsg.value = error?.message || '高德地图 SDK 加载失败，请检查高德 Web端 Key、安全密钥、应用服务类型和域名白名单'
  } finally {
    loading.value = false
  }
}

function focusAttraction(item) {
  const position = [item.location.longitude, item.location.latitude]
  if (mapInstance?.setZoomAndCenter) {
    mapInstance.setZoomAndCenter(15, position)
  } else if (mapInstance?.setCenter) {
    mapInstance.setCenter(position)
  }
}

onMounted(() => {
  initializeMap()
})

watch(
  () => props.plan,
  () => {
    if (window.AMap?.Map && mapInstance) {
      renderMap(window.AMap)
    }
  },
  { deep: true },
)

onUnmounted(() => {
  destroyed = true
  clearOverlays()
  mapInstance?.destroy?.()
  mapInstance = null
})
</script>

<template>
  <article class="tripstar-map-card glass">
    <div class="map-header">
      <div>
        <p class="eyebrow">Amap</p>
        <h2>TripStar 地图</h2>
      </div>
      <span class="map-state" :class="{ ready, error: errorMsg }">
        {{ stateLabel }}
      </span>
    </div>

    <p class="map-desc">
      展示每日景点点位与步行路线；后端路线/POI 接口使用高德 Web 服务 Key，前端渲染使用高德 Web端 Key。
    </p>

    <p v-if="loading" class="map-tip">正在加载高德地图...</p>
    <p v-if="errorMsg" class="map-error">{{ errorMsg }}</p>

    <div ref="mapEl" class="map-canvas" :class="{ hidden: errorMsg }" />

    <div v-if="attractions.length" class="map-points">
      <button
        v-for="item in attractions"
        :key="`${item.day}-${item.name}`"
        type="button"
        class="point-chip"
        @click="focusAttraction(item)"
      >
        <span>Day {{ item.day }}</span>
        {{ item.name }}
      </button>
    </div>

    <div v-if="routeSummaries.length" class="route-summary">
      <h3>地图路线</h3>
      <div
        v-for="route in routeSummaries"
        :key="route.day"
        class="route-row"
      >
        <strong>Day {{ route.day }}</strong>
        <span>{{ route.names.join(' → ') }}</span>
        <em v-if="route.distance || route.duration">
          {{ [route.distance, route.duration].filter(Boolean).join(' / ') }}
        </em>
      </div>
    </div>
  </article>
</template>

<style scoped>
.tripstar-map-card {
  grid-column: span 2;
  padding: 26px;
}

.map-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
}

.eyebrow {
  margin: 0 0 8px;
  color: var(--primary);
  font-size: 12px;
  font-weight: 900;
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

h2 {
  margin: 0;
}

.map-state {
  border-radius: 999px;
  padding: 8px 12px;
  background: rgba(255, 255, 255, 0.08);
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 900;
}

.map-state.ready {
  background: rgba(34, 197, 94, 0.18);
  color: #86efac;
}

.map-state.error {
  background: rgba(239, 68, 68, 0.18);
  color: #fca5a5;
}

.map-desc,
.map-tip,
.map-error {
  color: var(--text-secondary);
  line-height: 1.7;
}

.map-error {
  color: #fca5a5;
}

.map-canvas {
  height: 420px;
  overflow: hidden;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 22px;
  background:
    linear-gradient(135deg, rgba(56, 189, 248, 0.08), rgba(167, 139, 250, 0.08)),
    rgba(255, 255, 255, 0.04);
}

.map-canvas.hidden {
  display: none;
}

.map-points {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 16px;
}

.point-chip {
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 999px;
  padding: 9px 13px;
  background: rgba(255, 255, 255, 0.08);
  color: var(--text-primary);
  cursor: pointer;
}

.point-chip span {
  color: var(--primary);
  font-weight: 900;
}

.route-summary {
  margin-top: 18px;
  border-radius: 18px;
  padding: 16px;
  background: rgba(255, 255, 255, 0.06);
}

.route-summary h3 {
  margin: 0 0 12px;
  font-size: 16px;
}

.route-row {
  display: grid;
  grid-template-columns: 72px minmax(0, 1fr) auto;
  gap: 12px;
  align-items: center;
  padding: 10px 0;
  border-top: 1px solid rgba(255, 255, 255, 0.08);
  color: var(--text-secondary);
}

.route-row:first-of-type {
  border-top: none;
}

.route-row strong {
  color: var(--primary);
}

.route-row span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.route-row em {
  color: #86efac;
  font-style: normal;
  font-weight: 800;
}

@media (max-width: 760px) {
  .tripstar-map-card {
    grid-column: span 1;
  }

  .map-canvas {
    height: 320px;
  }

  .route-row {
    grid-template-columns: 1fr;
    gap: 6px;
  }

  .route-row span {
    white-space: normal;
  }
}
</style>
