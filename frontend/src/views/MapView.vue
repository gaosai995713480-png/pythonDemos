<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import TopBar from '../components/TopBar.vue'
import GlassModal from '../components/GlassModal.vue'
import { mapApi } from '../api'

const router = useRouter()
const markers = ref([])
const selectedMarker = ref(null)
const showDetail = ref(false)
const showForm = ref(false)
const form = ref({ name: '', note: '', date: '', photo: '', lat: 0, lng: 0 })
let editingId = null
let map = null
let mapMarkers = []
let polyline = null

// 地图初始化（需要等高德 SDK 加载完毕）
function initMap() {
  if (!window.AMap) return
  map = new AMap.Map('map-container', {
    zoom: 5,
    center: [114.3, 30.6],
    mapStyle: 'amap://styles/dark',
    viewMode: '2D',
  })
  map.on('click', onMapClick)
  loadMarkers()
}

function onMapClick(e) {
  if (showForm.value || showDetail.value) return
  const lnglat = e.lnglat
  const geocoder = new AMap.Geocoder()
  geocoder.getAddress([lnglat.lng, lnglat.lat], (status, result) => {
    let name = ''
    if (status === 'complete' && result.regeocode) {
      const addr = result.regeocode.formattedAddress || ''
      name = addr.replace(/^中国/, '').replace(/^\w+省/, '').replace(/^\w+市/, '')
    }
    openForm(name, lnglat.lat, lnglat.lng)
  })
}

function openForm(name, lat, lng, data) {
  editingId = data ? data.id : null
  form.value = {
    name: data ? data.title : (name || ''),
    note: data ? (data.note || '') : '',
    date: data ? (data.visit_date || '') : new Date().toISOString().split('T')[0],
    photo: data ? (data.photo_url || '') : '',
    lat, lng,
  }
  showForm.value = true
}

async function saveForm() {
  if (!form.value.name) { alert('请输入地点名称'); return }
  const body = {
    title: form.value.name, note: form.value.note,
    visit_date: form.value.date, photo_url: form.value.photo,
    lat: form.value.lat, lng: form.value.lng,
  }
  try {
    if (editingId) {
      body.id = editingId
      await mapApi.update(body)
    } else {
      await mapApi.create(body)
    }
    showForm.value = false
    showDetail.value = false
    loadMarkers()
  } catch { alert('保存失败') }
}

function openDetail(data) {
  selectedMarker.value = data
  showDetail.value = true
}

function editDetail() {
  if (!selectedMarker.value) return
  const d = selectedMarker.value
  showDetail.value = false
  openForm(d.title, d.lat, d.lng, d)
}

async function deleteDetail() {
  if (!selectedMarker.value || !confirm(`确定要删除「${selectedMarker.value.title}」吗？`)) return
  try {
    await mapApi.remove(selectedMarker.value.id)
    showDetail.value = false
    loadMarkers()
  } catch { alert('删除失败') }
}

function clearMapMarkers() {
  if (!map) return
  mapMarkers.forEach(m => map.remove(m))
  mapMarkers = []
  if (polyline) { map.remove(polyline); polyline = null }
}

function renderMapMarkers(data) {
  clearMapMarkers()
  data.forEach(item => {
    const content = document.createElement('div')
    content.className = 'love-marker'
    content.textContent = '💕'
    const marker = new AMap.Marker({
      position: [item.lng, item.lat],
      content,
      offset: new AMap.Pixel(-16, -16),
    })
    marker.on('click', () => openDetail(item))
    map.add(marker)
    mapMarkers.push(marker)
  })
  // 路线
  const sorted = [...data].filter(d => d.visit_date).sort((a, b) => a.visit_date.localeCompare(b.visit_date))
  if (sorted.length >= 2) {
    const path = sorted.map(d => [d.lng, d.lat])
    polyline = new AMap.Polyline({
      path,
      strokeColor: 'rgba(255,107,157,0.6)',
      strokeWeight: 2,
      strokeStyle: 'dashed',
      lineJoin: 'round',
    })
    map.add(polyline)
  }
  if (data.length > 0) map.setFitView(mapMarkers, false, [80, 80, 80, 80])
}

async function loadMarkers() {
  try {
    const data = await mapApi.list()
    markers.value = Array.isArray(data) ? data : []
    if (map) renderMapMarkers(markers.value)
  } catch { /* ignore */ }
}

// Search
const searchInput = ref('')
const searchResultsData = ref([])
const searchVisible = ref(false)
let searchTimer = null
let placeSearch = null

function initSearch() {
  if (!window.AMap) return
  AMap.plugin('AMap.PlaceSearch', function () {
    placeSearch = new AMap.PlaceSearch({ pageSize: 8 })
  })
}

function onSearchInput() {
  clearTimeout(searchTimer)
  const kw = searchInput.value.trim()
  if (!kw) { searchVisible.value = false; return }
  searchTimer = setTimeout(() => {
    if (!placeSearch) return
    placeSearch.search(kw, (status, result) => {
      if (status !== 'complete' || !result.poiList) {
        searchResultsData.value = []
        searchVisible.value = true
        return
      }
      searchResultsData.value = result.poiList.pois.map(p => ({
        name: p.name, address: p.address || p.cityname || '',
        lng: p.location.lng, lat: p.location.lat,
      }))
      searchVisible.value = true
    })
  }, 400)
}

function selectSearchResult(r) {
  map.setZoomAndCenter(15, [r.lng, r.lat])
  searchInput.value = r.name
  searchVisible.value = false
  openForm(r.name, r.lat, r.lng)
}

// Load AMap SDK dynamically
function loadAmapSDK() {
  return new Promise((resolve) => {
    if (window.AMap) { resolve(); return }
    window._AMapSecurityConfig = { securityJsCode: 'ca6c1f4b7f9f6da24ab08e9f5497621a' }
    const script = document.createElement('script')
    script.src = 'https://webapi.amap.com/maps?v=2.0&key=5bf41e2540a12180a9208bbcaea7c696&plugin=AMap.PlaceSearch,AMap.AutoComplete,AMap.Geocoder'
    script.onload = resolve
    document.head.appendChild(script)
  })
}

onMounted(async () => {
  await loadAmapSDK()
  initMap()
  initSearch()
})
</script>

<template>
  <TopBar title="🗺️ 恋爱足迹地图" @back="router.push('/')">
    <span class="marker-count">已标记 {{ markers.length }} 个地点</span>
  </TopBar>

  <!-- Search -->
  <div class="search-wrap">
    <div class="search-box">
      <span>🔍</span>
      <input v-model="searchInput" @input="onSearchInput" placeholder="搜索地点名称..." autocomplete="off" />
    </div>
    <div class="search-results" :class="{ 'is-visible': searchVisible && searchResultsData.length }">
      <div
        v-for="(r, i) in searchResultsData"
        :key="i"
        class="search-result-item"
        @click="selectSearchResult(r)"
      >
        <div class="search-result-name">{{ r.name }}</div>
        <div class="search-result-addr">{{ r.address }}</div>
      </div>
    </div>
  </div>

  <div id="map-container"></div>

  <!-- FAB -->
  <button class="fab-add" @click="map && openForm('', map.getCenter().lat, map.getCenter().lng)">+</button>

  <!-- Detail Card -->
  <div class="detail-backdrop" :class="{ 'is-visible': showDetail }" @click="showDetail = false"></div>
  <div class="detail-card" :class="{ 'is-visible': showDetail }" v-if="selectedMarker">
    <div class="detail-handle"></div>
    <img v-if="selectedMarker.photo_url" class="detail-photo" :src="selectedMarker.photo_url" alt="" />
    <div class="detail-title">{{ selectedMarker.title }}</div>
    <div class="detail-date">{{ selectedMarker.visit_date ? `📅 ${selectedMarker.visit_date}` : '' }}</div>
    <div class="detail-note">{{ selectedMarker.note || '暂无备注' }}</div>
    <div class="detail-actions">
      <button class="btn-edit" @click="editDetail">✏️ 编辑</button>
      <button class="btn-delete" @click="deleteDetail">🗑️ 删除</button>
    </div>
  </div>

  <!-- Form Modal -->
  <GlassModal v-model="showForm" :title="editingId ? '✏️ 编辑足迹' : '📍 添加足迹'">
    <div class="form-group">
      <label>地点名称 *</label>
      <input v-model="form.name" placeholder="如：黄鹤楼" maxlength="100" />
    </div>
    <div class="form-group">
      <label>一句话备注</label>
      <textarea v-model="form.note" placeholder="如：第一次约会的地方"></textarea>
    </div>
    <div class="form-group">
      <label>日期</label>
      <input type="date" v-model="form.date" />
    </div>
    <div class="form-group">
      <label>照片URL（可选）</label>
      <input v-model="form.photo" placeholder="https://..." />
    </div>
    <div class="form-btns">
      <button class="btn-cancel" @click="showForm = false">取消</button>
      <button class="btn-primary" @click="saveForm">保存</button>
    </div>
  </GlassModal>
</template>

<style scoped>
.marker-count { margin-left: auto; font-size: 13px; color: var(--text-secondary); white-space: nowrap; }

#map-container { position: fixed; top: 56px; left: 0; right: 0; bottom: 0; }

.search-wrap { position: fixed; top: 70px; left: 16px; right: 16px; z-index: 15; }
.search-box { display: flex; align-items: center; gap: 8px; background: var(--glass-bg); backdrop-filter: blur(20px); border: 1px solid var(--glass-border); border-radius: 14px; padding: 8px 16px; }
.search-box input { flex: 1; border: none; background: transparent; outline: none; font-size: 15px; color: var(--text-primary); }
.search-box input::placeholder { color: var(--text-secondary); }

.search-results { margin-top: 6px; max-height: 260px; overflow-y: auto; background: rgba(30, 30, 50, 0.92); backdrop-filter: blur(20px); border-radius: 12px; border: 1px solid var(--glass-border); display: none; }
.search-results.is-visible { display: block; }
.search-result-item { padding: 12px 16px; cursor: pointer; font-size: 14px; border-bottom: 1px solid rgba(255, 255, 255, 0.06); transition: background 0.15s; }
.search-result-item:hover { background: rgba(255, 255, 255, 0.08); }
.search-result-name { font-weight: 600; }
.search-result-addr { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }

.fab-add { position: fixed; bottom: 30px; right: 20px; z-index: 15; width: 56px; height: 56px; border-radius: 50%; border: none; background: linear-gradient(135deg, var(--primary), var(--secondary)); color: #fff; font-size: 28px; cursor: pointer; box-shadow: 0 6px 24px rgba(255, 107, 157, 0.4); transition: all 0.25s; display: flex; align-items: center; justify-content: center; }
.fab-add:hover { transform: scale(1.1); }

/* Detail Card */
.detail-backdrop { position: fixed; inset: 0; z-index: 25; background: rgba(0, 0, 0, 0.4); opacity: 0; pointer-events: none; transition: opacity 0.3s; }
.detail-backdrop.is-visible { opacity: 1; pointer-events: auto; }
.detail-card { position: fixed; bottom: 0; left: 0; right: 0; z-index: 30; background: rgba(30, 30, 50, 0.95); backdrop-filter: blur(30px); border-top: 1px solid var(--glass-border); border-radius: 24px 24px 0 0; padding: 20px 24px 36px; transform: translateY(100%); transition: transform 0.35s cubic-bezier(0.16, 1, 0.3, 1); max-height: 70vh; overflow-y: auto; }
.detail-card.is-visible { transform: translateY(0); }
.detail-handle { width: 40px; height: 4px; border-radius: 2px; background: rgba(255, 255, 255, 0.2); margin: 0 auto 16px; }
.detail-photo { width: 100%; max-height: 240px; object-fit: cover; border-radius: 16px; margin-bottom: 16px; }
.detail-title { font-size: 20px; font-weight: 700; margin-bottom: 6px; }
.detail-date { font-size: 13px; color: var(--accent); margin-bottom: 10px; }
.detail-note { font-size: 14px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 20px; }
.detail-actions { display: flex; gap: 12px; }
.detail-actions button { flex: 1; padding: 12px; border-radius: 12px; border: none; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
.btn-edit { background: rgba(255, 255, 255, 0.1); color: #fff; border: 1px solid rgba(255, 255, 255, 0.2) !important; }
.btn-edit:hover { background: rgba(255, 255, 255, 0.18); }
.btn-delete { background: rgba(220, 38, 38, 0.2); color: #f87171; }
.btn-delete:hover { background: rgba(220, 38, 38, 0.35); }

/* Form */
.form-group { margin-bottom: 14px; }
.form-group label { display: block; font-size: 13px; color: var(--text-secondary); margin-bottom: 6px; }
.form-group input, .form-group textarea { width: 100%; padding: 10px 14px; border-radius: 10px; border: 1px solid var(--glass-border); background: rgba(255, 255, 255, 0.06); color: #fff; font-size: 14px; outline: none; transition: border-color 0.2s; }
.form-group input:focus, .form-group textarea:focus { border-color: var(--primary); }
.form-group textarea { resize: vertical; min-height: 60px; }
.form-btns { display: flex; gap: 12px; margin-top: 20px; }
.form-btns button { flex: 1; padding: 12px; border-radius: 12px; border: none; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
.btn-cancel { background: rgba(255, 255, 255, 0.1); color: #fff; }

:deep(.love-marker) { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; font-size: 24px; filter: drop-shadow(0 2px 6px rgba(255, 107, 157, 0.5)); cursor: pointer; transition: transform 0.2s; }
:deep(.love-marker:hover) { transform: scale(1.3); }
</style>
