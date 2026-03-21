<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import TopBar from '../components/TopBar.vue'
import GlassModal from '../components/GlassModal.vue'
import { musicApi, jukeboxApi } from '../api'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const authStore = useAuthStore()

// ===== 推荐列表 =====
const requests = ref([])
const loading = ref(false)

async function loadRequests() {
  loading.value = true
  try {
    requests.value = await jukeboxApi.list()
  } catch { requests.value = [] }
  loading.value = false
}

// ===== 搜索歌曲 =====
const searchKeyword = ref('')
const searchResults = ref([])
const searchLoading = ref(false)
const searchPlatform = ref('netease')

const platforms = [
  { value: 'netease', label: '网易云' },
  { value: 'tencent', label: 'QQ音乐' },
  { value: 'kugou', label: '酷狗' },
  { value: 'kuwo', label: '酷我' },
]

async function searchSongs() {
  if (!searchKeyword.value.trim()) return
  searchLoading.value = true
  try {
    searchResults.value = await musicApi.search(searchKeyword.value, searchPlatform.value)
  } catch { searchResults.value = [] }
  searchLoading.value = false
}

// ===== 推荐弹窗 =====
const showRecommendModal = ref(false)
const selectedSong = ref(null)
const nickname = ref('')
const message = ref('')
const submitting = ref(false)

function openRecommend(song) {
  selectedSong.value = song
  nickname.value = ''
  message.value = ''
  showRecommendModal.value = true
}

async function submitRecommend() {
  if (!selectedSong.value || submitting.value) return
  submitting.value = true
  try {
    const song = selectedSong.value
    const res = await jukeboxApi.create({
      song_id: song.id,
      song_name: song.name || song.title || '',
      artist: song.artist?.join?.(' / ') || song.artist || '',
      platform: searchPlatform.value,
      nickname: nickname.value.trim() || '匿名访客',
      message: message.value.trim(),
    })
    if (res.rate_limited) {
      alert(res.error || '推荐太频繁，请稍后再试')
    } else {
      showRecommendModal.value = false
      searchResults.value = []
      searchKeyword.value = ''
      await loadRequests()
    }
  } catch { /* ignore */ }
  submitting.value = false
}

// ===== 点赞 =====
async function likeRequest(item) {
  try {
    const res = await jukeboxApi.like(item.id)
    if (res.ok) {
      item.likes = res.likes
    }
  } catch { /* ignore */ }
}

// ===== 采纳（需登录） =====
async function adoptRequest(item) {
  if (!confirm(`确定要将「${item.song_name}」加入你的歌单吗？`)) return
  try {
    const res = await jukeboxApi.adopt(item.id)
    if (res.ok) {
      item.is_adopted = true
    }
  } catch { /* ignore */ }
}

// ===== 删除推荐（需登录） =====
async function removeRequest(item) {
  if (!confirm(`确定要移除「${item.song_name}」的推荐吗？`)) return
  try {
    const res = await jukeboxApi.remove(item.id)
    if (res.ok) {
      requests.value = requests.value.filter(r => r.id !== item.id)
    }
  } catch { /* ignore */ }
}

const isLoggedIn = computed(() => authStore.authenticated)

onMounted(() => loadRequests())
</script>

<template>
  <TopBar title="🎤 点歌台" @back="router.push('/')">
    <span class="req-count">{{ requests.length }} 首推荐</span>
  </TopBar>

  <div class="jukebox-container">
    <!-- 搜索推荐区 -->
    <div class="search-section">
      <h2 class="section-title">🎵 推荐一首歌给他们</h2>
      <div class="platform-row">
        <button
          v-for="p in platforms"
          :key="p.value"
          class="plat-btn"
          :class="{ 'is-active': searchPlatform === p.value }"
          @click="searchPlatform = p.value"
        >{{ p.label }}</button>
      </div>
      <div class="search-row">
        <input
          v-model="searchKeyword"
          placeholder="搜索歌曲名..."
          @keydown.enter="searchSongs"
        />
        <button class="btn-primary" @click="searchSongs" :disabled="searchLoading">
          {{ searchLoading ? '搜索中...' : '🔍 搜索' }}
        </button>
      </div>

      <!-- 搜索结果 -->
      <div class="search-results" v-if="searchResults.length">
        <div
          v-for="r in searchResults"
          :key="r.id"
          class="search-item"
          @click="openRecommend(r)"
        >
          <div class="sr-meta">
            <div class="sr-title">{{ r.name }}</div>
            <div class="sr-artist">{{ r.artist?.join?.(' / ') || r.artist }}</div>
          </div>
          <button class="sr-recommend-btn" title="推荐这首歌">🎤</button>
        </div>
      </div>
    </div>

    <!-- 推荐榜 -->
    <div class="request-section">
      <h2 class="section-title">🏆 推荐榜</h2>
      <div v-if="loading" class="loading-hint">加载中...</div>
      <div v-else-if="!requests.length" class="empty-hint">
        还没有人推荐歌曲，成为第一个吧 ✨
      </div>
      <div class="request-list" v-else>
        <div
          v-for="item in requests"
          :key="item.id"
          class="request-card"
          :class="{ 'is-adopted': item.is_adopted }"
        >
          <div class="rc-header">
            <div class="rc-song">
              <div class="rc-song-name">{{ item.song_name }}</div>
              <div class="rc-artist">{{ item.artist }}</div>
            </div>
            <span class="rc-platform">{{ platforms.find(p => p.value === item.platform)?.label || item.platform }}</span>
          </div>
          <div class="rc-message" v-if="item.message">「{{ item.message }}」</div>
          <div class="rc-footer">
            <span class="rc-nickname">— {{ item.nickname }}</span>
            <div class="rc-actions">
              <button class="rc-like-btn" @click="likeRequest(item)">
                ❤️ {{ item.likes }}
              </button>
              <span class="rc-adopted-badge" v-if="item.is_adopted">✅ 已采纳</span>
              <button
                v-else-if="isLoggedIn"
                class="rc-adopt-btn"
                @click="adoptRequest(item)"
              >📥 采纳</button>
              <button
                v-if="isLoggedIn"
                class="rc-remove-btn"
                @click="removeRequest(item)"
              >✕</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- 推荐弹窗 -->
  <GlassModal v-model="showRecommendModal" title="🎤 推荐歌曲">
    <div class="recommend-form" v-if="selectedSong">
      <div class="rf-song-info">
        <div class="rf-song-name">{{ selectedSong.name }}</div>
        <div class="rf-artist">{{ selectedSong.artist?.join?.(' / ') || selectedSong.artist }}</div>
      </div>
      <div class="rf-field">
        <label>你的昵称（可选）</label>
        <input v-model="nickname" placeholder="匿名访客" maxlength="30" />
      </div>
      <div class="rf-field">
        <label>祝福语（可选）</label>
        <input
          v-model="message"
          placeholder="写一句祝福的话..."
          maxlength="100"
          @keydown.enter="submitRecommend"
        />
      </div>
      <button
        class="btn-primary rf-submit"
        @click="submitRecommend"
        :disabled="submitting"
      >{{ submitting ? '推荐中...' : '🎵 推荐这首歌' }}</button>
    </div>
  </GlassModal>
</template>

<style scoped>
.req-count { margin-left: auto; font-size: 13px; color: rgba(255, 255, 255, 0.5); }

.jukebox-container {
  max-width: 640px;
  margin: 0 auto;
  padding: 90px 20px 60px;
}

.section-title {
  font-size: 20px;
  font-weight: 700;
  margin: 0 0 16px;
  letter-spacing: 0.5px;
}

/* Search Section */
.search-section {
  background: var(--glass-bg);
  backdrop-filter: blur(20px);
  border: 1px solid var(--glass-border);
  border-radius: 20px;
  padding: 24px;
  margin-bottom: 24px;
}

.platform-row { display: flex; gap: 8px; margin-bottom: 14px; flex-wrap: wrap; }
.plat-btn {
  padding: 6px 14px; border-radius: 8px;
  border: 1px solid rgba(255, 255, 255, 0.15);
  background: transparent; color: var(--text-secondary);
  font-size: 13px; cursor: pointer; transition: all 0.2s;
}
.plat-btn.is-active {
  background: rgba(255, 255, 255, 0.15);
  color: #fff; border-color: var(--primary);
}

.search-row { display: flex; gap: 8px; margin-bottom: 12px; }
.search-row input {
  flex: 1; padding: 10px 14px; border-radius: 10px;
  border: 1px solid rgba(255, 255, 255, 0.2);
  background: rgba(255, 255, 255, 0.06);
  color: #fff; font-size: 14px; outline: none;
}
.search-row input:focus { border-color: var(--primary); }
.search-row .btn-primary { padding: 10px 18px; white-space: nowrap; }

.search-results { max-height: 240px; overflow-y: auto; }
.search-item {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 14px; border-radius: 10px;
  cursor: pointer; transition: background 0.15s;
}
.search-item:hover { background: rgba(255, 255, 255, 0.08); }

.sr-meta { flex: 1; min-width: 0; }
.sr-title {
  font-size: 14px; font-weight: 600;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.sr-artist {
  font-size: 12px; color: var(--text-secondary); margin-top: 2px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

.sr-recommend-btn {
  width: 36px; height: 36px; border-radius: 50%;
  border: 1px solid rgba(255, 255, 255, 0.2);
  background: rgba(255, 255, 255, 0.08);
  font-size: 18px; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  transition: all 0.2s; flex-shrink: 0;
}
.sr-recommend-btn:hover {
  background: var(--primary); border-color: var(--primary);
  transform: scale(1.1);
}

/* Request Section */
.request-section {
  background: var(--glass-bg);
  backdrop-filter: blur(20px);
  border: 1px solid var(--glass-border);
  border-radius: 20px;
  padding: 24px;
}

.loading-hint, .empty-hint {
  text-align: center; padding: 40px 20px;
  color: var(--text-secondary); font-size: 14px;
}

.request-list { display: flex; flex-direction: column; gap: 12px; }

.request-card {
  padding: 18px; border-radius: 16px;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.08);
  transition: all 0.2s;
}
.request-card:hover {
  background: rgba(255, 255, 255, 0.08);
  border-color: rgba(255, 255, 255, 0.15);
}
.request-card.is-adopted {
  border-color: rgba(52, 211, 153, 0.3);
  background: rgba(52, 211, 153, 0.05);
}

.rc-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
.rc-song { flex: 1; min-width: 0; }
.rc-song-name { font-size: 16px; font-weight: 700; line-height: 1.3; }
.rc-artist { font-size: 13px; color: var(--text-secondary); margin-top: 2px; }
.rc-platform {
  font-size: 11px; color: var(--accent);
  padding: 2px 8px; border-radius: 6px;
  background: rgba(255, 192, 72, 0.1);
  flex-shrink: 0;
}

.rc-message {
  margin: 12px 0; padding: 10px 14px;
  background: rgba(255, 255, 255, 0.04);
  border-radius: 10px; border-left: 3px solid var(--primary);
  font-size: 14px; font-style: italic;
  color: rgba(255, 255, 255, 0.85);
  line-height: 1.5;
}

.rc-footer {
  display: flex; align-items: center;
  justify-content: space-between; margin-top: 10px;
}
.rc-nickname { font-size: 12px; color: var(--text-secondary); }
.rc-actions { display: flex; gap: 8px; align-items: center; }

.rc-like-btn {
  padding: 4px 12px; border-radius: 8px; border: none;
  background: rgba(255, 107, 157, 0.12);
  color: var(--primary); font-size: 13px;
  cursor: pointer; transition: all 0.2s;
}
.rc-like-btn:hover {
  background: rgba(255, 107, 157, 0.25);
  transform: scale(1.05);
}

.rc-adopt-btn {
  padding: 4px 12px; border-radius: 8px; border: none;
  background: rgba(52, 211, 153, 0.15);
  color: #34d399; font-size: 13px;
  cursor: pointer; transition: all 0.2s;
}
.rc-adopt-btn:hover {
  background: rgba(52, 211, 153, 0.3);
  transform: scale(1.05);
}

.rc-adopted-badge {
  font-size: 12px; color: #34d399;
  padding: 2px 8px; border-radius: 6px;
  background: rgba(52, 211, 153, 0.1);
}

.rc-remove-btn {
  width: 28px; height: 28px; border-radius: 50%; border: none;
  background: transparent; color: rgba(255, 255, 255, 0.3);
  font-size: 14px; cursor: pointer; transition: all 0.2s;
  display: flex; align-items: center; justify-content: center;
  opacity: 0;
}
.request-card:hover .rc-remove-btn { opacity: 1; }
@media (hover: none) { .rc-remove-btn { opacity: 0.6; } }
.rc-remove-btn:hover {
  background: rgba(255, 80, 80, 0.25); color: #fff;
}

/* Recommend Form */
.recommend-form { padding: 8px 0; }

.rf-song-info {
  text-align: center; margin-bottom: 20px;
  padding: 16px; border-radius: 12px;
  background: rgba(255, 107, 157, 0.08);
}
.rf-song-name { font-size: 18px; font-weight: 700; }
.rf-artist { font-size: 13px; color: var(--text-secondary); margin-top: 4px; }

.rf-field { margin-bottom: 14px; }
.rf-field label {
  display: block; font-size: 13px; font-weight: 600;
  margin-bottom: 6px; color: var(--accent);
}
.rf-field input {
  width: 100%; padding: 10px 14px; border-radius: 10px;
  border: 1px solid rgba(255, 255, 255, 0.15);
  background: rgba(255, 255, 255, 0.06);
  color: #fff; font-size: 14px; outline: none;
  box-sizing: border-box;
}
.rf-field input:focus { border-color: var(--primary); }

.rf-submit { width: 100%; padding: 12px; margin-top: 8px; font-size: 15px; }

/* Mobile */
@media (max-width: 720px) {
  .jukebox-container { padding-top: 80px; }
  .search-section, .request-section { padding: 18px; }
}
</style>
