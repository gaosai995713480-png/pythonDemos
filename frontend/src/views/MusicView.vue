<script setup>
import { ref, computed, onMounted, watch, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import TopBar from '../components/TopBar.vue'
import GlassModal from '../components/GlassModal.vue'
import { useMusicStore } from '../stores/music'
import { musicApi } from '../api'

const router = useRouter()
const musicStore = useMusicStore()

const showAddModal = ref(false)
const searchKeyword = ref('')
const searchResults = ref([])
const searchLoading = ref(false)
const addById = ref('')
const addPlatform = ref('netease')
const lyricContainer = ref(null)

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
    searchResults.value = await musicApi.search(searchKeyword.value)
  } catch { searchResults.value = [] }
  searchLoading.value = false
}

async function addSong(song) {
  try {
    await musicApi.add({
      netease_id: song.id,
      title: song.name,
      artist: song.artist?.join?.(' / ') || song.artist || '',
      album: song.album || '',
      platform: addPlatform.value,
    })
    showAddModal.value = false
    musicStore.loadSongs()
  } catch { alert('添加失败') }
}

async function addSongById() {
  const id = addById.value.trim()
  if (!id) return
  try {
    await musicApi.add({ netease_id: id, platform: addPlatform.value })
    showAddModal.value = false
    addById.value = ''
    musicStore.loadSongs()
  } catch { alert('添加失败') }
}

async function removeSong(id) {
  if (!confirm('确定要删除这首歌吗？')) return
  try {
    await musicApi.remove(id)
    musicStore.loadSongs()
  } catch { /* ignore */ }
}

function playSong(index) { musicStore.play(index) }

function onProgressClick(e) {
  const rect = e.currentTarget.getBoundingClientRect()
  const pct = ((e.clientX - rect.left) / rect.width) * 100
  musicStore.seekTo(pct)
}

// 自动滚动歌词
watch(() => musicStore.currentLyricIndex, async (idx) => {
  if (idx < 0 || !lyricContainer.value) return
  await nextTick()
  const el = lyricContainer.value.querySelector('.lyric-active')
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' })
})

onMounted(() => musicStore.loadSongs())
</script>

<template>
  <TopBar title="🎵 音乐时光" @back="router.push('/')">
    <button class="btn-primary add-btn" @click="showAddModal = true">+ 添加歌曲</button>
  </TopBar>

  <div class="music-container">
    <!-- Player Card -->
    <div class="player-card" v-if="musicStore.currentSong">
      <div class="disc" :class="{ spinning: musicStore.isPlaying }">
        <div class="disc-inner">🎵</div>
      </div>
      <div class="song-info">
        <div class="song-title">{{ musicStore.currentSong.title }}</div>
        <div class="song-artist">{{ musicStore.currentSong.artist }}</div>
        <div class="song-platform">{{ musicStore.currentPlatformName }}</div>
      </div>
      <div class="controls">
        <button class="ctrl-btn" @click="musicStore.prev">⏮</button>
        <button class="ctrl-btn play-btn" @click="musicStore.togglePlay">{{ musicStore.isPlaying ? '⏸' : '▶' }}</button>
        <button class="ctrl-btn" @click="musicStore.next">⏭</button>
      </div>
      <div class="progress-wrap" @click="onProgressClick">
        <div class="progress-bar" :style="{ width: (musicStore.duration ? (musicStore.currentTime / musicStore.duration * 100) : 0) + '%' }"></div>
      </div>
      <div class="time-row">
        <span>{{ musicStore.fmtTime(musicStore.currentTime) }}</span>
        <span>{{ musicStore.fmtTime(musicStore.duration) }}</span>
      </div>
    </div>

    <!-- Lyrics -->
    <div class="lyrics-card" v-if="musicStore.lyricLines.length" ref="lyricContainer">
      <p
        v-for="(line, i) in musicStore.lyricLines"
        :key="i"
        class="lyric-line"
        :class="{ 'lyric-active': i === musicStore.currentLyricIndex }"
      >{{ line.text }}</p>
    </div>

    <!-- Song List -->
    <div class="song-list">
      <div
        v-for="(song, i) in musicStore.songs"
        :key="song.id"
        class="song-item"
        :class="{ 'is-playing': i === musicStore.currentIndex }"
        @click="playSong(i)"
      >
        <div class="song-num">{{ i + 1 }}</div>
        <div class="song-meta">
          <div class="song-name">{{ song.title }}</div>
          <div class="song-detail">{{ song.artist }}</div>
        </div>
        <button class="song-del" @click.stop="removeSong(song.id)">✕</button>
      </div>
    </div>
  </div>

  <!-- Add Modal -->
  <GlassModal v-model="showAddModal" title="🎵 添加歌曲">
    <div class="platform-row">
      <button
        v-for="p in platforms"
        :key="p.value"
        class="plat-btn"
        :class="{ 'is-active': addPlatform === p.value }"
        @click="addPlatform = p.value"
      >{{ p.label }}</button>
    </div>
    <!-- Search -->
    <div class="search-row">
      <input v-model="searchKeyword" placeholder="搜索歌曲名..." @keydown.enter="searchSongs" />
      <button class="btn-primary" @click="searchSongs" :disabled="searchLoading">搜索</button>
    </div>
    <div class="search-results" v-if="searchResults.length">
      <div
        v-for="r in searchResults"
        :key="r.id"
        class="search-item"
        @click="addSong(r)"
      >
        <div class="sr-title">{{ r.name }}</div>
        <div class="sr-artist">{{ r.artist?.join?.(' / ') || r.artist }}</div>
      </div>
    </div>
    <!-- Or by ID -->
    <div class="divider">或直接输入歌曲 ID</div>
    <div class="search-row">
      <input v-model="addById" placeholder="输入歌曲ID" />
      <button class="btn-primary" @click="addSongById">添加</button>
    </div>
  </GlassModal>
</template>

<style scoped>
.add-btn { margin-left: auto; font-size: 14px; padding: 8px 18px; }

.music-container { max-width: 600px; margin: 0 auto; padding: 90px 20px 60px; }

.player-card {
  background: var(--glass-bg); backdrop-filter: blur(26px);
  border: 1px solid var(--glass-border); border-radius: 24px;
  padding: 30px; text-align: center; margin-bottom: 24px;
  box-shadow: 0 12px 40px rgba(0, 0, 0, 0.3);
}

.disc {
  width: 100px; height: 100px; border-radius: 50%; margin: 0 auto 16px;
  background: linear-gradient(135deg, rgba(255, 107, 157, 0.3), rgba(196, 69, 105, 0.3));
  border: 3px solid rgba(255, 255, 255, 0.15);
  display: flex; align-items: center; justify-content: center;
}

.disc.spinning { animation: spin 8s linear infinite; }
.disc-inner { font-size: 36px; }

.song-title { font-size: 20px; font-weight: 700; margin-bottom: 4px; }
.song-artist { font-size: 14px; color: var(--text-secondary); }
.song-platform { font-size: 12px; color: var(--accent); margin-top: 4px; }

.controls { display: flex; justify-content: center; gap: 20px; margin: 20px 0; }
.ctrl-btn { width: 44px; height: 44px; border-radius: 50%; border: none; background: rgba(255, 255, 255, 0.1); color: #fff; font-size: 18px; cursor: pointer; transition: all 0.2s; display: flex; align-items: center; justify-content: center; }
.ctrl-btn:hover { background: rgba(255, 255, 255, 0.2); transform: scale(1.1); }
.play-btn { width: 56px; height: 56px; background: linear-gradient(135deg, var(--primary), var(--secondary)); font-size: 22px; box-shadow: 0 4px 16px rgba(255, 107, 157, 0.3); }

.progress-wrap { width: 100%; height: 6px; border-radius: 3px; background: rgba(255, 255, 255, 0.1); cursor: pointer; margin: 8px 0; }
.progress-bar { height: 100%; border-radius: 3px; background: linear-gradient(90deg, var(--primary), var(--accent)); transition: width 0.1s; }
.time-row { display: flex; justify-content: space-between; font-size: 12px; color: var(--text-secondary); }

/* Lyrics */
.lyrics-card {
  background: var(--glass-bg); backdrop-filter: blur(20px);
  border: 1px solid var(--glass-border); border-radius: 20px;
  padding: 24px; margin-bottom: 24px; max-height: 300px; overflow-y: auto;
  text-align: center;
}

.lyric-line { padding: 8px; font-size: 14px; color: rgba(255, 255, 255, 0.4); transition: all 0.3s; }
.lyric-active { color: var(--accent); font-size: 16px; font-weight: 600; transform: scale(1.05); }

/* Song List */
.song-list { display: flex; flex-direction: column; gap: 8px; }
.song-item {
  display: flex; align-items: center; gap: 14px; padding: 14px 16px;
  border-radius: 14px; background: var(--glass-bg); backdrop-filter: blur(16px);
  border: 1px solid var(--glass-border); cursor: pointer; transition: all 0.2s;
}
.song-item:hover { background: rgba(255, 255, 255, 0.12); }
.song-item.is-playing { border-color: var(--primary); box-shadow: 0 0 12px rgba(255, 107, 157, 0.2); }
.song-num { width: 24px; text-align: center; font-size: 13px; color: var(--text-secondary); }
.song-meta { flex: 1; }
.song-name { font-size: 15px; font-weight: 600; }
.song-detail { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }
.song-del { width: 28px; height: 28px; border-radius: 50%; border: none; background: transparent; color: rgba(255, 255, 255, 0.3); font-size: 14px; cursor: pointer; opacity: 0; transition: all 0.2s; display: flex; align-items: center; justify-content: center; }
.song-item:hover .song-del { opacity: 1; }
.song-del:hover { background: rgba(255, 80, 80, 0.25); color: #fff; }

/* Modal content */
.platform-row { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
.plat-btn { padding: 6px 14px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.15); background: transparent; color: var(--text-secondary); font-size: 13px; cursor: pointer; transition: all 0.2s; }
.plat-btn.is-active { background: rgba(255, 255, 255, 0.15); color: #fff; border-color: var(--primary); }
.search-row { display: flex; gap: 8px; margin-bottom: 12px; }
.search-row input { flex: 1; padding: 10px 14px; border-radius: 10px; border: 1px solid rgba(255, 255, 255, 0.2); background: rgba(255, 255, 255, 0.06); color: #fff; font-size: 14px; outline: none; }
.search-row input:focus { border-color: var(--primary); }
.search-row .btn-primary { padding: 10px 18px; }
.search-results { max-height: 200px; overflow-y: auto; margin-bottom: 16px; }
.search-item { padding: 10px 14px; border-radius: 10px; cursor: pointer; transition: background 0.15s; }
.search-item:hover { background: rgba(255, 255, 255, 0.08); }
.sr-title { font-size: 14px; font-weight: 600; }
.sr-artist { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }
.divider { text-align: center; font-size: 12px; color: rgba(255, 255, 255, 0.35); margin: 16px 0; position: relative; }
.divider::before, .divider::after { content: ''; position: absolute; top: 50%; width: 30%; height: 1px; background: rgba(255, 255, 255, 0.1); }
.divider::before { left: 0; }
.divider::after { right: 0; }
</style>
