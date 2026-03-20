import { defineStore } from 'pinia'
import { ref, computed, markRaw } from 'vue'
import { musicApi } from '../api'

export const useMusicStore = defineStore('music', () => {
  const songs = ref([])
  const currentIndex = ref(-1)
  const isPlaying = ref(false)
  const lyricLines = ref([])
  const currentLyricIndex = ref(-1)
  const currentTime = ref(0)
  const duration = ref(0)

  // 使用 markRaw 避免 Vue 对 Audio 做响应式代理
  const audio = markRaw(new Audio())
  audio.preload = 'auto'

  const PLATFORM_NAMES = {
    netease: '网易云', tencent: 'QQ音乐',
    kugou: '酷狗', kuwo: '酷我', baidu: '千千',
  }

  const currentSong = computed(() =>
    currentIndex.value >= 0 && currentIndex.value < songs.value.length
      ? songs.value[currentIndex.value]
      : null
  )

  const currentPlatformName = computed(() =>
    currentSong.value ? (PLATFORM_NAMES[currentSong.value.platform] || currentSong.value.platform) : ''
  )

  // 解析 LRC 歌词
  function parseLRC(lrcText) {
    if (!lrcText) return []
    const lines = []
    const regex = /\[(\d{1,2}):(\d{2})(?:[.:](\d{1,3}))?\](.*)/
    lrcText.split('\n').forEach(line => {
      const match = line.match(regex)
      if (match) {
        const min = parseInt(match[1])
        const sec = parseInt(match[2])
        const ms = match[3] ? parseInt(match[3].padEnd(3, '0')) : 0
        const time = min * 60 + sec + ms / 1000
        const text = match[4].trim()
        if (text) lines.push({ time, text })
      }
    })
    lines.sort((a, b) => a.time - b.time)
    return lines
  }

  // Audio 事件
  audio.addEventListener('timeupdate', () => {
    if (!audio.duration) return
    currentTime.value = audio.currentTime
    updateLyricHighlight(audio.currentTime)
  })

  audio.addEventListener('loadedmetadata', () => {
    duration.value = audio.duration
  })

  audio.addEventListener('ended', () => {
    next()
  })

  function updateLyricHighlight(time) {
    if (lyricLines.value.length === 0) return
    let idx = -1
    for (let i = lyricLines.value.length - 1; i >= 0; i--) {
      if (time >= lyricLines.value[i].time) { idx = i; break }
    }
    currentLyricIndex.value = idx
  }

  async function loadSongs() {
    try {
      songs.value = await musicApi.list()
      if (songs.value.length > 0 && currentIndex.value < 0) {
        currentIndex.value = 0
      }
    } catch (e) {
      console.warn('加载歌单失败', e)
    }
  }

  async function loadLyrics(songId, platform) {
    lyricLines.value = []
    currentLyricIndex.value = -1
    try {
      const data = await musicApi.lyric(songId, platform || 'netease')
      lyricLines.value = parseLRC(data.lyric || '')
    } catch (e) {
      console.warn('歌词加载失败', e)
    }
  }

  async function play(index) {
    if (index < 0 || index >= songs.value.length) return
    currentIndex.value = index
    const s = songs.value[index]
    loadLyrics(s.netease_id, s.platform || 'netease')
    try {
      const data = await musicApi.url(s.netease_id, s.platform || 'netease')
      if (data.url) {
        audio.src = data.url
        await audio.play()
        isPlaying.value = true
      } else {
        isPlaying.value = false
      }
    } catch (e) {
      isPlaying.value = false
    }
  }

  function togglePlay() {
    if (!songs.value.length) return
    if (isPlaying.value) {
      audio.pause()
      isPlaying.value = false
    } else {
      if (currentIndex.value < 0) {
        play(0)
      } else {
        audio.play().catch(() => {})
        isPlaying.value = true
      }
    }
  }

  function next() {
    if (songs.value.length === 0) return
    play((currentIndex.value + 1) % songs.value.length)
  }

  function prev() {
    if (songs.value.length === 0) return
    play((currentIndex.value - 1 + songs.value.length) % songs.value.length)
  }

  function seekTo(percent) {
    if (audio.duration) {
      audio.currentTime = (percent / 100) * audio.duration
    }
  }

  function fmtTime(s) {
    if (!s || !isFinite(s)) return '0:00'
    const m = Math.floor(s / 60)
    const sec = Math.floor(s % 60)
    return m + ':' + (sec < 10 ? '0' : '') + sec
  }

  return {
    songs, currentIndex, isPlaying, lyricLines, currentLyricIndex,
    currentTime, duration, currentSong, currentPlatformName,
    audio, PLATFORM_NAMES,
    loadSongs, loadLyrics, play, togglePlay, next, prev,
    seekTo, fmtTime,
  }
})
