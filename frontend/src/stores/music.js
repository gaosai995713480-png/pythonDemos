import { defineStore } from 'pinia'
import { ref, computed, markRaw } from 'vue'
import { musicApi, bgmApi } from '../api'

export const useMusicStore = defineStore('music', () => {
  const songs = ref([])
  const currentIndex = ref(-1)
  const isPlaying = ref(false)
  const lyricLines = ref([])
  const currentLyricIndex = ref(-1)
  const currentTime = ref(0)
  const duration = ref(0)
  const playError = ref('')  // B1: 播放失败时展示错误信息
  const bgm = ref(null)          // 首页背景音乐配置（管理员设置，全局共享）
  const bgmBlocked = ref(false)  // 浏览器拦截了自动播放，需要用户点一下

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
    playError.value = ''
    audio.loop = false  // 歌单按顺序播放，清掉 BGM 留下的循环标记
    loadLyrics(s.netease_id, s.platform || 'netease')
    try {
      const data = await musicApi.url(s.netease_id, s.platform || 'netease')
      if (data.url) {
        audio.src = data.url
        // B5: 统一 try/catch 处理浏览器播放拒绝
        try {
          await audio.play()
          isPlaying.value = true
        } catch {
          isPlaying.value = false
          playError.value = '浏览器阻止自动播放，请手动点击播放'
        }
      } else {
        // B1: 播放链接获取失败给用户反馈
        isPlaying.value = false
        playError.value = '该歌曲暂无播放源'
      }
    } catch (e) {
      isPlaying.value = false
      playError.value = '播放请求失败'
    }
  }

  // ===== 首页背景音乐 =====

  // 进入首页时调用：拉取管理员设置的 BGM 并循环播放。
  // 复用同一个 audio 实例，保证首页 BGM 和音乐页播放器不会同时出声。
  async function startBgm() {
    if (isPlaying.value) return  // 音乐页已经在放歌，不打断
    try {
      const data = await bgmApi.get()
      bgm.value = data.enabled ? data : null
    } catch {
      bgm.value = null
      return
    }
    if (!bgm.value) return

    currentIndex.value = -1
    playError.value = ''
    if (bgm.value.source === 'meting' && bgm.value.song_id) {
      loadLyrics(bgm.value.song_id, bgm.value.platform || 'netease')
    } else {
      lyricLines.value = []
      currentLyricIndex.value = -1
    }

    audio.src = bgm.value.url
    audio.loop = true
    try {
      await audio.play()
      isPlaying.value = true
      bgmBlocked.value = false
    } catch (e) {
      // NotAllowedError = 浏览器自动播放策略拦截，点一下即可；
      // 其他错误（NotSupportedError/AbortError）说明音频源本身有问题，必须暴露出来
      console.warn('[BGM] 自动播放失败:', e.name, e.message, '音频源:', bgm.value.url)
      isPlaying.value = false
      bgmBlocked.value = true
      if (e.name !== 'NotAllowedError') {
        playError.value = `音频加载失败（${e.name}）`
      }
    }
  }

  // 用户点击「播放」后重试，用于绕过自动播放拦截
  async function resumeBgm() {
    if (!bgm.value) return
    try {
      await audio.play()
      isPlaying.value = true
      bgmBlocked.value = false
    } catch {
      isPlaying.value = false
      playError.value = '播放失败，请重试'
    }
  }

  function togglePlay() {
    if (isPlaying.value) {
      audio.pause()
      isPlaying.value = false
      return
    }
    // 当前播的是首页 BGM（不属于歌单）时，恢复它而不是去放歌单第一首
    if (bgm.value && currentIndex.value < 0) {
      resumeBgm()
      return
    }
    if (!songs.value.length) return
    if (currentIndex.value < 0) {
      play(0).catch(() => {
        isPlaying.value = false
        playError.value = '播放请求失败'
      })
    } else {
      // B2: await play() 并 catch，确保状态同步
      audio.play().then(() => {
        isPlaying.value = true
      }).catch(() => {
        isPlaying.value = false
        playError.value = '播放失败，请重试'
      })
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

  // B4: 删除歌曲后修正 currentIndex
  function handleSongRemoved(removedIndex) {
    if (songs.value.length === 0) {
      // 歌单清空
      currentIndex.value = -1
      audio.pause()
      audio.src = ''
      isPlaying.value = false
      lyricLines.value = []
      return
    }
    if (removedIndex === currentIndex.value) {
      // 删除的是当前播放的歌，播下一首
      const nextIdx = currentIndex.value >= songs.value.length
        ? 0 : currentIndex.value
      play(nextIdx)
    } else if (removedIndex < currentIndex.value) {
      // 删除的在当前之前，index 前移
      currentIndex.value--
    }
  }

  function fmtTime(s) {
    if (!s || !isFinite(s)) return '0:00'
    const m = Math.floor(s / 60)
    const sec = Math.floor(s % 60)
    return m + ':' + (sec < 10 ? '0' : '') + sec
  }

  function reset() {
    audio.pause()
    audio.src = ''
    audio.loop = false
    isPlaying.value = false
    currentIndex.value = -1
    currentTime.value = 0
    duration.value = 0
    lyricLines.value = []
    currentLyricIndex.value = -1
    playError.value = ''
    bgm.value = null
    bgmBlocked.value = false
  }

  return {
    songs, currentIndex, isPlaying, lyricLines, currentLyricIndex,
    currentTime, duration, currentSong, currentPlatformName,
    playError, bgm, bgmBlocked,
    audio, PLATFORM_NAMES,
    loadSongs, loadLyrics, play, togglePlay, next, prev,
    startBgm, resumeBgm,
    seekTo, fmtTime, handleSongRemoved, reset,
  }
})
