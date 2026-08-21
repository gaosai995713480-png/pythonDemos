import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

/**
 * 首页歌词漂浮效果。
 * perChar 为 true 的效果需要把歌词按字拆成 span 才能逐字错峰动画。
 */
const EFFECTS = [
  { key: 'none', name: '关闭', emoji: '⏹️', desc: '歌词静止' },
  { key: 'float', name: '整卡轻浮', emoji: '🫧', desc: '卡片整体缓慢上下浮动' },
  { key: 'wave', name: '逐字波浪', emoji: '🌊', desc: '每个字依次起伏', perChar: true },
  { key: 'drift', name: '自由漂浮', emoji: '🎐', desc: '脱开卡片，文字发光漂移' },
  { key: 'bubble', name: '气泡上升', emoji: '🎈', desc: '换句时从下方浮上来' },
  { key: 'dream', name: '梦幻组合', emoji: '✨', desc: '漂移 + 逐字波浪', perChar: true },
]

const STORAGE_KEY = 'love_lyric_fx'

export const useLyricFxStore = defineStore('lyricFx', () => {
  const currentKey = ref('float')
  const effects = EFFECTS

  const current = computed(() => EFFECTS.find(e => e.key === currentKey.value) || EFFECTS[0])
  const isPerChar = computed(() => !!current.value.perChar)
  // 关闭时不加 class，避免 HomeView 里出现无意义的空效果类
  const cssClass = computed(() => (currentKey.value === 'none' ? '' : `fx-${currentKey.value}`))

  function init() {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved && EFFECTS.some(e => e.key === saved)) currentKey.value = saved
  }

  function apply(key) {
    if (!EFFECTS.some(e => e.key === key)) return
    currentKey.value = key
    localStorage.setItem(STORAGE_KEY, key)
  }

  return { currentKey, effects, current, isPerChar, cssClass, init, apply }
})
