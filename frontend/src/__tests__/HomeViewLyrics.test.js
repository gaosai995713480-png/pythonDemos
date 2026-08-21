/**
 * HomeView 歌词漂浮效果接入测试
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { reactive } from 'vue'
import { mount } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'

const musicState = reactive({
  currentLyricIndex: 0,
  lyricLines: [{ text: '我怀念的' }],
  isPlaying: false,
  bgmBlocked: false,
  bgm: null,
  startBgm: vi.fn(),
  togglePlay: vi.fn(),
})

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}))

vi.mock('../stores/music', () => ({
  useMusicStore: () => musicState,
}))

vi.mock('../stores/auth', () => ({
  useAuthStore: () => ({ isAdmin: false, logout: vi.fn() }),
}))

const STUBS = {
  DanmuBar: { template: '<div />' },
  WeatherCard: { template: '<div />' },
  CapsuleSection: { template: '<div />' },
  NavSidebar: { template: '<div />' },
  ThemeSwitcher: { template: '<div />' },
  LyricFxSwitcher: { template: '<div class="fx-stub" />' },
}

async function mountHome() {
  const { default: HomeView } = await import('../views/HomeView.vue')
  return mount(HomeView, { global: { stubs: STUBS } })
}

describe('HomeView 歌词漂浮效果', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    musicState.currentLyricIndex = 0
  })

  it('默认整卡轻浮：漂浮层带 fx-float，歌词整行渲染', async () => {
    const wrapper = await mountHome()

    const float = wrapper.find('.lyrics-float')
    expect(float.classes()).toContain('fx-float')
    expect(float.find('.lyrics').text()).toBe('我怀念的')
    expect(wrapper.findAll('.lyric-char')).toHaveLength(0)
  })

  it('逐字方案把歌词拆成带序号的单字', async () => {
    localStorage.setItem('love_lyric_fx', 'wave')
    const { useLyricFxStore } = await import('../stores/lyricFx')
    useLyricFxStore().init()

    const wrapper = await mountHome()

    const chars = wrapper.findAll('.lyric-char')
    expect(chars).toHaveLength(4)
    expect(chars[0].text()).toBe('我')
    expect(chars[3].attributes('style')).toContain('--i: 3')
    expect(wrapper.find('.lyrics-float').classes()).toContain('fx-wave')
  })

  it('关闭效果时漂浮层不带任何 fx- 类', async () => {
    const { useLyricFxStore } = await import('../stores/lyricFx')
    useLyricFxStore().apply('none')

    const wrapper = await mountHome()

    const classes = wrapper.find('.lyrics-float').classes()
    expect(classes.some(c => c.startsWith('fx-'))).toBe(false)
  })

  it('没有歌词时不渲染漂浮层', async () => {
    musicState.currentLyricIndex = -1

    const wrapper = await mountHome()

    expect(wrapper.find('.lyrics-float').exists()).toBe(false)
  })
})
