/**
 * lyricFx store 单元测试：首页歌词漂浮效果偏好
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useLyricFxStore } from '../stores/lyricFx'

describe('useLyricFxStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
  })

  it('默认使用整卡轻浮', () => {
    const store = useLyricFxStore()

    expect(store.currentKey).toBe('float')
    expect(store.cssClass).toBe('fx-float')
    expect(store.isPerChar).toBe(false)
  })

  it('apply 切换效果并写入 localStorage', () => {
    const store = useLyricFxStore()

    store.apply('wave')

    expect(store.currentKey).toBe('wave')
    expect(store.cssClass).toBe('fx-wave')
    expect(store.isPerChar).toBe(true)
    expect(localStorage.getItem('love_lyric_fx')).toBe('wave')
  })

  it('apply 忽略未知效果，保持原状且不落盘', () => {
    const store = useLyricFxStore()

    store.apply('不存在的效果')

    expect(store.currentKey).toBe('float')
    expect(localStorage.getItem('love_lyric_fx')).toBeNull()
  })

  it('关闭时不输出效果 class', () => {
    const store = useLyricFxStore()

    store.apply('none')

    expect(store.cssClass).toBe('')
    expect(store.isPerChar).toBe(false)
  })

  it('init 恢复上次选择', () => {
    localStorage.setItem('love_lyric_fx', 'dream')
    const store = useLyricFxStore()

    store.init()

    expect(store.currentKey).toBe('dream')
    expect(store.isPerChar).toBe(true)
  })

  it('init 遇到脏数据时回退到默认值', () => {
    localStorage.setItem('love_lyric_fx', 'garbage')
    const store = useLyricFxStore()

    store.init()

    expect(store.currentKey).toBe('float')
  })
})
