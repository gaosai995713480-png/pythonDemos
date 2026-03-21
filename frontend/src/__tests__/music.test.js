/**
 * music store 单元测试
 * TDD: 先写测试 → 确认失败 → 写实现 → 确认通过
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useMusicStore } from '../stores/music'

describe('useMusicStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('reset', () => {
    it('重置所有播放状态', () => {
      const store = useMusicStore()
      // 模拟播放中状态
      store.isPlaying = true
      store.currentIndex = 2
      store.currentTime = 120
      store.duration = 300
      store.playError = '测试错误'

      store.reset()

      expect(store.isPlaying).toBe(false)
      expect(store.currentIndex).toBe(-1)
      expect(store.currentTime).toBe(0)
      expect(store.duration).toBe(0)
      expect(store.lyricLines).toEqual([])
      expect(store.currentLyricIndex).toBe(-1)
      expect(store.playError).toBe('')
    })
  })
})
