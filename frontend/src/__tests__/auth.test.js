/**
 * auth store 单元测试
 * TDD: 验证 logout 时统一重置音乐状态
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

// mock API
vi.mock('../api/index.js', () => ({
  authApi: {
    status: vi.fn().mockResolvedValue({ authenticated: true }),
    login: vi.fn().mockResolvedValue({ ok: true }),
    logout: vi.fn().mockResolvedValue({ ok: true }),
  },
  musicApi: {
    list: vi.fn().mockResolvedValue([]),
    url: vi.fn().mockResolvedValue({ url: '' }),
    lyric: vi.fn().mockResolvedValue({ lyric: '' }),
  },
}))

import { useAuthStore } from '../stores/auth'
import { useMusicStore } from '../stores/music'

describe('useAuthStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('logout', () => {
    it('退出登录时重置音乐状态', async () => {
      const authStore = useAuthStore()
      const musicStore = useMusicStore()
      authStore.authenticated = true
      musicStore.isPlaying = true
      musicStore.currentIndex = 3

      await authStore.logout()

      expect(authStore.authenticated).toBe(false)
      expect(musicStore.isPlaying).toBe(false)
      expect(musicStore.currentIndex).toBe(-1)
    })
  })
})
