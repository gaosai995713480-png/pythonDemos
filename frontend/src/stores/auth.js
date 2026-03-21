import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { authApi } from '../api'
import { useMusicStore } from './music'

export const useAuthStore = defineStore('auth', () => {
  const authenticated = ref(false)
  const checking = ref(true)

  async function checkAuth() {
    checking.value = true
    try {
      const data = await authApi.status()
      authenticated.value = !!data.authenticated
    } catch {
      authenticated.value = false
    } finally {
      checking.value = false
    }
  }

  async function login(password) {
    const data = await authApi.login(password)
    if (data.ok) {
      authenticated.value = true
    }
    return data
  }

  async function logout() {
    await authApi.logout()
    // 全局熄灯：重置所有 Store
    useMusicStore().reset()
    authenticated.value = false
  }

  return { authenticated, checking, checkAuth, login, logout }
})
