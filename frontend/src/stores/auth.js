import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { authApi } from '../api'
import { useMusicStore } from './music'

export const useAuthStore = defineStore('auth', () => {
  const authenticated = ref(false)
  const checking = ref(true)
  const username = ref('')
  const role = ref('')
  const isAdmin = computed(() => role.value === 'admin')

  async function checkAuth() {
    checking.value = true
    try {
      const data = await authApi.status()
      authenticated.value = !!data.authenticated
      username.value = data.username || ''
      role.value = data.role || ''
    } catch {
      authenticated.value = false
      username.value = ''
      role.value = ''
    } finally {
      checking.value = false
    }
  }

  async function login(user, pass) {
    const data = await authApi.login(user, pass)
    if (data.ok) {
      authenticated.value = true
      username.value = data.username
      role.value = data.role
    }
    return data
  }

  async function logout() {
    await authApi.logout()
    useMusicStore().reset()
    authenticated.value = false
    username.value = ''
    role.value = ''
  }

  return { authenticated, checking, username, role, isAdmin, checkAuth, login, logout }
})
