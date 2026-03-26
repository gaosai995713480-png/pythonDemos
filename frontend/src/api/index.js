/**
 * 统一 API 封装层
 * - 所有请求经过统一处理
 * - 401 自动跳转登录页
 * - 非 401 错误自动 Toast 提示
 */
import { useToast } from '../composables/useToast'

const BASE = ''

async function request(url, options = {}) {
  try {
    const res = await fetch(`${BASE}${url}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    })
    if (res.status === 401) {
      window.location.replace('/login')
      throw new Error('unauthorized')
    }
    if (res.status === 403) {
      const data = await res.clone().json().catch(() => ({}))
      const { error } = useToast()
      error(data.detail || data.error || '权限不足')
    }
    if (!res.ok && res.status !== 403) {
      const { error } = useToast()
      error(`请求失败 (${res.status})`)
    }
    return res
  } catch (e) {
    if (e.message !== 'unauthorized') {
      const { error } = useToast()
      error('网络错误，请检查连接')
    }
    throw e
  }
}

async function get(url) {
  const res = await request(url)
  return res.json()
}

async function post(url, body) {
  const res = await request(url, {
    method: 'POST',
    body: JSON.stringify(body),
  })
  return res.json()
}

async function put(url, body) {
  const res = await request(url, {
    method: 'PUT',
    body: JSON.stringify(body),
  })
  return res.json()
}

async function del(url) {
  const res = await request(url, { method: 'DELETE' })
  return res.json()
}

async function readJsonSafe(res) {
  return res.json().catch(() => ({}))
}

async function handlePhotoResponse(res) {
  if (res.status === 401) {
    window.location.replace('/login')
    throw new Error('unauthorized')
  }
  const data = await readJsonSafe(res)
  if (res.status === 403) {
    const { error } = useToast()
    const message = data.detail || data.error || '权限不足'
    error(message)
    throw new Error(message)
  }
  if (!res.ok) {
    const { error } = useToast()
    const message = data.detail || data.error || `请求失败 (${res.status})`
    error(message)
    throw new Error(message)
  }
  return data
}

// 上传文件（非 JSON）
async function uploadFile(url, file, fileName) {
  const data = await file.arrayBuffer()
  const res = await fetch(`${BASE}${url}`, {
    method: 'POST',
    headers: { 'X-File-Name': encodeURIComponent(fileName) },
    body: data,
  })
  return handlePhotoResponse(res)
}

// ===== 各模块 API =====

export const authApi = {
  // status 不走通用 request()，避免 401 触发 window.location.replace 导致无限刷新
  status: async () => {
    try {
      const res = await fetch('/auth/status', {
        headers: { 'Content-Type': 'application/json' },
      })
      if (res.ok) return res.json()
      return { authenticated: false }
    } catch {
      return { authenticated: false }
    }
  },
  login: (username, password) => post('/auth/login', { username, password }),
  register: (username, password, invite_code) => post('/auth/register', { username, password, invite_code }),
  logout: () => post('/auth/logout', {}),
}

export const usersApi = {
  list: () => get('/api/users'),
  toggle: (id) => post(`/api/users/${id}/toggle`, {}),
  getInviteCode: () => get('/api/users/invite-code'),
  updateInviteCode: (code) => post('/api/users/invite-code', { code }),
}

export const danmuApi = {
  list: (limit = 50) => get(`/danmu?limit=${limit}`),
  send: (text) => post('/danmu', { text }),
  like: (id) => post('/danmu/like', { id }),
}

export const timelineApi = {
  list: () => get('/api/timeline'),
  create: (data) => post('/api/timeline', data),
  remove: (id) => del(`/api/timeline?id=${id}`),
}

export const capsuleApi = {
  list: () => get('/api/capsules'),
  create: (data) => post('/api/capsules', data),
  open: (id) => post('/api/capsules/open', { id }),
}

export const moodApi = {
  list: (year, month) => get(`/api/mood?year=${year}&month=${month}`),
  save: (data) => post('/api/mood', data),
}

export const wishApi = {
  list: () => get('/api/wishes'),
  create: (data) => post('/api/wishes', data),
}

export const mapApi = {
  list: () => get('/api/map'),
  create: (data) => post('/api/map', data),
  update: (data) => put('/api/map', data),
  remove: (id) => del(`/api/map?id=${id}`),
}

export const musicApi = {
  list: () => get('/api/music'),
  add: (data) => post('/api/music', data),
  remove: (id) => del(`/api/music?id=${id}`),
  search: (keyword, platform = 'netease', limit = 8) =>
    get(`/api/music/search?keyword=${encodeURIComponent(keyword)}&platform=${platform}&limit=${limit}`),
  url: (id, platform = 'netease') =>
    get(`/api/music/url?id=${id}&platform=${platform}`),
  lyric: (id, platform = 'netease') =>
    get(`/api/music/lyric?id=${id}&platform=${platform}`),
}

export const photoApi = {
  list: async () => {
    const res = await fetch(`${BASE}/photos.json`)
    return handlePhotoResponse(res)
  },
  upload: (file, fileName) => uploadFile('/photos/upload-file', file, fileName),
  importZip: async (file) => {
    const data = await file.arrayBuffer()
    const res = await fetch(`${BASE}/photos/import`, {
      method: 'POST',
      body: data,
    })
    return handlePhotoResponse(res)
  },
}

export const galleryApi = {
  verify: (password) => post('/api/gallery/verify', { password }),
}

export const weatherApi = {
  weather: (city, extensions = 'base') =>
    get(`/api/weather?city=${city}&extensions=${extensions}`),
  district: (keywords, subdistrict = 1) =>
    get(`/api/weather/district?keywords=${encodeURIComponent(keywords)}&subdistrict=${subdistrict}`),
  locate: () => get('/api/weather/locate'),
}

export const configApi = {
  getCookies: () => get('/api/config/cookies'),
  updateCookies: (data) => post('/api/config/cookies', data),
}

export const jukeboxApi = {
  list: (limit = 50) => get(`/api/jukebox?limit=${limit}`),
  create: (data) => post('/api/jukebox', data),
  like: (id) => post('/api/jukebox/like', { id }),
  adopt: (id) => post('/api/jukebox/adopt', { id }),
  remove: (id) => del(`/api/jukebox?id=${id}`),
}

export const expressApi = {
  query: (num, com, phone = '') =>
    get(`/api/express/query?num=${encodeURIComponent(num)}&com=${encodeURIComponent(com)}&phone=${encodeURIComponent(phone)}`),
  detect: (num) =>
    get(`/api/express/detect?num=${encodeURIComponent(num)}`),
  companies: () => get('/api/express/companies'),
  getConfig: () => get('/api/express/config'),
  updateConfig: (data) => post('/api/express/config', data),
}

export const aiApi = {
  status: () => get('/api/ai/status'),
  getConfig: () => get('/api/ai/config'),
  updateConfig: (data) => post('/api/ai/config', data),
}

