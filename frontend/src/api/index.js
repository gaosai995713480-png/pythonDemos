/**
 * 统一 API 封装层
 * - 所有请求经过统一处理
 * - 401 自动跳转登录页
 */
import { useRouter } from 'vue-router'

const BASE = ''

async function request(url, options = {}) {
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
  return res
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

// 上传文件（非 JSON）
async function uploadFile(url, file, fileName) {
  const data = await file.arrayBuffer()
  const res = await fetch(`${BASE}${url}`, {
    method: 'POST',
    headers: { 'X-File-Name': encodeURIComponent(fileName) },
    body: data,
  })
  if (res.status === 401) {
    window.location.replace('/login')
    throw new Error('unauthorized')
  }
  return res.json()
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
  login: (password) => post('/auth/login', { password }),
  logout: () => post('/auth/logout', {}),
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
  list: () => get('/photos.json'),
  upload: (file, fileName) => uploadFile('/photos/upload-file', file, fileName),
  importZip: async (file) => {
    const data = await file.arrayBuffer()
    const res = await fetch(`${BASE}/photos/import`, {
      method: 'POST',
      body: data,
    })
    if (res.status === 401) {
      window.location.replace('/login')
      throw new Error('unauthorized')
    }
    return res.json()
  },
}

export const weatherApi = {
  weather: (city, extensions = 'base') =>
    get(`/api/weather?city=${city}&extensions=${extensions}`),
  district: (keywords, subdistrict = 1) =>
    get(`/api/weather/district?keywords=${encodeURIComponent(keywords)}&subdistrict=${subdistrict}`),
  locate: () => get('/api/weather/locate'),
}
