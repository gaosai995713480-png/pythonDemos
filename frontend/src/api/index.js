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
    if (!res.ok) {
      // 尝试读取后端返回的具体错误信息
      const data = await res.clone().json().catch(() => ({}))
      const msg = data.error || data.detail || ''
      const message = msg || `请求失败 (${res.status})`
      if (res.status === 403) {
        const { error } = useToast()
        error(msg || '权限不足')
      } else {
        // 400/409/500 等：优先展示后端返回的具体原因
        const { error } = useToast()
        error(message)
      }
      const apiError = new Error(message)
      apiError.isApiError = true
      throw apiError
    }
    return res
  } catch (e) {
    if (e.message !== 'unauthorized' && !e.isApiError) {
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
  login: async (username, password) => {
    // login 也不走通用 request()：登录失败本身就是 401，
    // 通用层会 replace 回 /login 整页刷新，导致错误提示永远显示不出来
    try {
      const res = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })
      return await res.json()
    } catch {
      return { error: '网络错误，请检查连接' }
    }
  },
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
  upload: (file, fileName) => uploadFile('/api/map/upload', file, fileName),
  cleanupUploads: (names) => post('/api/map/upload/cleanup', { names }),
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

// 首页背景音乐：管理员设置，所有登录用户共享同一首
export const bgmApi = {
  get: () => get('/api/music/bgm'),
  set: (data) => put('/api/music/bgm', data),
  clear: () => del('/api/music/bgm'),
  upload: (file) => uploadFile('/api/music/bgm/upload', file, file.name),
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
  delete: (filename) => del(`/photos/${encodeURIComponent(filename)}`),
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
  listKeys: () => get('/api/config/keys'),
  saveKey: (data) => post('/api/config/keys', data),
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

export const tripstarApi = {
  health: () => get('/api/tripstar/health'),
  createPlan: (data) => post('/api/tripstar/plan', data),
  getStatus: (taskId) => get(`/api/tripstar/status/${encodeURIComponent(taskId)}`),
  history: (limit = 10) => get(`/api/tripstar/history?limit=${limit}`),
  getMapConfig: () => get('/api/tripstar/map/config'),
  geocode: ({ city, keyword }) => get(`/api/tripstar/map/geocode${toQuery({ city, keyword })}`),
  searchPoi: ({ city, keyword, limit = 10 }) => get(`/api/tripstar/map/poi${toQuery({ city, keyword, limit })}`),
  planRoute: (data) => post('/api/tripstar/map/route', data),
  getXhsStatus: () => get('/api/tripstar/xhs/status'),
  searchXhs: ({ city, keyword = '', limit = 6 }) => get(`/api/tripstar/xhs/search${toQuery({ city, keyword, limit })}`),
}

function toQuery(params = {}) {
  const search = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return
    search.set(key, String(value))
  })
  const query = search.toString()
  return query ? `?${query}` : ''
}

export const recipeApi = {
  list: (params = {}) => get(`/api/recipes${toQuery(params)}`),
  categories: () => get('/api/recipes/categories'),
  detail: (id) => get(`/api/recipes/${id}`),
  random: (params = {}) => get(`/api/recipes/random${toQuery(params)}`),
  updateState: (id, data) => post(`/api/recipes/${id}/state`, data),
  addRecord: (id, data) => post(`/api/recipes/${id}/records`, data),
  records: (id) => get(`/api/recipes/${id}/records`),
}

export const cookingApi = {
  records: () => get('/api/cooking/records'),
  menus: () => get('/api/cooking/menus'),
  createMenu: (data) => post('/api/cooking/menus', data),
  addMenuItem: (menuId, data) => post(`/api/cooking/menus/${menuId}/items`, data),
  completeMenu: (menuId) => post(`/api/cooking/menus/${menuId}/complete`, {}),
  removeMenuItem: (menuId, itemId) => del(`/api/cooking/menus/${menuId}/items/${itemId}`),
}

export const aiApi = {
  status: () => get('/api/ai/status'),
  getConfig: () => get('/api/ai/config'),
  updateConfig: (data) => post('/api/ai/config', data),
}
