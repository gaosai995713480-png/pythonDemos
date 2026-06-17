const TASK_KEY = 'tripstar.latestTaskId'
const EXPIRE_KEY = 'tripstar.latestTaskExpireAt'
const DEFAULT_TTL_MS = 2 * 60 * 60 * 1000

function storage() {
  try {
    return window.sessionStorage
  } catch {
    return null
  }
}

export function rememberTripStarTask(taskId, ttlMs = DEFAULT_TTL_MS) {
  const id = String(taskId || '').trim()
  if (!id) return
  const target = storage()
  if (!target) return
  target.setItem(TASK_KEY, id)
  target.setItem(EXPIRE_KEY, String(Date.now() + ttlMs))
}

export function getRememberedTripStarTask() {
  const target = storage()
  if (!target) return ''
  const id = target.getItem(TASK_KEY) || ''
  const expireAt = Number(target.getItem(EXPIRE_KEY) || 0)
  if (!id) return ''
  if (expireAt && expireAt < Date.now()) {
    clearRememberedTripStarTask()
    return ''
  }
  return id
}

export function clearRememberedTripStarTask() {
  const target = storage()
  if (!target) return
  target.removeItem(TASK_KEY)
  target.removeItem(EXPIRE_KEY)
}
