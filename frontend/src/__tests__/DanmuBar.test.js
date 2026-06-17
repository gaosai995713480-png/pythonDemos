import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'

const mockList = vi.fn()
const mockLike = vi.fn()
const mockSend = vi.fn()
let setIntervalSpy
let clearIntervalSpy
const BASE_INTERVAL_MS = 1500
const RESUME_INTERVAL_MS = 2700
const RESUME_WARMUP_MS = 4000

vi.mock('../api/index.js', () => ({
  danmuApi: {
    list: (...args) => mockList(...args),
    like: (...args) => mockLike(...args),
    send: (...args) => mockSend(...args),
  },
}))

const flushPromises = async () => {
  await Promise.resolve()
  await Promise.resolve()
}

function setVisibility(state) {
  Object.defineProperty(document, 'visibilityState', {
    configurable: true,
    get: () => state,
  })
  Object.defineProperty(document, 'hidden', {
    configurable: true,
    get: () => state === 'hidden',
  })
  document.dispatchEvent(new Event('visibilitychange'))
}

describe('DanmuBar', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
    setIntervalSpy = vi.spyOn(globalThis, 'setInterval')
    clearIntervalSpy = vi.spyOn(globalThis, 'clearInterval')
    mockList.mockResolvedValue([
      { id: 1, text: '第一条弹幕', likes: 0 },
      { id: 2, text: '第二条弹幕', likes: 0 },
      { id: 3, text: '第三条弹幕', likes: 0 },
    ])
    mockLike.mockResolvedValue({ ok: true, likes: 1, liked: true })
    mockSend.mockResolvedValue({ ok: true, id: 999 })
    setVisibility('visible')
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
    document.body.innerHTML = ''
  })

  it('页面隐藏时暂停弹幕并清空旧弹幕，恢复可见后先低密度暖启动再恢复正常速度', async () => {
    const { default: DanmuBar } = await import('../components/DanmuBar.vue')
    const wrapper = mount(DanmuBar, { attachTo: document.body })

    await flushPromises()

    expect(setIntervalSpy).toHaveBeenCalledTimes(1)
    expect(setIntervalSpy.mock.calls[0][1]).toBe(BASE_INTERVAL_MS)

    const layer = wrapper.find('#danmu-layer').element
    layer.appendChild(document.createElement('div'))
    layer.appendChild(document.createElement('div'))
    expect(layer.children.length).toBe(2)

    setVisibility('hidden')
    expect(clearIntervalSpy).toHaveBeenCalledTimes(1)
    expect(layer.children.length).toBe(0)

    setVisibility('visible')
    expect(setIntervalSpy).toHaveBeenCalledTimes(2)
    expect(setIntervalSpy.mock.calls[1][1]).toBe(RESUME_INTERVAL_MS)

    await vi.advanceTimersByTimeAsync(RESUME_WARMUP_MS)
    expect(setIntervalSpy).toHaveBeenCalledTimes(3)
    expect(setIntervalSpy.mock.calls[2][1]).toBe(BASE_INTERVAL_MS)

    wrapper.unmount()
  })
})
