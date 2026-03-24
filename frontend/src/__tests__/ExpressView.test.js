import { beforeEach, describe, expect, it, vi, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'

const mockCompanies = vi.fn()
const mockDetect = vi.fn()
const mockQuery = vi.fn()
const mockGetConfig = vi.fn()
const mockUpdateConfig = vi.fn()
const mockPush = vi.fn()

vi.mock('../api/index.js', () => ({
  expressApi: {
    companies: (...args) => mockCompanies(...args),
    detect: (...args) => mockDetect(...args),
    query: (...args) => mockQuery(...args),
    getConfig: (...args) => mockGetConfig(...args),
    updateConfig: (...args) => mockUpdateConfig(...args),
  },
}))

vi.mock('../stores/auth.js', () => ({
  useAuthStore: () => ({
    isAdmin: false,
  }),
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({
    push: mockPush,
  }),
}))

const flushPromises = async () => {
  await Promise.resolve()
  await Promise.resolve()
}

describe('ExpressView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useRealTimers()
    localStorage.clear()
    mockCompanies.mockResolvedValue([
      { code: 'shunfeng', name: '顺丰速运' },
      { code: 'zhongtong', name: '中通快递' },
    ])
    mockDetect.mockResolvedValue({ auto: [] })
    mockQuery.mockResolvedValue({ status: '200', message: 'ok', data: [] })
    mockGetConfig.mockResolvedValue({ customer_configured: false, key_configured: false })
    mockUpdateConfig.mockResolvedValue({ ok: true, updated: 1 })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('点击历史记录时会恢复手机号并带入查询', async () => {
    localStorage.setItem('express_history', JSON.stringify([
      {
        num: 'SF1234567890',
        com: 'shunfeng',
        comName: '顺丰速运',
        phone: '1234',
        time: '2026/03/24 20:00:00',
      },
    ]))

    const { default: ExpressView } = await import('../views/ExpressView.vue')
    const wrapper = mount(ExpressView, {
      global: {
        stubs: {
          TopBar: { template: '<div><slot /></div>' },
        },
      },
    })

    await flushPromises()
    await wrapper.find('.history-item').trigger('click')
    await flushPromises()

    expect(mockQuery).toHaveBeenCalledWith('SF1234567890', 'shunfeng', '1234')
  })

  it('单号缩短到 6 位以下时会立即结束识别中状态', async () => {
    vi.useFakeTimers()

    const { default: ExpressView } = await import('../views/ExpressView.vue')
    const wrapper = mount(ExpressView, {
      global: {
        stubs: {
          TopBar: { template: '<div><slot /></div>' },
        },
      },
    })

    await flushPromises()

    const trackingInput = wrapper.find('#express-num-input')
    await trackingInput.setValue('123456')
    await flushPromises()
    expect(wrapper.find('.input-suffix').exists()).toBe(true)

    await trackingInput.setValue('12345')
    await flushPromises()

    expect(wrapper.find('.input-suffix').exists()).toBe(false)
  })
})
