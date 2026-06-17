import { beforeEach, describe, expect, it, vi, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'

const mockGetStatus = vi.fn()
const mockGetMapConfig = vi.fn()
const mockSearchXhs = vi.fn()
const mockPush = vi.fn()

vi.mock('../api/index.js', () => ({
  tripstarApi: {
    getStatus: (...args) => mockGetStatus(...args),
    getMapConfig: (...args) => mockGetMapConfig(...args),
    searchXhs: (...args) => mockSearchXhs(...args),
  },
}))

vi.mock('vue-router', () => ({
  useRoute: () => ({ params: { taskId: 'task-001' } }),
  useRouter: () => ({ push: mockPush }),
}))

const flushPromises = async () => {
  await Promise.resolve()
  await Promise.resolve()
}

describe('TripStarResultView', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.clearAllMocks()
    mockGetMapConfig.mockResolvedValue({
      provider: 'amap',
      configured: false,
      amap_web_js_key: '',
      amap_security_js_code: '',
    })
    mockSearchXhs.mockResolvedValue({ query: '西安', items: [] })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('任务完成后停止轮询，避免状态闭环空转', async () => {
    mockGetStatus
      .mockResolvedValueOnce({
        task_id: 'task-001',
        status: 'processing',
        progress: 45,
        message: '正在规划路线...',
      })
      .mockResolvedValueOnce({
        task_id: 'task-001',
        status: 'completed',
        progress: 100,
        message: '旅行计划生成成功',
        result: {
          success: true,
          data: {
            city: '西安',
            travel_days: 2,
            overview: '西安两日游',
            days: [
              {
                day: 1,
                title: '古城初见',
                summary: '城墙与钟鼓楼',
                attractions: [{ name: '西安城墙', duration: '2小时' }],
              },
            ],
            budget: {
              total_estimate: '1200-1800元/人',
              items: [{ category: '餐饮', amount: '300元/人' }],
            },
          },
        },
      })

    const { default: TripStarResultView } = await import('../views/TripStarResultView.vue')
    const wrapper = mount(TripStarResultView, {
      global: {
        stubs: {
          TopBar: { template: '<div><slot /></div>' },
        },
      },
    })

    await flushPromises()
    expect(mockGetStatus).toHaveBeenCalledTimes(1)
    expect(wrapper.text()).toContain('正在规划路线')

    await vi.advanceTimersByTimeAsync(1000)
    await flushPromises()

    expect(mockGetStatus).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).toContain('西安')
    expect(wrapper.text()).toContain('古城初见')

    await vi.advanceTimersByTimeAsync(3000)
    await flushPromises()

    expect(mockGetStatus).toHaveBeenCalledTimes(2)
  })

  it('点击结果页返回时清理最近任务标记，避免主动返回后又被自动恢复', async () => {
    sessionStorage.setItem('tripstar.latestTaskId', 'task-001')
    sessionStorage.setItem('tripstar.latestTaskExpireAt', String(Date.now() + 60_000))
    mockGetStatus.mockResolvedValueOnce({
      task_id: 'task-001',
      status: 'completed',
      progress: 100,
      message: '旅行计划生成成功',
      result: {
        success: true,
        data: {
          city: '西安',
          travel_days: 1,
          overview: '西安一日游',
          days: [],
          budget: { items: [] },
        },
      },
    })

    const { default: TripStarResultView } = await import('../views/TripStarResultView.vue')
    const wrapper = mount(TripStarResultView, {
      global: {
        stubs: {
          TopBar: {
            template: '<button id="topbar-back" @click="$emit(\'back\')">返回</button>',
          },
        },
      },
    })

    await flushPromises()
    await wrapper.find('#topbar-back').trigger('click')

    expect(sessionStorage.getItem('tripstar.latestTaskId')).toBeNull()
    expect(mockPush).toHaveBeenCalledWith('/tripstar')
  })
})
