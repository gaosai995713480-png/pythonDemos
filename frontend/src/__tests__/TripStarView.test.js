import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'

const mockCreatePlan = vi.fn()
const mockGetStatus = vi.fn()
const mockPush = vi.fn()
const mockReplace = vi.fn()

vi.mock('../api/index.js', () => ({
  tripstarApi: {
    createPlan: (...args) => mockCreatePlan(...args),
    getStatus: (...args) => mockGetStatus(...args),
  },
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: mockPush, replace: mockReplace }),
}))

const flushPromises = async () => {
  await Promise.resolve()
  await Promise.resolve()
}

describe('TripStarView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sessionStorage.clear()
  })

  it('后端未返回 task_id 时显示错误，不跳转到 undefined 结果页', async () => {
    mockCreatePlan.mockResolvedValueOnce({ detail: 'TripStar 模块未启用' })

    const { default: TripStarView } = await import('../views/TripStarView.vue')
    const wrapper = mount(TripStarView, {
      global: {
        stubs: {
          TopBar: { template: '<div />' },
        },
      },
    })

    await wrapper.find('#tripstar-city-input').setValue('西安')
    const inputs = wrapper.findAll('input')
    await inputs[1].setValue('2026-06-01')
    await inputs[2].setValue('2026-06-02')
    await wrapper.find('form').trigger('submit.prevent')
    await flushPromises()

    expect(mockPush).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('TripStar 模块未启用')
  })

  it('提交成功后记录最近任务，避免线上误回主页面后丢失结果', async () => {
    mockCreatePlan.mockResolvedValueOnce({ task_id: 'task-online-001' })

    const { default: TripStarView } = await import('../views/TripStarView.vue')
    const wrapper = mount(TripStarView, {
      global: {
        stubs: {
          TopBar: { template: '<div />' },
        },
      },
    })

    await wrapper.find('#tripstar-city-input').setValue('武汉')
    const inputs = wrapper.findAll('input')
    await inputs[1].setValue('2026-06-18')
    await inputs[2].setValue('2026-06-18')
    await wrapper.find('form').trigger('submit.prevent')
    await flushPromises()

    expect(sessionStorage.getItem('tripstar.latestTaskId')).toBe('task-online-001')
    expect(mockPush).toHaveBeenCalledWith('/tripstar/result/task-online-001')
  })

  it('进入主页面时自动恢复最近仍存在的 TripStar 任务', async () => {
    sessionStorage.setItem('tripstar.latestTaskId', 'task-online-002')
    sessionStorage.setItem('tripstar.latestTaskExpireAt', String(Date.now() + 60_000))
    mockGetStatus.mockResolvedValueOnce({
      task_id: 'task-online-002',
      status: 'completed',
      progress: 100,
    })

    const { default: TripStarView } = await import('../views/TripStarView.vue')
    mount(TripStarView, {
      global: {
        stubs: {
          TopBar: { template: '<div />' },
        },
      },
    })

    await flushPromises()

    expect(mockGetStatus).toHaveBeenCalledWith('task-online-002')
    expect(mockReplace).toHaveBeenCalledWith('/tripstar/result/task-online-002')
  })

  it('规划页点击返回固定回到主界面，而不是沿历史记录回到结果页（避免两页互相弹跳）', async () => {
    const { default: TripStarView } = await import('../views/TripStarView.vue')
    const wrapper = mount(TripStarView, {
      global: {
        stubs: {
          TopBar: { template: '<button class="top-bar-back" @click="$emit(\'back\')" />' },
        },
      },
    })

    await wrapper.find('.top-bar-back').trigger('click')

    expect(mockPush).toHaveBeenCalledWith('/')
  })
})
