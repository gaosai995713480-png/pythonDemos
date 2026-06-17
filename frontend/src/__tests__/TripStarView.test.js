import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'

const mockCreatePlan = vi.fn()
const mockPush = vi.fn()

vi.mock('../api/index.js', () => ({
  tripstarApi: {
    createPlan: (...args) => mockCreatePlan(...args),
  },
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: mockPush }),
}))

const flushPromises = async () => {
  await Promise.resolve()
  await Promise.resolve()
}

describe('TripStarView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
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
})
