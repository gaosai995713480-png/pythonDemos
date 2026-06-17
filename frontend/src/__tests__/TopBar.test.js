import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'

const mockBack = vi.fn()
const mockPush = vi.fn()

vi.mock('vue-router', () => ({
  useRouter: () => ({
    back: mockBack,
    push: mockPush,
  }),
}))

describe('TopBar', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('没有自定义 back 监听时点击返回执行默认路由返回', async () => {
    const { default: TopBar } = await import('../components/TopBar.vue')
    const wrapper = mount(TopBar, {
      props: { title: '旅行星辰' },
      global: {
        stubs: {
          ThemeSwitcher: { template: '<div />' },
        },
      },
    })

    await wrapper.find('.back-btn').trigger('click')

    expect(mockBack).toHaveBeenCalledTimes(1)
  })

  it('有自定义 back 监听时只触发父组件逻辑，不重复路由返回', async () => {
    const onBack = vi.fn()
    const { default: TopBar } = await import('../components/TopBar.vue')
    const wrapper = mount(TopBar, {
      props: { title: '旅行星辰', onBack },
      global: {
        stubs: {
          ThemeSwitcher: { template: '<div />' },
        },
      },
    })

    await wrapper.find('.back-btn').trigger('click')

    expect(onBack).toHaveBeenCalledTimes(1)
    expect(mockBack).not.toHaveBeenCalled()
  })
})
