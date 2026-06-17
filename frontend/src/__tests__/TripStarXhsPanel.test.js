import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'

const mockSearchXhs = vi.fn()

vi.mock('../api/index.js', () => ({
  tripstarApi: {
    searchXhs: (...args) => mockSearchXhs(...args),
  },
}))

const flushPromises = async () => {
  await Promise.resolve()
  await Promise.resolve()
}

const plan = {
  city: '武汉',
  preferences: ['历史文化', '本地美食'],
  days: [
    {
      day: 1,
      attractions: [{ name: '黄鹤楼' }, { name: '户部巷' }],
    },
  ],
}

describe('TripStarXhsPanel', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.clearAllMocks()
  })

  it('根据城市和偏好加载小红书推荐并展示笔记卡片', async () => {
    mockSearchXhs.mockResolvedValueOnce({
      query: '武汉 历史文化 本地美食 黄鹤楼',
      items: [
        {
          id: 'note-1',
          title: '武汉三天两夜避坑攻略',
          desc: '黄鹤楼和户部巷可以放在同一天，晚上去江汉路。',
          liked_count: 128,
          note_url: 'https://www.xiaohongshu.com/explore/note-1',
          author: { nickname: '旅行薯' },
        },
      ],
    })

    const { default: TripStarXhsPanel } = await import('../components/tripstar/TripStarXhsPanel.vue')
    const wrapper = mount(TripStarXhsPanel, { props: { plan } })

    await flushPromises()

    expect(mockSearchXhs).toHaveBeenCalledTimes(1)
    expect(mockSearchXhs.mock.calls[0][0]).toEqual({
      city: '武汉',
      keyword: '历史文化 本地美食 黄鹤楼 户部巷',
      limit: 6,
    })
    expect(wrapper.text()).toContain('小红书推荐')
    expect(wrapper.text()).toContain('武汉三天两夜避坑攻略')
    expect(wrapper.text()).toContain('旅行薯')
  })

  it('小红书接口失败时显示可读错误，不阻塞行程结果', async () => {
    mockSearchXhs.mockRejectedValueOnce(new Error('TripStar 小红书 Cookie 未配置'))

    const { default: TripStarXhsPanel } = await import('../components/tripstar/TripStarXhsPanel.vue')
    const wrapper = mount(TripStarXhsPanel, { props: { plan } })

    await flushPromises()

    expect(wrapper.text()).toContain('小红书推荐暂不可用')
    expect(wrapper.text()).toContain('TripStar 小红书 Cookie 未配置')
  })
})
