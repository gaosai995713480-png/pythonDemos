import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'

const mockListUsers = vi.fn()
const mockGetInviteCode = vi.fn()
const mockListKeys = vi.fn()
const mockSaveKey = vi.fn()
const mockPush = vi.fn()
const mockReplace = vi.fn()

vi.mock('../api/index.js', () => ({
  usersApi: {
    list: (...args) => mockListUsers(...args),
    getInviteCode: (...args) => mockGetInviteCode(...args),
    toggle: vi.fn(),
    updateInviteCode: vi.fn(),
  },
  configApi: {
    listKeys: (...args) => mockListKeys(...args),
    saveKey: (...args) => mockSaveKey(...args),
  },
}))

vi.mock('../stores/auth', () => ({
  useAuthStore: () => ({
    isAdmin: true,
  }),
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({
    push: mockPush,
    replace: mockReplace,
    back: vi.fn(),
  }),
}))

const flushPromises = async () => {
  await Promise.resolve()
  await Promise.resolve()
}

describe('UsersView 配置管理', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockListUsers.mockResolvedValue([])
    mockGetInviteCode.mockResolvedValue({ code: 'love2023' })
    mockListKeys.mockResolvedValue({
      items: [
        {
          key: 'TRIPSTAR_AMAP_WEB_KEY',
          label: 'TripStar 高德 Web 服务 Key',
          value: '',
          masked_value: 'abcd****1234',
          has_value: true,
          is_secret: true,
        },
      ],
    })
    mockSaveKey.mockResolvedValue({ ok: true, key: 'TRIPSTAR_XHS_COOKIE' })
  })

  it('管理员可以在用户管理页新增 love_config key', async () => {
    const { default: UsersView } = await import('../views/UsersView.vue')
    const wrapper = mount(UsersView, {
      global: {
        stubs: {
          TopBar: { template: '<div><slot /></div>' },
        },
      },
    })

    await flushPromises()

    expect(wrapper.text()).toContain('系统配置')
    expect(wrapper.text()).toContain('TRIPSTAR_AMAP_WEB_KEY')

    await wrapper.find('[data-test="add-config-key"]').trigger('click')
    await wrapper.find('[data-test="config-key-input"]').setValue('TRIPSTAR_XHS_COOKIE')
    await wrapper.find('[data-test="config-value-input"]').setValue('cookie-value')
    await wrapper.find('[data-test="save-config-key"]').trigger('click')
    await flushPromises()

    expect(mockSaveKey).toHaveBeenCalledWith({
      key: 'TRIPSTAR_XHS_COOKIE',
      value: 'cookie-value',
    })
    expect(mockListKeys).toHaveBeenCalledTimes(2)
  })
})
