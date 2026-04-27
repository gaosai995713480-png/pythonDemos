import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'

const mockRecipeList = vi.fn()
const mockCategories = vi.fn()
const mockDetail = vi.fn()
const mockUpdateState = vi.fn()
const mockAddRecord = vi.fn()
const mockRandom = vi.fn()
const mockMenus = vi.fn()
const mockCreateMenu = vi.fn()
const mockAddMenuItem = vi.fn()
const mockCompleteMenu = vi.fn()
const mockRemoveMenuItem = vi.fn()

vi.mock('../api/index.js', () => ({
  recipeApi: {
    list: (...args) => mockRecipeList(...args),
    categories: (...args) => mockCategories(...args),
    detail: (...args) => mockDetail(...args),
    updateState: (...args) => mockUpdateState(...args),
    addRecord: (...args) => mockAddRecord(...args),
    random: (...args) => mockRandom(...args),
  },
  cookingApi: {
    menus: (...args) => mockMenus(...args),
    createMenu: (...args) => mockCreateMenu(...args),
    addMenuItem: (...args) => mockAddMenuItem(...args),
    completeMenu: (...args) => mockCompleteMenu(...args),
    removeMenuItem: (...args) => mockRemoveMenuItem(...args),
  },
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({
    push: vi.fn(),
  }),
}))

const flushPromises = async () => {
  await Promise.resolve()
  await Promise.resolve()
}

describe('CookbookView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockRecipeList.mockResolvedValue({
      items: [
        {
          id: 1,
          title: '番茄炒蛋',
          category: 'vegetable_dish',
          description: '家常菜',
          difficulty: 'easy',
          cook_time_minutes: 15,
          tags: ['番茄', '鸡蛋'],
          is_favorite: false,
          want_to_cook: false,
          cooked_count: 0,
        },
      ],
      total: 1,
      page: 1,
      page_size: 20,
    })
    mockCategories.mockResolvedValue({
      items: [{ category: 'vegetable_dish', count: 1 }],
    })
    mockDetail.mockResolvedValue({
      id: 1,
      title: '番茄炒蛋',
      ingredients: ['鸡蛋', '番茄'],
      steps: ['打蛋', '翻炒'],
      tips: '少放盐',
      user_state: { is_favorite: false, want_to_cook: false, cooked_count: 0 },
    })
    mockUpdateState.mockResolvedValue({ ok: true })
    mockAddRecord.mockResolvedValue({ ok: true, id: 9 })
    mockRandom.mockResolvedValue({ id: 1, title: '番茄炒蛋' })
    mockMenus.mockResolvedValue({ items: [] })
    mockCreateMenu.mockResolvedValue({ ok: true, id: 3 })
    mockAddMenuItem.mockResolvedValue({ ok: true, id: 4 })
    mockCompleteMenu.mockResolvedValue({ ok: true })
    mockRemoveMenuItem.mockResolvedValue({ ok: true })
  })

  it('加载菜谱库并展示 HowToCook 集成来源说明', async () => {
    const { default: CookbookView } = await import('../views/CookbookView.vue')
    const wrapper = mount(CookbookView)

    await flushPromises()

    expect(mockRecipeList).toHaveBeenCalledWith({
      keyword: '',
      category: '',
      difficulty: '',
      only_favorite: false,
      only_want_to_cook: false,
      only_cooked: false,
      page: 1,
      page_size: 20,
    })
    expect(wrapper.text()).toContain('我们的小厨房')
    expect(wrapper.text()).toContain('番茄炒蛋')
    expect(wrapper.text()).toContain('HowToCook')
  })

  it('点击收藏会更新菜谱状态并刷新列表', async () => {
    const { default: CookbookView } = await import('../views/CookbookView.vue')
    const wrapper = mount(CookbookView)
    await flushPromises()

    await wrapper.find('[data-test="favorite-1"]').trigger('click')
    await flushPromises()

    expect(mockUpdateState).toHaveBeenCalledWith(1, {
      is_favorite: true,
      want_to_cook: false,
      rating: undefined,
      note: '',
    })
    expect(mockRecipeList).toHaveBeenCalledTimes(2)
  })

  it('能创建纪念日菜单', async () => {
    const { default: CookbookView } = await import('../views/CookbookView.vue')
    const wrapper = mount(CookbookView)
    await flushPromises()

    await wrapper.find('[data-test="tab-menus"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="menu-title"]').setValue('纪念日晚餐')
    await wrapper.find('[data-test="create-menu"]').trigger('submit')
    await flushPromises()

    expect(mockMenus).toHaveBeenCalled()
    expect(mockCreateMenu).toHaveBeenCalledWith({
      title: '纪念日晚餐',
      menu_date: '',
      description: '',
    })
  })

  it('随机接口没有返回菜谱 id 时不会继续请求 undefined 详情', async () => {
    mockRandom.mockResolvedValueOnce({ detail: '没有可推荐的菜谱' })
    const { default: CookbookView } = await import('../views/CookbookView.vue')
    const wrapper = mount(CookbookView)
    await flushPromises()

    const randomButton = wrapper.findAll('button').find((button) => button.text().includes('随机一道菜'))
    await randomButton.trigger('click')
    await flushPromises()

    expect(mockRandom).toHaveBeenCalledTimes(1)
    expect(mockDetail).not.toHaveBeenCalledWith(undefined)
    expect(wrapper.text()).toContain('没有可推荐的菜谱')
  })

  it('打开菜谱详情时展示可加入菜单并在菜单页展示菜品明细', async () => {
    mockMenus.mockResolvedValue({
      items: [
        {
          id: 3,
          title: '纪念日晚餐',
          menu_date: '2026-05-20',
          description: '一起做饭',
          status: 'planned',
          items: [{ id: 7, recipe_id: 1, title: '番茄炒蛋', sort_order: 0, note: '主菜' }],
        },
      ],
    })
    const { default: CookbookView } = await import('../views/CookbookView.vue')
    const wrapper = mount(CookbookView)
    await flushPromises()

    await wrapper.find('.recipe-card').trigger('click')
    await flushPromises()

    expect(mockMenus).toHaveBeenCalled()
    expect(wrapper.text()).toContain('加入 纪念日晚餐')

    await wrapper.find('[data-test="tab-menus"]').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('番茄炒蛋')
    await wrapper.find('[data-test="complete-menu-3"]').trigger('click')
    await wrapper.find('[data-test="remove-menu-item-3-7"]').trigger('click')
    await flushPromises()

    expect(mockCompleteMenu).toHaveBeenCalledWith(3)
    expect(mockRemoveMenuItem).toHaveBeenCalledWith(3, 7)
  })
})
