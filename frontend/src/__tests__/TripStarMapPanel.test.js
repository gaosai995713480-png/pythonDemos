import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'

const mockGetMapConfig = vi.fn()

vi.mock('../api/index.js', () => ({
  tripstarApi: {
    getMapConfig: (...args) => mockGetMapConfig(...args),
  },
}))

const flushPromises = async () => {
  await Promise.resolve()
  await Promise.resolve()
}

const plan = {
  city: '西安',
  map_center: { longitude: 108.939621, latitude: 34.343147 },
  days: [
    {
      day: 1,
      title: '古城初见',
      attractions: [
        {
          name: '钟楼',
          location: { longitude: 108.940174, latitude: 34.341568 },
        },
        {
          name: '西安城墙',
          location: { longitude: 108.953493, latitude: 34.269036 },
        },
      ],
    },
  ],
  map_routes: [
    {
      day: 1,
      polyline: [
        [108.940174, 34.341568],
        [108.953493, 34.269036],
      ],
    },
  ],
}

describe('TripStarMapPanel', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.clearAllMocks()
    delete window.AMap
    delete window._AMapSecurityConfig
    document.getElementById('tripstar-amap-js-sdk')?.remove()
  })

  afterEach(() => {
    delete window.AMap
    delete window._AMapSecurityConfig
    document.getElementById('tripstar-amap-js-sdk')?.remove()
  })

  it('配置完整时加载高德地图并渲染 marker 和路线', async () => {
    mockGetMapConfig.mockResolvedValueOnce({
      provider: 'amap',
      configured: true,
      amap_web_js_key: 'web-js-key',
      amap_security_js_code: 'security-code',
    })

    const add = vi.fn()
    const setFitView = vi.fn()
    const destroy = vi.fn()
    const MapCtor = vi.fn(function () {
      this.add = add
      this.setFitView = setFitView
      this.destroy = destroy
    })
    const MarkerCtor = vi.fn(function (options) {
      this.options = options
    })
    const PolylineCtor = vi.fn(function (options) {
      this.options = options
    })
    window.AMap = {
      Map: MapCtor,
      Marker: MarkerCtor,
      Polyline: PolylineCtor,
    }

    const { default: TripStarMapPanel } = await import('../components/tripstar/TripStarMapPanel.vue')
    const wrapper = mount(TripStarMapPanel, { props: { plan } })

    await flushPromises()

    expect(mockGetMapConfig).toHaveBeenCalledTimes(1)
    expect(window._AMapSecurityConfig.securityJsCode).toBe('security-code')
    expect(MapCtor).toHaveBeenCalledTimes(1)
    expect(MarkerCtor).toHaveBeenCalledTimes(2)
    expect(MarkerCtor.mock.calls[0][0].label.content).toContain('tripstar-amap-label')
    expect(MarkerCtor.mock.calls[0][0].label.content).toContain('钟楼')
    expect(PolylineCtor).toHaveBeenCalledTimes(1)
    expect(setFitView).toHaveBeenCalledTimes(1)
    expect(wrapper.text()).toContain('TripStar 地图')
    expect(wrapper.text()).toContain('钟楼')
    expect(wrapper.text()).toContain('地图路线')
  })

  it('前端地图配置缺失时显示明确提示，不进入无限加载', async () => {
    mockGetMapConfig.mockResolvedValueOnce({
      provider: 'amap',
      configured: false,
      amap_web_js_key: '',
      amap_security_js_code: '',
      message: 'VITE_TRIPSTAR_AMAP_WEB_JS_KEY 未配置或仍是占位值',
    })

    const { default: TripStarMapPanel } = await import('../components/tripstar/TripStarMapPanel.vue')
    const wrapper = mount(TripStarMapPanel, { props: { plan } })

    await flushPromises()

    expect(wrapper.text()).toContain('VITE_TRIPSTAR_AMAP_WEB_JS_KEY 未配置或仍是占位值')
    expect(wrapper.text()).not.toContain('正在加载高德地图')
  })

  it('SDK 脚本已加载但未初始化时显示加载失败，而不是误报需要配置', async () => {
    vi.useFakeTimers()
    mockGetMapConfig.mockResolvedValueOnce({
      provider: 'amap',
      configured: true,
      amap_web_js_key: 'web-js-key',
      amap_security_js_code: 'security-code',
    })

    const { default: TripStarMapPanel } = await import('../components/tripstar/TripStarMapPanel.vue')
    const wrapper = mount(TripStarMapPanel, { props: { plan } })

    await flushPromises()
    const script = document.getElementById('tripstar-amap-js-sdk')
    expect(script).toBeTruthy()
    script.dispatchEvent(new Event('load'))
    await vi.advanceTimersByTimeAsync(12000)
    await flushPromises()

    expect(wrapper.text()).toContain('加载失败')
    expect(wrapper.text()).not.toContain('需要配置')
    expect(wrapper.text()).toContain('请检查高德 Web端 Key')
    vi.useRealTimers()
  })

  it('通过高德 callback 初始化 SDK 后再渲染地图', async () => {
    vi.useFakeTimers()
    mockGetMapConfig.mockResolvedValueOnce({
      provider: 'amap',
      configured: true,
      amap_web_js_key: 'web-js-key',
      amap_security_js_code: 'security-code',
    })

    const add = vi.fn()
    const setFitView = vi.fn()
    const MapCtor = vi.fn(function () {
      this.add = add
      this.setFitView = setFitView
      this.destroy = vi.fn()
    })
    const MarkerCtor = vi.fn(function (options) {
      this.options = options
    })
    const PolylineCtor = vi.fn(function (options) {
      this.options = options
    })

    const { default: TripStarMapPanel } = await import('../components/tripstar/TripStarMapPanel.vue')
    mount(TripStarMapPanel, { props: { plan } })

    await flushPromises()
    const script = document.getElementById('tripstar-amap-js-sdk')
    expect(script.src).toContain('callback=__tripstarAmapReady')

    window.AMap = {
      Map: MapCtor,
      Marker: MarkerCtor,
      Polyline: PolylineCtor,
    }
    window.__tripstarAmapReady()
    await flushPromises()

    expect(MapCtor).toHaveBeenCalledTimes(1)
    expect(MarkerCtor).toHaveBeenCalledTimes(2)
    expect(PolylineCtor).toHaveBeenCalledTimes(1)
    vi.useRealTimers()
  })

  it('配置换成新 JS Key 后会替换页面残留的旧 SDK 脚本', async () => {
    vi.useFakeTimers()
    mockGetMapConfig.mockResolvedValueOnce({
      provider: 'amap',
      configured: true,
      amap_web_js_key: 'new-web-js-key',
      amap_security_js_code: 'new-security-code',
    })
    const oldScript = document.createElement('script')
    oldScript.id = 'tripstar-amap-js-sdk'
    oldScript.src = 'https://webapi.amap.com/maps?v=2.0&key=old-web-js-key&callback=__tripstarAmapReady'
    oldScript.dataset.tripstarAmapKey = 'old-web-js-key'
    document.head.appendChild(oldScript)

    const { default: TripStarMapPanel } = await import('../components/tripstar/TripStarMapPanel.vue')
    mount(TripStarMapPanel, { props: { plan } })

    await flushPromises()

    const script = document.getElementById('tripstar-amap-js-sdk')
    expect(script).toBeTruthy()
    expect(script).not.toBe(oldScript)
    expect(script.src).toContain('key=new-web-js-key')
    expect(script.dataset.tripstarAmapKey).toBe('new-web-js-key')
    vi.useRealTimers()
  })
})
