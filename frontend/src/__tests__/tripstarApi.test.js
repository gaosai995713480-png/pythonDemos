import { beforeEach, describe, expect, it, vi } from 'vitest'

const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

let tripstarApi

beforeEach(async () => {
  vi.resetModules()
  mockFetch.mockReset()
  const api = await import('../api/index.js')
  tripstarApi = api.tripstarApi
})

describe('tripstarApi', () => {
  it('提交旅行规划任务到独立 TripStar 前缀', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ task_id: 'abc123', status: 'processing' }),
    })

    const payload = { city: '西安', start_date: '2026-06-01', end_date: '2026-06-03', travel_days: 3 }
    const result = await tripstarApi.createPlan(payload)

    expect(mockFetch).toHaveBeenCalledTimes(1)
    const [url, options] = mockFetch.mock.calls[0]
    expect(url).toBe('/api/tripstar/plan')
    expect(options.method).toBe('POST')
    expect(JSON.parse(options.body)).toEqual(payload)
    expect(result.task_id).toBe('abc123')
  })

  it('提交旅行规划失败时抛出后端错误，避免跳转到 undefined 任务', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 503,
      clone: () => ({
        json: () => Promise.resolve({ detail: 'TripStar 模块未启用' }),
      }),
      json: () => Promise.resolve({ detail: 'TripStar 模块未启用' }),
    })

    await expect(
      tripstarApi.createPlan({ city: '西安', start_date: '2026-06-01', end_date: '2026-06-02', travel_days: 2 }),
    ).rejects.toThrow('TripStar 模块未启用')
  })

  it('查询任务状态使用 task_id 路径', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ task_id: 'abc123', status: 'completed' }),
    })

    await tripstarApi.getStatus('abc123')

    expect(mockFetch).toHaveBeenCalledTimes(1)
    expect(mockFetch.mock.calls[0][0]).toBe('/api/tripstar/status/abc123')
  })

  it('读取 TripStar 前端地图配置', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ provider: 'amap', configured: true }),
    })

    const result = await tripstarApi.getMapConfig()

    expect(mockFetch).toHaveBeenCalledTimes(1)
    expect(mockFetch.mock.calls[0][0]).toBe('/api/tripstar/map/config')
    expect(result.configured).toBe(true)
  })

  it('调用后端高德地理编码接口时正确编码查询参数', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ item: { name: '钟楼' } }),
    })

    await tripstarApi.geocode({ city: '西安', keyword: '钟楼' })

    expect(mockFetch).toHaveBeenCalledTimes(1)
    expect(mockFetch.mock.calls[0][0]).toBe('/api/tripstar/map/geocode?city=%E8%A5%BF%E5%AE%89&keyword=%E9%92%9F%E6%A5%BC')
  })

  it('提交多点路线规划到 TripStar 地图接口', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ route: { distance_meters: 1600 } }),
    })

    const points = [
      { name: '钟楼', longitude: 108.940174, latitude: 34.341568 },
      { name: '城墙', longitude: 108.953493, latitude: 34.269036 },
    ]
    await tripstarApi.planRoute({ mode: 'walking', points })

    expect(mockFetch).toHaveBeenCalledTimes(1)
    const [url, options] = mockFetch.mock.calls[0]
    expect(url).toBe('/api/tripstar/map/route')
    expect(options.method).toBe('POST')
    expect(JSON.parse(options.body)).toEqual({ mode: 'walking', points })
  })

  it('查询小红书推荐时使用城市和关键词参数', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ items: [{ title: '武汉攻略' }] }),
    })

    await tripstarApi.searchXhs({ city: '武汉', keyword: '美食', limit: 4 })

    expect(mockFetch).toHaveBeenCalledTimes(1)
    expect(mockFetch.mock.calls[0][0]).toBe('/api/tripstar/xhs/search?city=%E6%AD%A6%E6%B1%89&keyword=%E7%BE%8E%E9%A3%9F&limit=4')
  })
})
