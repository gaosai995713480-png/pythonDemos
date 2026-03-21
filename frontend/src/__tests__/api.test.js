/**
 * API 层单元测试
 * 测试 request、get、post 等基础函数的行为
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// mock fetch
const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

// 动态导入以确保 mock 生效
let danmuApi, authApi

beforeEach(async () => {
  vi.resetModules()
  mockFetch.mockReset()
  const api = await import('../api/index.js')
  danmuApi = api.danmuApi
  authApi = api.authApi
})

describe('danmuApi', () => {
  describe('list', () => {
    it('发送 GET 请求获取弹幕列表', async () => {
      const mockData = [
        { id: 1, text: '测试弹幕', likes: 5 },
        { id: 2, text: '另一条', likes: 0 },
      ]
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockData),
      })

      const result = await danmuApi.list(50)

      expect(mockFetch).toHaveBeenCalledTimes(1)
      const [url] = mockFetch.mock.calls[0]
      expect(url).toBe('/danmu?limit=50')
      expect(result).toEqual(mockData)
    })
  })

  describe('like', () => {
    it('发送 POST 请求进行点赞', async () => {
      const mockResponse = { ok: true, id: 1, likes: 6, liked: true }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockResponse),
      })

      const result = await danmuApi.like(1)

      expect(mockFetch).toHaveBeenCalledTimes(1)
      const [url, options] = mockFetch.mock.calls[0]
      expect(url).toBe('/danmu/like')
      expect(options.method).toBe('POST')
      expect(JSON.parse(options.body)).toEqual({ id: 1 })
      expect(result).toEqual(mockResponse)
    })

    it('已点赞时返回 liked: false', async () => {
      const mockResponse = { ok: true, id: 1, likes: 6, liked: false }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockResponse),
      })

      const result = await danmuApi.like(1)
      expect(result.liked).toBe(false)
    })
  })

  describe('send', () => {
    it('发送 POST 请求发送弹幕', async () => {
      const mockResponse = { ok: true, id: 100 }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockResponse),
      })

      const result = await danmuApi.send('测试弹幕')

      expect(mockFetch).toHaveBeenCalledTimes(1)
      const [url, options] = mockFetch.mock.calls[0]
      expect(url).toBe('/danmu')
      expect(options.method).toBe('POST')
      expect(JSON.parse(options.body)).toEqual({ text: '测试弹幕' })
      expect(result.ok).toBe(true)
    })
  })
})

describe('authApi', () => {
  describe('status', () => {
    it('正常返回认证状态', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ authenticated: true }),
      })

      const result = await authApi.status()
      expect(result.authenticated).toBe(true)
    })

    it('请求失败时返回未认证', async () => {
      mockFetch.mockRejectedValueOnce(new Error('network error'))

      const result = await authApi.status()
      expect(result.authenticated).toBe(false)
    })
  })
})
