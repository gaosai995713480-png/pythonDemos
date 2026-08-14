/**
 * 登录错误提示回归测试
 *
 * Bug：authApi.login 走通用 request() 时，登录失败返回的 401 会触发
 * window.location.replace('/login') 整页刷新，页面看不到任何错误提示。
 * 修复后 login 独立请求，任何失败都以 { error } 形式返回给视图层内联展示。
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { authApi } from '../api'

function mockFetchResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  }
}

describe('authApi.login 错误提示', () => {
  beforeEach(() => {
    vi.unstubAllGlobals()
  })

  it('密码错误（401）时返回后端错误体，而不是跳转或抛异常', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      mockFetchResponse(401, { error: '用户名或密码错误' })
    ))

    await expect(authApi.login('admin', 'wrong')).resolves.toEqual({
      error: '用户名或密码错误',
    })
    expect(fetch).toHaveBeenCalledWith('/auth/login', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ username: 'admin', password: 'wrong' }),
    }))
  })

  it('账号被禁用（403）时同样返回后端错误体', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      mockFetchResponse(403, { error: '账号已被禁用' })
    ))

    await expect(authApi.login('admin', 'pass')).resolves.toEqual({
      error: '账号已被禁用',
    })
  })

  it('网络异常时返回可展示的错误信息', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new TypeError('Failed to fetch')
    }))

    await expect(authApi.login('admin', 'pass')).resolves.toEqual({
      error: '网络错误，请检查连接',
    })
  })

  it('登录成功时原样返回响应体', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      mockFetchResponse(200, { ok: true, username: 'admin', role: 'admin' })
    ))

    await expect(authApi.login('admin', 'right')).resolves.toEqual({
      ok: true,
      username: 'admin',
      role: 'admin',
    })
  })
})
