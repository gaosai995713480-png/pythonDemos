import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mockFetch = vi.fn()
const mockToastError = vi.fn()

vi.stubGlobal('fetch', mockFetch)
vi.mock('../composables/useToast', () => ({
  useToast: () => ({
    error: mockToastError,
  }),
}))

let photoApi

beforeEach(async () => {
  vi.resetModules()
  mockFetch.mockReset()
  mockToastError.mockReset()
  const api = await import('../api/index.js')
  photoApi = api.photoApi
})

afterEach(() => {
  sessionStorage.clear()
})

describe('photoApi', () => {
  it('上传失败时提示后端错误并抛出异常', async () => {
    const file = new File(['bad'], 'bad.txt', { type: 'text/plain' })
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: () => Promise.resolve({ error: 'only image files are allowed' }),
    })

    await expect(photoApi.upload(file, file.name)).rejects.toThrow('only image files are allowed')
    expect(mockToastError).toHaveBeenCalledWith('only image files are allowed')
  })

  it('导入失败时提示后端错误并抛出异常', async () => {
    const file = new File(['bad zip'], 'photos.zip', { type: 'application/zip' })
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: () => Promise.resolve({ error: 'invalid zip file' }),
    })

    await expect(photoApi.importZip(file)).rejects.toThrow('invalid zip file')
    expect(mockToastError).toHaveBeenCalledWith('invalid zip file')
  })
})
