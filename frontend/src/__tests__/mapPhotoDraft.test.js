import { describe, expect, it, vi } from 'vitest'

import {
  createMapPhotoDrafts,
  createPendingPhotoDrafts,
  resolveMapPhotoDraftUrls,
  revokeLocalPhotoDrafts,
} from '../views/mapPhotoDraft.js'

describe('createMapPhotoDrafts', () => {
  it('编辑旧足迹时会用 photo_url 回填首图', () => {
    const drafts = createMapPhotoDrafts({
      photo_url: 'https://example.com/legacy-cover.jpg',
    })

    expect(drafts).toEqual([
      { url: 'https://example.com/legacy-cover.jpg', file: null },
    ])
  })

  it('多图数据优先于旧封面字段', () => {
    const drafts = createMapPhotoDrafts({
      photo_url: 'https://example.com/legacy-cover.jpg',
      photos: [
        'https://example.com/first.jpg',
        'https://example.com/second.jpg',
      ],
    })

    expect(drafts).toEqual([
      { url: 'https://example.com/first.jpg', file: null },
      { url: 'https://example.com/second.jpg', file: null },
    ])
  })
})

describe('pending map photos', () => {
  it('选择文件时只创建本地预览，不会立刻上传', () => {
    const createObjectURL = vi
      .fn()
      .mockReturnValueOnce('blob:preview-1')
      .mockReturnValueOnce('blob:preview-2')

    const drafts = createPendingPhotoDrafts(
      [{ name: 'first.jpg' }, { name: 'second.jpg' }],
      createObjectURL,
    )

    expect(createObjectURL).toHaveBeenCalledTimes(2)
    expect(drafts).toEqual([
      { url: 'blob:preview-1', file: { name: 'first.jpg' } },
      { url: 'blob:preview-2', file: { name: 'second.jpg' } },
    ])
  })

  it('保存时才上传本地图片，并在失败后清理已上传对象', async () => {
    const upload = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        url: 'https://oss.example.com/map/uploaded-1.jpg',
        name: 'uploaded-1.jpg',
      })
      .mockRejectedValueOnce(new Error('upload failed'))
    const cleanup = vi.fn().mockResolvedValue()

    await expect(
      resolveMapPhotoDraftUrls(
        [
          { url: 'https://example.com/existing.jpg', file: null },
          { url: 'blob:preview-1', file: { name: 'first.jpg' } },
          { url: 'blob:preview-2', file: { name: 'second.jpg' } },
        ],
        upload,
        cleanup,
      ),
    ).rejects.toThrow('upload failed')

    expect(upload).toHaveBeenCalledTimes(2)
    expect(cleanup).toHaveBeenCalledWith(['uploaded-1.jpg'])
  })

  it('关闭表单时会释放本地预览 URL', () => {
    const revokeObjectURL = vi.fn()

    revokeLocalPhotoDrafts(
      [
        { url: 'https://example.com/existing.jpg', file: null },
        { url: 'blob:preview-1', file: { name: 'first.jpg' } },
      ],
      revokeObjectURL,
    )

    expect(revokeObjectURL).toHaveBeenCalledTimes(1)
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:preview-1')
  })
})
