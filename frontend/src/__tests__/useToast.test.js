/**
 * useToast composable 单元测试
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { useToast } from '../composables/useToast'

describe('useToast', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('show() 设置 toast 状态', () => {
    const { toast, show } = useToast()
    show('测试消息', 'error')
    expect(toast.visible).toBe(true)
    expect(toast.message).toBe('测试消息')
    expect(toast.type).toBe('error')
  })

  it('show() 默认 3 秒后自动隐藏', () => {
    const { toast, show } = useToast()
    show('自动隐藏')
    expect(toast.visible).toBe(true)
    vi.advanceTimersByTime(3000)
    expect(toast.visible).toBe(false)
  })

  it('show() 支持自定义 duration', () => {
    const { toast, show } = useToast()
    show('快速消失', 'info', 1000)
    expect(toast.visible).toBe(true)
    vi.advanceTimersByTime(1000)
    expect(toast.visible).toBe(false)
  })
})
