/**
 * 全局 Toast 通知 composable
 * 单例模式：所有调用共享同一个 toast 状态
 */
import { reactive } from 'vue'

const toast = reactive({
  message: '',
  type: 'info', // 'success' | 'error' | 'info' | 'warning'
  visible: false,
})

let hideTimer = null

export function useToast() {
  function show(message, type = 'info', duration = 3000) {
    if (hideTimer) clearTimeout(hideTimer)
    toast.message = message
    toast.type = type
    toast.visible = true
    hideTimer = setTimeout(() => {
      toast.visible = false
    }, duration)
  }

  function success(message, duration) { show(message, 'success', duration) }
  function error(message, duration) { show(message, 'error', duration) }
  function warning(message, duration) { show(message, 'warning', duration) }
  function info(message, duration) { show(message, 'info', duration) }

  return { toast, show, success, error, warning, info }
}
