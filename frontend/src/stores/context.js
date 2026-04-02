import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useContextStore = defineStore('context', () => {
  const pageName = ref('')
  const pageState = ref('')

  function setPageState(state) {
    pageState.value = state
  }

  function getFormattedContext() {
    const now = new Date()
    const timeStr = now.toLocaleString('zh-CN', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      weekday: 'long'
    })
    
    let ctx = `本地时间: ${timeStr}\n`
    if (pageName.value) {
      ctx += `当前所在页面: ${pageName.value}\n`
    }
    if (pageState.value) {
      ctx += `页面状态: ${pageState.value}\n`
    }
    return ctx
  }

  return {
    pageName,
    pageState,
    setPageState,
    getFormattedContext
  }
})
