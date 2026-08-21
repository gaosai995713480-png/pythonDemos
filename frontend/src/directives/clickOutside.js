/**
 * v-click-outside：点击元素外部时触发回调。
 * 供 ThemeSwitcher / LyricFxSwitcher 等下拉面板收起使用。
 */
const handlers = new WeakMap()

export const clickOutside = {
  mounted(el, binding) {
    const handler = (e) => {
      if (!el.contains(e.target)) binding.value?.(e)
    }
    handlers.set(el, handler)
    // 捕获阶段监听，避免被子元素的 stopPropagation 拦掉
    document.addEventListener('click', handler, true)
  },
  unmounted(el) {
    const handler = handlers.get(el)
    if (handler) {
      document.removeEventListener('click', handler, true)
      handlers.delete(el)
    }
  },
}
