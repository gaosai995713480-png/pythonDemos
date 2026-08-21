/**
 * LyricFxSwitcher 组件测试：首页歌词漂浮效果切换按钮
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'
import LyricFxSwitcher from '../components/LyricFxSwitcher.vue'
import { clickOutside } from '../directives/clickOutside'
import { useLyricFxStore } from '../stores/lyricFx'

function mountSwitcher() {
  return mount(LyricFxSwitcher, {
    attachTo: document.body,
    global: { directives: { 'click-outside': clickOutside } },
  })
}

describe('LyricFxSwitcher', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
  })

  it('点击按钮展开效果列表', async () => {
    const wrapper = mountSwitcher()

    expect(wrapper.find('.fx-dropdown').classes()).not.toContain('is-open')

    await wrapper.find('.fx-btn').trigger('click')

    expect(wrapper.find('.fx-dropdown').classes()).toContain('is-open')
    expect(wrapper.findAll('.fx-item')).toHaveLength(6)

    wrapper.unmount()
  })

  it('选中效果后写入 store 并收起列表', async () => {
    const wrapper = mountSwitcher()
    const store = useLyricFxStore()

    await wrapper.find('.fx-btn').trigger('click')
    // 列表顺序：关闭 / 整卡轻浮 / 逐字波浪 / 自由漂浮 / 气泡上升 / 梦幻组合
    await wrapper.findAll('.fx-item')[2].trigger('click')

    expect(store.currentKey).toBe('wave')
    expect(localStorage.getItem('love_lyric_fx')).toBe('wave')
    expect(wrapper.find('.fx-dropdown').classes()).not.toContain('is-open')
    expect(wrapper.find('.fx-item.is-active').text()).toContain('逐字波浪')

    wrapper.unmount()
  })

  it('点击外部收起列表', async () => {
    const wrapper = mountSwitcher()

    await wrapper.find('.fx-btn').trigger('click')
    expect(wrapper.find('.fx-dropdown').classes()).toContain('is-open')

    document.body.click()
    await wrapper.vm.$nextTick()

    expect(wrapper.find('.fx-dropdown').classes()).not.toContain('is-open')

    wrapper.unmount()
  })
})
