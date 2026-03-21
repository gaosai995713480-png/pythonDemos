import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

const THEMES = [
  {
    name: '春樱', emoji: '🌸', effect: 'hearts',
    color: 'linear-gradient(135deg, #ee7752, #e73c7e)',
    vars: {
      '--primary': '#ff6b9d', '--secondary': '#c44569', '--accent': '#ffc048',
      '--bg-grad-1': '#ee7752', '--bg-grad-2': '#e73c7e',
      '--bg-grad-3': '#23a6d5', '--bg-grad-4': '#23d5ab',
    }
  },
  {
    name: '星空', emoji: '✨', effect: 'hearts',
    color: 'linear-gradient(135deg, #0f0c29, #302b63)',
    vars: {
      '--primary': '#a78bfa', '--secondary': '#7c3aed', '--accent': '#f9a8d4',
      '--bg-grad-1': '#0f0c29', '--bg-grad-2': '#302b63',
      '--bg-grad-3': '#24243e', '--bg-grad-4': '#0f0c29',
    }
  },
  {
    name: '海边', emoji: '🌊', effect: 'hearts',
    color: 'linear-gradient(135deg, #1cb5e0, #000851)',
    vars: {
      '--primary': '#38bdf8', '--secondary': '#0284c7', '--accent': '#fbbf24',
      '--bg-grad-1': '#1cb5e0', '--bg-grad-2': '#000851',
      '--bg-grad-3': '#0ea5e9', '--bg-grad-4': '#0369a1',
    }
  },
  {
    name: '雪夜', emoji: '❄️', effect: 'hearts',
    color: 'linear-gradient(135deg, #e6dada, #274046)',
    vars: {
      '--primary': '#94a3b8', '--secondary': '#475569', '--accent': '#e2e8f0',
      '--bg-grad-1': '#e6dada', '--bg-grad-2': '#274046',
      '--bg-grad-3': '#536976', '--bg-grad-4': '#292e49',
    }
  },
  {
    name: '森林', emoji: '🌿', effect: 'leaves',
    color: 'linear-gradient(135deg, #134e5e, #71b280)',
    vars: {
      '--primary': '#71b280', '--secondary': '#2d6a4f', '--accent': '#a7f3d0',
      '--bg-grad-1': '#134e5e', '--bg-grad-2': '#71b280',
      '--bg-grad-3': '#2d5016', '--bg-grad-4': '#1a472a',
    }
  },
  {
    name: '日落', emoji: '🌅', effect: 'hearts',
    color: 'linear-gradient(135deg, #f12711, #f5af19)',
    vars: {
      '--primary': '#f59e0b', '--secondary': '#dc2626', '--accent': '#fde68a',
      '--bg-grad-1': '#f12711', '--bg-grad-2': '#f5af19',
      '--bg-grad-3': '#c33764', '--bg-grad-4': '#1d2671',
    }
  },
  {
    name: '薰衣草', emoji: '💜', effect: 'hearts',
    color: 'linear-gradient(135deg, #c471f5, #fa71cd)',
    vars: {
      '--primary': '#c084fc', '--secondary': '#a855f7', '--accent': '#f0abfc',
      '--bg-grad-1': '#c471f5', '--bg-grad-2': '#fa71cd',
      '--bg-grad-3': '#e8b4f8', '--bg-grad-4': '#ad5389',
    }
  },
  {
    name: '焦糖', emoji: '🍂', effect: 'hearts',
    color: 'linear-gradient(135deg, #8b5e3c, #d4a574)',
    vars: {
      '--primary': '#d4a574', '--secondary': '#8b5e3c', '--accent': '#fbbf24',
      '--bg-grad-1': '#8b5e3c', '--bg-grad-2': '#d4a574',
      '--bg-grad-3': '#5c3317', '--bg-grad-4': '#a0522d',
    }
  },
  {
    name: '极光', emoji: '🌌', effect: 'aurora',
    color: 'linear-gradient(135deg, #0b3d0b, #1a0533)',
    vars: {
      '--primary': '#34d399', '--secondary': '#6366f1', '--accent': '#a78bfa',
      '--bg-grad-1': '#0b3d0b', '--bg-grad-2': '#1a0533',
      '--bg-grad-3': '#004d40', '--bg-grad-4': '#0d1b2a',
    }
  },
]

export const useThemeStore = defineStore('theme', () => {
  const currentName = ref('春樱')
  const themes = THEMES

  const currentEffect = computed(() => {
    const theme = THEMES.find(t => t.name === currentName.value)
    return theme?.effect || 'hearts'
  })

  function init() {
    try {
      const saved = localStorage.getItem('love_theme')
      if (saved) {
        const t = JSON.parse(saved)
        if (t.name) currentName.value = t.name
        if (t.vars) applyVars(t.vars)
      }
    } catch (e) { /* ignore */ }
  }

  function applyVars(vars) {
    Object.entries(vars).forEach(([k, v]) => {
      document.documentElement.style.setProperty(k, v)
    })
  }

  function applyTheme(name) {
    const theme = THEMES.find(t => t.name === name)
    if (!theme) return
    currentName.value = name
    applyVars(theme.vars)
    localStorage.setItem('love_theme', JSON.stringify({ name, vars: theme.vars }))
  }

  return { currentName, currentEffect, themes, init, applyTheme }
})