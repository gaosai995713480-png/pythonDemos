import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

const THEMES = [
  {
    name: '春樱', emoji: '🌸',
    color: 'linear-gradient(135deg, #ee7752, #e73c7e)',
    vars: {
      '--primary': '#ff6b9d', '--secondary': '#c44569', '--accent': '#ffc048',
      '--bg-grad-1': '#ee7752', '--bg-grad-2': '#e73c7e',
      '--bg-grad-3': '#23a6d5', '--bg-grad-4': '#23d5ab',
    }
  },
  {
    name: '星空', emoji: '✨',
    color: 'linear-gradient(135deg, #0f0c29, #302b63)',
    vars: {
      '--primary': '#a78bfa', '--secondary': '#7c3aed', '--accent': '#f9a8d4',
      '--bg-grad-1': '#0f0c29', '--bg-grad-2': '#302b63',
      '--bg-grad-3': '#24243e', '--bg-grad-4': '#0f0c29',
    }
  },
  {
    name: '海边', emoji: '🌊',
    color: 'linear-gradient(135deg, #1cb5e0, #000851)',
    vars: {
      '--primary': '#38bdf8', '--secondary': '#0284c7', '--accent': '#fbbf24',
      '--bg-grad-1': '#1cb5e0', '--bg-grad-2': '#000851',
      '--bg-grad-3': '#0ea5e9', '--bg-grad-4': '#0369a1',
    }
  },
  {
    name: '雪夜', emoji: '❄️',
    color: 'linear-gradient(135deg, #e6dada, #274046)',
    vars: {
      '--primary': '#94a3b8', '--secondary': '#475569', '--accent': '#e2e8f0',
      '--bg-grad-1': '#e6dada', '--bg-grad-2': '#274046',
      '--bg-grad-3': '#536976', '--bg-grad-4': '#292e49',
    }
  },
]

export const useThemeStore = defineStore('theme', () => {
  const currentName = ref('春樱')
  const themes = THEMES

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

  return { currentName, themes, init, applyTheme }
})
