import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

const THEMES = [
  {
    name: '春', emoji: '🌸', effect: 'petals',
    color: 'linear-gradient(135deg, #a8edea 0%, #fed6e3 100%)',
    vars: {
      '--primary': '#ff6b9d', '--secondary': '#c44569', '--accent': '#ffc048',
      '--bg-grad-1': '#a8edea', '--bg-grad-2': '#fed6e3',
      '--bg-grad-3': '#ff9a9e', '--bg-grad-4': '#fecfef',
    }
  },
  {
    name: '夏', emoji: '☀️', effect: 'fireflies',
    color: 'linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%)',
    vars: {
      '--primary': '#00b09b', '--secondary': '#96c93d', '--accent': '#fde68a',
      '--bg-grad-1': '#0f2027', '--bg-grad-2': '#203a43',
      '--bg-grad-3': '#2c5364', '--bg-grad-4': '#141e30',
    }
  },
  {
    name: '流星', emoji: '🌠', effect: 'meteors',
    color: 'linear-gradient(135deg, #000000 0%, #151525 100%)',
    vars: {
      '--primary': '#a78bfa', '--secondary': '#38bdf8', '--accent': '#fde047',
      '--bg-grad-1': '#000000', '--bg-grad-2': '#151525',
      '--bg-grad-3': '#201633', '--bg-grad-4': '#090810',
    }
  },
  {
    name: '秋', emoji: '🍂', effect: 'leaves',
    color: 'linear-gradient(135deg, #d4a574, #8b5e3c)',
    vars: {
      '--primary': '#d4a574', '--secondary': '#8b5e3c', '--accent': '#fbbf24',
      '--bg-grad-1': '#8b5e3c', '--bg-grad-2': '#d4a574',
      '--bg-grad-3': '#5c3317', '--bg-grad-4': '#a0522d',
    }
  },
  {
    name: '冬', emoji: '❄️', effect: 'snow',
    color: 'linear-gradient(135deg, #e0c3fc 0%, #8ec5fc 100%)',
    vars: {
      '--primary': '#8ec5fc', '--secondary': '#475569', '--accent': '#e2e8f0',
      '--bg-grad-1': '#e0c3fc', '--bg-grad-2': '#8ec5fc',
      '--bg-grad-3': '#536976', '--bg-grad-4': '#292e49',
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
    name: '极光', emoji: '🌌', effect: 'aurora',
    color: 'linear-gradient(135deg, #0b3d0b, #1a0533)',
    vars: {
      '--primary': '#34d399', '--secondary': '#6366f1', '--accent': '#a78bfa',
      '--bg-grad-1': '#0b3d0b', '--bg-grad-2': '#1a0533',
      '--bg-grad-3': '#004d40', '--bg-grad-4': '#0d1b2a',
    }
  },
  {
    name: '海月', emoji: '🌊', effect: 'hearts',
    color: 'linear-gradient(135deg, #1cb5e0, #000851)',
    vars: {
      '--primary': '#38bdf8', '--secondary': '#0284c7', '--accent': '#fbbf24',
      '--bg-grad-1': '#1cb5e0', '--bg-grad-2': '#000851',
      '--bg-grad-3': '#0ea5e9', '--bg-grad-4': '#0369a1',
    }
  },
]

export const useThemeStore = defineStore('theme', () => {
  const currentName = ref('流星')
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
      } else {
        applyTheme(currentName.value)
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