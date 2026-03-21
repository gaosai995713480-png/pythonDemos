<script setup>
import { ref } from 'vue'
import { useThemeStore } from '../stores/theme'

const themeStore = useThemeStore()
const open = ref(false)

function toggle() {
  open.value = !open.value
}

function select(theme) {
  themeStore.applyTheme(theme.name)
  open.value = false
}

// 点击外部关闭
function onClickOutside() {
  open.value = false
}
</script>

<template>
  <div class="ts-wrap" v-click-outside="onClickOutside">
    <button class="ts-btn" type="button" title="切换主题" @click.stop="toggle">🎨</button>
    <div class="ts-dropdown" :class="{ 'is-open': open }">
      <div
        v-for="theme in themeStore.themes"
        :key="theme.name"
        class="ts-swatch"
        :class="{ 'is-active': themeStore.currentName === theme.name }"
        :style="{ background: theme.color }"
        :title="theme.name"
        @click="select(theme)"
      >
        <span class="ts-emoji">{{ theme.emoji }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.ts-wrap {
  position: relative;
  margin-left: auto;
}

.ts-btn {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  border: 1px solid rgba(255, 255, 255, 0.15);
  background: rgba(255, 255, 255, 0.1);
  color: #fff;
  font-size: 18px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}

.ts-btn:hover {
  background: rgba(255, 255, 255, 0.2);
  transform: scale(1.05);
}

.ts-dropdown {
  position: absolute;
  top: calc(100% + 8px);
  right: 0;
  background: rgba(20, 20, 30, 0.92);
  backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.15);
  border-radius: 14px;
  padding: 10px;
  display: flex;
  flex-wrap: wrap;
  max-width: 220px;
  gap: 8px;
  opacity: 0;
  pointer-events: none;
  transform: translateY(-6px);
  transition: all 0.2s ease;
  z-index: 50;
}

.ts-dropdown.is-open {
  opacity: 1;
  pointer-events: auto;
  transform: translateY(0);
}

.ts-swatch {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  border: 2px solid transparent;
  cursor: pointer;
  transition: all 0.2s;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
}

.ts-swatch:hover {
  transform: scale(1.12);
}

.ts-swatch.is-active {
  border-color: #fff;
  box-shadow: 0 0 12px rgba(255, 255, 255, 0.3);
}

.ts-emoji {
  font-size: 16px;
}
</style>
