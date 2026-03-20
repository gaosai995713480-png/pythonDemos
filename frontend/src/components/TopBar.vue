<script setup>
import ThemeSwitcher from './ThemeSwitcher.vue'

defineProps({
  title: { type: String, default: '' },
  showBack: { type: Boolean, default: true },
  showTheme: { type: Boolean, default: true },
})

const emit = defineEmits(['back'])

function handleBack() {
  emit('back')
}
</script>

<template>
  <div class="top-bar">
    <a v-if="showBack" class="back-btn" @click.prevent="handleBack" href="#">← 返回</a>
    <h1>{{ title }}</h1>
    <slot />
    <ThemeSwitcher v-if="showTheme" />
  </div>
</template>

<style scoped>
.top-bar {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 10;
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 20px;
  background: var(--glass-bg);
  backdrop-filter: blur(30px);
  border-bottom: 1px solid var(--glass-border);
}

.back-btn {
  text-decoration: none;
  color: #fff;
  font-size: 14px;
  font-weight: 600;
  padding: 8px 16px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.2);
  transition: all 0.2s ease;
  cursor: pointer;
}

.back-btn:hover {
  background: rgba(255, 255, 255, 0.18);
  transform: translateY(-1px);
}

h1 {
  font-size: 18px;
  font-weight: 700;
  white-space: nowrap;
}
</style>
