<template>
  <FloatingHearts v-if="currentEffect === 'hearts'" />
  <FallingLeaves v-if="currentEffect === 'leaves'" />
  <AuroraEffect v-if="currentEffect === 'aurora'" />
  <AppToast />
  <router-view />
  <!-- AI 聊天悬浮组件 - 全局常驻，登录后可用 -->
  <AiChatWidget v-if="authStore.authenticated" />
</template>

<script setup>
import { computed } from 'vue'
import { useThemeStore } from './stores/theme'
import { useAuthStore } from './stores/auth'
import AppToast from './components/AppToast.vue'
import FloatingHearts from './components/FloatingHearts.vue'
import FallingLeaves from './components/FallingLeaves.vue'
import AuroraEffect from './components/AuroraEffect.vue'
import AiChatWidget from './components/AiChatWidget.vue'

const themeStore = useThemeStore()
const authStore = useAuthStore()
const currentEffect = computed(() => themeStore.currentEffect)
</script>