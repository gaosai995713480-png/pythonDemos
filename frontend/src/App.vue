<template>
  <FloatingHearts v-if="currentEffect === 'hearts'" />
  <FallingLeaves v-if="currentEffect === 'leaves'" />
  <AuroraEffect v-if="currentEffect === 'aurora'" />
  <AppToast />
  <router-view />
</template>

<script setup>
import { computed } from 'vue'
import { useThemeStore } from './stores/theme'
import AppToast from './components/AppToast.vue'
import FloatingHearts from './components/FloatingHearts.vue'
import FallingLeaves from './components/FallingLeaves.vue'
import AuroraEffect from './components/AuroraEffect.vue'

const themeStore = useThemeStore()
const currentEffect = computed(() => themeStore.currentEffect)
</script>