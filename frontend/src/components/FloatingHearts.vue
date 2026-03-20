<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const props = defineProps({
  visible: { type: Boolean, default: true },
})

const emit = defineEmits(['update:visible'])
const container = ref(null)
let timer = null

function spawnHeart() {
  if (!container.value) return
  const heart = document.createElement('span')
  const size = Math.random() * 14 + 10
  heart.className = 'floating-heart'
  heart.style.setProperty('--x', `${Math.random() * 100}%`)
  heart.style.setProperty('--size', `${size}px`)
  heart.style.setProperty('--float-duration', `${Math.random() * 4 + 6}s`)
  container.value.appendChild(heart)
  setTimeout(() => { heart.remove() }, 12000)
}

onMounted(() => {
  spawnHeart()
  timer = setInterval(spawnHeart, 1400)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<template>
  <div v-if="visible" ref="container" class="floating-layer"></div>
</template>

<style scoped>
.floating-layer {
  position: fixed;
  inset: 0;
  overflow: hidden;
  pointer-events: none;
  z-index: 1;
}

:deep(.floating-heart) {
  position: absolute;
  left: var(--x);
  bottom: -15vh;
  width: var(--size);
  height: var(--size);
  background: linear-gradient(135deg, rgba(255, 107, 157, 0.6), rgba(196, 69, 105, 0.4));
  transform: rotate(-45deg);
  filter: blur(1px) drop-shadow(0 0 12px rgba(255, 107, 157, 0.5));
  animation: float-up var(--float-duration) ease-in forwards;
  border-radius: 4px;
}

:deep(.floating-heart::before),
:deep(.floating-heart::after) {
  content: "";
  position: absolute;
  width: 100%;
  height: 100%;
  background: inherit;
  border-radius: 50%;
}

:deep(.floating-heart::before) {
  top: -50%;
  left: 0;
}

:deep(.floating-heart::after) {
  top: 0;
  left: 50%;
}
</style>
