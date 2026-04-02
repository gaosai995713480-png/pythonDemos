<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const fireflies = ref([])
let timer = null

function spawnFirefly() {
  const id = Date.now() + Math.random()
  fireflies.value.push({
    id,
    left: Math.random() * 100,
    bottom: Math.random() * 20 - 10,
    duration: Math.random() * 5 + 5,
    size: Math.random() * 4 + 3,
    xdrift: (Math.random() - 0.5) * 100,
  })
  setTimeout(() => {
    fireflies.value = fireflies.value.filter(f => f.id !== id)
  }, 11000)
}

onMounted(() => {
  for (let i = 0; i < 20; i++) {
    setTimeout(spawnFirefly, i * 200)
  }
  timer = setInterval(spawnFirefly, 500)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
  fireflies.value = []
})
</script>

<template>
  <div class="falling-layer">
    <div
      v-for="ff in fireflies"
      :key="ff.id"
      class="firefly"
      :style="{
        left: ff.left + '%',
        bottom: ff.bottom + '%',
        animationDuration: ff.duration + 's',
        '--xdrift': ff.xdrift + 'px',
        width: ff.size + 'px',
        height: ff.size + 'px',
      }"
    ></div>
  </div>
</template>

<style scoped>
.falling-layer {
  position: fixed; inset: 0; overflow: hidden; pointer-events: none; z-index: 1;
}

.firefly {
  position: absolute;
  background: #fffafa;
  border-radius: 50%;
  box-shadow: 0 0 8px 3px rgba(212, 255, 9, 0.8), 0 0 15px 5px rgba(255, 235, 59, 0.4);
  animation: firefly-float linear forwards, blink 2s ease-in-out infinite;
  will-change: transform, opacity;
}

@keyframes firefly-float {
  0% { transform: translateY(0) translateX(0); opacity: 0; }
  10% { opacity: 1; }
  90% { opacity: 1; }
  100% { transform: translateY(-80vh) translateX(var(--xdrift)); opacity: 0; }
}

@keyframes blink {
  0%, 100% { opacity: 0.4; transform: scale(0.8); }
  50% { opacity: 1; transform: scale(1.2); }
}

@media (prefers-reduced-motion: reduce) {
  .firefly { animation: none; opacity: 0.5; top: 50%; }
}
</style>
