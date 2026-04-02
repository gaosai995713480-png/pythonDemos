<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const flakes = ref([])
let timer = null

function spawnFlake() {
  const id = Date.now() + Math.random()
  flakes.value.push({
    id,
    left: Math.random() * 100,
    delay: Math.random() * 2,
    duration: Math.random() * 5 + 7,
    size: Math.random() * 6 + 4,
    opacity: Math.random() * 0.6 + 0.3,
  })
  setTimeout(() => {
    flakes.value = flakes.value.filter(f => f.id !== id)
  }, 13000)
}

onMounted(() => {
  for (let i = 0; i < 20; i++) {
    setTimeout(spawnFlake, i * 200)
  }
  timer = setInterval(spawnFlake, 300)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
  flakes.value = []
})
</script>

<template>
  <div class="falling-layer">
    <div
      v-for="flake in flakes"
      :key="flake.id"
      class="flake"
      :style="{
        left: flake.left + '%',
        animationDuration: flake.duration + 's',
        animationDelay: flake.delay + 's',
        width: flake.size + 'px',
        height: flake.size + 'px',
        opacity: flake.opacity,
      }"
    ></div>
  </div>
</template>

<style scoped>
.falling-layer {
  position: fixed;
  inset: 0;
  overflow: hidden;
  pointer-events: none;
  z-index: 1;
}

.flake {
  position: absolute;
  top: -20px;
  background: white;
  border-radius: 50%;
  filter: blur(1px);
  animation: snow-fall linear forwards;
  will-change: transform;
}

@keyframes snow-fall {
  0% { transform: translateY(0) translateX(0); }
  50% { transform: translateY(50vh) translateX(15px); }
  100% { transform: translateY(110vh) translateX(-15px); }
}

@media (prefers-reduced-motion: reduce) {
  .flake { animation: none; opacity: 0.5; top: 50%; }
}
</style>
