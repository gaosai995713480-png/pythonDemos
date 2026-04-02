<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const petals = ref([])
let timer = null

function spawnPetal() {
  const id = Date.now() + Math.random()
  petals.value.push({
    id,
    left: Math.random() * 100,
    duration: Math.random() * 6 + 8,
    size: Math.random() * 10 + 12,
    sway: Math.random() * 50 + 20,
    rotation: Math.random() * 360,
  })
  setTimeout(() => {
    petals.value = petals.value.filter(p => p.id !== id)
  }, 15000)
}

onMounted(() => {
  for (let i = 0; i < 12; i++) {
    setTimeout(spawnPetal, i * 300)
  }
  timer = setInterval(spawnPetal, 800)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
  petals.value = []
})
</script>

<template>
  <div class="falling-layer">
    <div
      v-for="petal in petals"
      :key="petal.id"
      class="petal"
      :style="{
        left: petal.left + '%',
        animationDuration: petal.duration + 's',
        '--sway': petal.sway + 'px',
        '--start-rot': petal.rotation + 'deg',
        width: petal.size + 'px',
        height: petal.size * 0.7 + 'px',
      }"
    ></div>
  </div>
</template>

<style scoped>
.falling-layer {
  position: fixed; inset: 0; overflow: hidden; pointer-events: none; z-index: 1;
}

.petal {
  position: absolute;
  top: -30px;
  background: linear-gradient(135deg, #ffb7c5, #ff94b3);
  border-radius: 15px 0 15px 0;
  box-shadow: 0 2px 4px rgba(255, 105, 180, 0.2);
  animation: petal-fall linear forwards;
  transform-style: preserve-3d;
  will-change: transform;
}

@keyframes petal-fall {
  0% { transform: translateY(0) translateX(0) rotate3d(1, 1, 1, var(--start-rot)); }
  33% { transform: translateY(33vh) translateX(var(--sway)) rotate3d(1, 1, 1, calc(var(--start-rot) + 180deg)); }
  66% { transform: translateY(66vh) translateX(calc(var(--sway) * -1)) rotate3d(1, 1, 1, calc(var(--start-rot) + 360deg)); }
  100% { transform: translateY(110vh) translateX(0) rotate3d(1, 1, 1, calc(var(--start-rot) + 720deg)); opacity: 0; }
}

@media (prefers-reduced-motion: reduce) {
  .petal { animation: none; opacity: 0.5; top: 50%; }
}
</style>
