<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

defineProps({
  visible: { type: Boolean, default: true },
})

const leaves = ref([])
const LEAF_EMOJIS = ['🍃', '🌿', '🍀']
let timer = null

function spawnLeaf() {
  const id = Date.now() + Math.random()
  leaves.value.push({
    id,
    emoji: LEAF_EMOJIS[Math.floor(Math.random() * LEAF_EMOJIS.length)],
    left: Math.random() * 100,
    delay: 0,
    duration: Math.random() * 6 + 8,
    swayAmount: Math.random() * 60 + 30,
    size: Math.random() * 10 + 16,
  })
  setTimeout(() => {
    leaves.value = leaves.value.filter(l => l.id !== id)
  }, 16000)
}

onMounted(() => {
  for (let i = 0; i < 8; i++) {
    setTimeout(spawnLeaf, i * 600)
  }
  timer = setInterval(spawnLeaf, 1800)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
  leaves.value = []
})
</script>

<template>
  <div v-if="visible" class="falling-layer">
    <span
      v-for="leaf in leaves"
      :key="leaf.id"
      class="leaf"
      :style="{
        left: leaf.left + '%',
        animationDuration: leaf.duration + 's',
        animationDelay: leaf.delay + 's',
        '--sway': leaf.swayAmount + 'px',
        fontSize: leaf.size + 'px',
      }"
    >{{ leaf.emoji }}</span>
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

.leaf {
  position: absolute;
  top: -40px;
  animation: leaf-fall linear forwards;
  will-change: transform;
}

@keyframes leaf-fall {
  0% {
    transform: translateY(0) translateX(0) rotate(0deg);
    opacity: 0.9;
  }
  25% {
    transform: translateY(25vh) translateX(var(--sway)) rotate(90deg);
  }
  50% {
    transform: translateY(50vh) translateX(calc(var(--sway) * -0.5)) rotate(180deg);
  }
  75% {
    transform: translateY(75vh) translateX(var(--sway)) rotate(270deg);
    opacity: 0.7;
  }
  100% {
    transform: translateY(110vh) translateX(0) rotate(360deg);
    opacity: 0;
  }
}

@media (prefers-reduced-motion: reduce) {
  .leaf { animation: none; opacity: 0.5; top: 50%; }
}
</style>