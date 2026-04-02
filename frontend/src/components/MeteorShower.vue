<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const meteors = ref([])
const stars = ref([])
let meteorTimer = null

function spawnMeteor() {
  const id = Date.now() + Math.random()
  // 错落有致的属性
  const isLarge = Math.random() > 0.8
  const length = isLarge ? Math.random() * 200 + 150 : Math.random() * 80 + 80
  const duration = isLarge ? Math.random() * 1.5 + 1.2 : Math.random() * 0.8 + 0.8

  meteors.value.push({
    id,
    top: Math.random() * 100 - 50,  // 从更远的顶部生成
    left: Math.random() * 150 - 20, // 覆盖较宽的横向生成区域
    duration: duration,
    delay: Math.random() * 0.5,
    length: length,
    thickness: isLarge ? 2 : 1,
    opacity: isLarge ? 1 : Math.random() * 0.5 + 0.3
  })
  
  setTimeout(() => {
    meteors.value = meteors.value.filter(m => m.id !== id)
  }, duration * 1000 + 1000)
}

function initStars() {
  // 生成满天繁星背景
  for(let i = 0; i < 60; i++) {
    stars.value.push({
      id: i,
      top: Math.random() * 100,
      left: Math.random() * 100,
      size: Math.random() * 2 + 1,
      duration: Math.random() * 3 + 2,
      delay: Math.random() * 5
    })
  }
}

onMounted(() => {
  initStars()
  
  // 初始生成几颗流星
  for (let i = 0; i < 5; i++) {
    setTimeout(spawnMeteor, Math.random() * 2000)
  }
  
  // 生成频率稍微降低，营造珍贵和高级感，每次可能生成1-2颗
  meteorTimer = setInterval(() => {
    const burst = Math.floor(Math.random() * 2) + 1
    for(let i=0; i<burst; i++) {
      spawnMeteor()
    }
  }, 1200)
})

onUnmounted(() => {
  if (meteorTimer) clearInterval(meteorTimer)
  meteors.value = []
  stars.value = []
})
</script>

<template>
  <div class="meteor-container">
    <!-- 闪烁的背景星空 -->
    <div
      v-for="star in stars"
      :key="'s'+star.id"
      class="star"
      :style="{
        top: star.top + '%',
        left: star.left + '%',
        width: star.size + 'px',
        height: star.size + 'px',
        animationDuration: star.duration + 's',
        animationDelay: star.delay + 's'
      }"
    ></div>

    <!-- 流星层 -->
    <div
      v-for="meteor in meteors"
      :key="'m'+meteor.id"
      class="meteor"
      :style="{
        top: meteor.top + '%',
        left: meteor.left + '%',
        width: meteor.length + 'px',
        height: meteor.thickness + 'px',
        animationDuration: meteor.duration + 's',
        animationDelay: meteor.delay + 's',
        opacity: meteor.opacity
      }"
    ></div>
  </div>
</template>

<style scoped>
.meteor-container {
  position: fixed;
  inset: 0;
  overflow: hidden;
  pointer-events: none;
  z-index: 1;
}

/* --- 背景星星 --- */
.star {
  position: absolute;
  background: white;
  border-radius: 50%;
  animation: star-twinkle ease-in-out infinite alternate;
  box-shadow: 0 0 6px 1px rgba(255, 255, 255, 0.4);
}

@keyframes star-twinkle {
  0% { opacity: 0.1; transform: scale(0.8); }
  100% { opacity: 0.9; transform: scale(1.2); }
}

/* --- 逼真流星 --- */
.meteor {
  position: absolute;
  /* 左侧是实心白色（头部），向右逐渐变透明（尾巴） */
  background: linear-gradient(to right, rgba(255, 255, 255, 1) 0%, rgba(255, 255, 255, 0) 100%);
  transform-origin: left center;
  /* 旋转 -45度后，左侧（头部）会朝向左下方，右侧（尾巴）伸向右上侧 */
  transform: rotate(-45deg);
  animation: meteor-fall linear forwards;
  will-change: transform, opacity;
}

/* 耀眼的流星头部 */
.meteor::before {
  content: '';
  position: absolute;
  top: 50%;
  left: 0;
  transform: translateY(-50%);
  width: 6px;
  height: 6px;
  background: #fff;
  border-radius: 50%;
  box-shadow: 0 0 15px 3px #fff, 0 0 30px 6px rgba(100, 200, 255, 0.8); /* 尾部发蓝光 */
}

@keyframes meteor-fall {
  0% {
    /* 初始状态处于其所在的旋转坐标系原点处 */
    transform: rotate(-45deg) translateX(0);
    opacity: 0;
  }
  10% {
    opacity: 1;
  }
  80% {
    opacity: 1;
  }
  100% {
    /* 向自己的 left (负X) 方向极速滑行 */
    transform: rotate(-45deg) translateX(-150vw);
    opacity: 0;
  }
}

@media (prefers-reduced-motion: reduce) {
  .meteor, .star { animation: none; opacity: 0; }
}
</style>
