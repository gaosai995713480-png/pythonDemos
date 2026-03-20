<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import TopBar from '../components/TopBar.vue'
import { photoApi } from '../api'

const router = useRouter()
const photos = ref([])
const currentIndex = ref(0)
const lightboxActive = ref(false)

async function loadPhotos() {
  try {
    photos.value = await photoApi.list()
  } catch (e) { /* ignore */ }
}

function openLightbox(index) {
  currentIndex.value = index
  lightboxActive.value = true
  document.body.style.overflow = 'hidden'
}

function closeLightbox() {
  lightboxActive.value = false
  document.body.style.overflow = ''
}

function navigate(dir) {
  currentIndex.value = (currentIndex.value + dir + photos.value.length) % photos.value.length
}

function onKeydown(e) {
  if (!lightboxActive.value) return
  if (e.key === 'Escape') closeLightbox()
  if (e.key === 'ArrowLeft') navigate(-1)
  if (e.key === 'ArrowRight') navigate(1)
}

// Touch swipe
let touchStartX = 0
function onTouchStart(e) { touchStartX = e.touches[0].clientX }
function onTouchEnd(e) {
  const dx = e.changedTouches[0].clientX - touchStartX
  if (Math.abs(dx) > 50) navigate(dx > 0 ? -1 : 1)
}

onMounted(() => {
  loadPhotos()
  document.addEventListener('keydown', onKeydown)
})
</script>

<template>
  <TopBar title="💕 心动画廊" @back="router.push('/')">
    <span class="photo-count">{{ photos.length ? `共 ${photos.length} 张` : '' }}</span>
  </TopBar>

  <div class="gallery" v-if="photos.length">
    <div
      v-for="(src, i) in photos"
      :key="src"
      class="gallery-item"
      @click="openLightbox(i)"
    >
      <img :src="src" :alt="`照片 ${i + 1}`" loading="lazy" />
    </div>
  </div>

  <div class="empty-state" v-else>还没有照片哦，快去上传吧 📸</div>

  <!-- Lightbox -->
  <Teleport to="body">
    <div class="lightbox" :class="{ 'is-active': lightboxActive }" @click.self="closeLightbox">
      <button class="lightbox-close" @click="closeLightbox">✕</button>
      <button class="lightbox-nav lightbox-prev" @click="navigate(-1)">‹</button>
      <img
        v-if="photos.length"
        :src="photos[currentIndex]"
        alt="大图"
        @touchstart="onTouchStart"
        @touchend="onTouchEnd"
      />
      <button class="lightbox-nav lightbox-next" @click="navigate(1)">›</button>
      <div class="lightbox-counter">{{ currentIndex + 1 }} / {{ photos.length }}</div>
    </div>
  </Teleport>
</template>

<style scoped>
.photo-count { font-size: 13px; color: var(--text-secondary); margin-left: auto; }

.gallery {
  padding: 80px 24px 40px;
  column-count: 4;
  column-gap: 16px;
  max-width: 1400px;
  margin: 0 auto;
}

.gallery-item {
  break-inside: avoid;
  margin-bottom: 16px;
  border-radius: 16px;
  overflow: hidden;
  cursor: pointer;
  transition: transform 0.3s, box-shadow 0.3s;
}

.gallery-item:hover {
  transform: translateY(-4px);
  box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
}

.gallery-item img {
  width: 100%;
  display: block;
}

.empty-state {
  text-align: center;
  padding: 120px 24px;
  font-size: 18px;
  color: var(--text-secondary);
}

/* Lightbox */
.lightbox {
  position: fixed; inset: 0; z-index: 100;
  background: rgba(0, 0, 0, 0.92);
  backdrop-filter: blur(20px);
  display: flex; align-items: center; justify-content: center;
  opacity: 0; pointer-events: none;
  transition: opacity 0.3s;
}

.lightbox.is-active { opacity: 1; pointer-events: auto; }

.lightbox img {
  max-width: 92vw; max-height: 90vh;
  border-radius: 12px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.6);
}

.lightbox-close {
  position: absolute; top: 20px; right: 24px;
  width: 44px; height: 44px; border-radius: 50%;
  background: rgba(255, 255, 255, 0.15); border: none;
  color: #fff; font-size: 22px; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  transition: all 0.2s;
}

.lightbox-close:hover { background: rgba(255, 255, 255, 0.25); transform: scale(1.1); }

.lightbox-nav {
  position: absolute; top: 50%; transform: translateY(-50%);
  width: 48px; height: 48px; border-radius: 50%;
  background: rgba(255, 255, 255, 0.12); border: none;
  color: #fff; font-size: 22px; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  transition: all 0.2s;
}

.lightbox-nav:hover { background: rgba(255, 255, 255, 0.25); }
.lightbox-prev { left: 20px; }
.lightbox-next { right: 20px; }

.lightbox-counter {
  position: absolute; bottom: 24px; left: 50%; transform: translateX(-50%);
  padding: 6px 16px; border-radius: 20px;
  background: rgba(0, 0, 0, 0.5); font-size: 13px; color: rgba(255, 255, 255, 0.8);
}

@media (max-width: 1100px) { .gallery { column-count: 3; } }
@media (max-width: 720px) {
  .gallery { column-count: 2; padding: 72px 12px 24px; column-gap: 10px; }
  .gallery-item { margin-bottom: 10px; border-radius: 12px; }
}
</style>
