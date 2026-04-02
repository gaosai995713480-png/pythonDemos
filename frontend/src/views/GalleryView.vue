<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { useRouter } from 'vue-router'
import TopBar from '../components/TopBar.vue'
import { photoApi, galleryApi } from '../api'
import { useAuthStore } from '../stores/auth'
import { useContextStore } from '../stores/context'

const authStore = useAuthStore()
const contextStore = useContextStore()

const router = useRouter()
const photos = ref([])
const currentIndex = ref(0)
const lightboxActive = ref(false)
const actionError = ref('')

// ===== 密码锁 =====
const STORAGE_KEY = 'gallery_unlocked'
const unlocked = ref(sessionStorage.getItem(STORAGE_KEY) === '1')
const lockPassword = ref('')
const lockError = ref('')
const lockLoading = ref(false)

async function verifyPassword() {
  if (!lockPassword.value.trim()) return
  lockLoading.value = true
  lockError.value = ''
  try {
    const data = await galleryApi.verify(lockPassword.value)
    if (data.ok) {
      unlocked.value = true
      sessionStorage.setItem(STORAGE_KEY, '1')
      await loadPhotos()
    } else {
      lockError.value = data.error || '密码错误'
    }
  } catch {
    lockError.value = '验证失败，请重试'
  } finally {
    lockLoading.value = false
  }
}

function onLockKeydown(e) {
  if (e.key === 'Enter') verifyPassword()
}

// ===== 画廊 =====
function updateGalleryContext() {
  if (lightboxActive.value) {
    const photo = photos.value[currentIndex.value]
    if (photo) {
      contextStore.setPageState(`正在大图预览相片，上传时间: ${photo.created_at || '未知'}`)
    }
  } else {
    contextStore.setPageState(`正在浏览相册列表，共 ${photos.value.length} 张照片`)
  }
}

async function loadPhotos() {
  try {
    photos.value = await photoApi.list()
    actionError.value = ''
    updateGalleryContext()
  } catch (e) {
    photos.value = []
    const message = e?.message || '照片加载失败'
    if (message === '画廊未解锁') {
      unlocked.value = false
      sessionStorage.removeItem(STORAGE_KEY)
      lockError.value = '画廊已锁定，请重新输入密码'
      return
    }
    actionError.value = message
  }
}

function openLightbox(index) {
  currentIndex.value = index
  lightboxActive.value = true
  document.body.style.overflow = 'hidden'
  updateGalleryContext()
}

function closeLightbox() {
  lightboxActive.value = false
  document.body.style.overflow = ''
  updateGalleryContext()
}

function navigate(dir) {
  currentIndex.value = (currentIndex.value + dir + photos.value.length) % photos.value.length
  updateGalleryContext()
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

// ===== 删除 =====
const deleting = ref(false)
async function handleDelete() {
  const photo = photos.value[currentIndex.value]
  if (!photo) return
  if (!confirm(`确定要永久删除这张照片吗？\n${photo.filename}`)) return
  deleting.value = true
  try {
    await photoApi.delete(photo.filename)
    photos.value.splice(currentIndex.value, 1)
    if (photos.value.length === 0) {
      closeLightbox()
    } else if (currentIndex.value >= photos.value.length) {
      currentIndex.value = photos.value.length - 1
    }
  } catch (e) {
    actionError.value = e?.message || '删除失败'
  } finally {
    deleting.value = false
  }
}

// ===== 上传/导入 =====
const uploadInput = ref(null)
const importInput = ref(null)
const uploading = ref(false)

async function handleUpload(e) {
  const files = e.target.files
  if (!files || !files.length) return
  uploading.value = true
  actionError.value = ''
  try {
    for (const file of files) {
      await photoApi.upload(file, file.name)
    }
    await loadPhotos()
  } catch (e) {
    actionError.value = e?.message || '上传失败'
  }
  finally {
    uploading.value = false
    if (uploadInput.value) uploadInput.value.value = ''
  }
}

async function handleImport(e) {
  const file = e.target.files?.[0]
  if (!file) return
  uploading.value = true
  actionError.value = ''
  try {
    await photoApi.importZip(file)
    await loadPhotos()
  } catch (e) {
    actionError.value = e?.message || '导入失败'
  }
  finally {
    uploading.value = false
    if (importInput.value) importInput.value.value = ''
  }
}

onMounted(() => {
  if (unlocked.value) loadPhotos()
  document.addEventListener('keydown', onKeydown)
})

onBeforeUnmount(() => {
  document.removeEventListener('keydown', onKeydown)
  document.body.style.overflow = ''
})
</script>

<template>
  <!-- 密码锁遮罩 -->
  <div v-if="!unlocked" class="lock-screen">
    <div class="lock-card">
      <div class="lock-icon">🔒</div>
      <h2 class="lock-title">这里是私密空间</h2>
      <p class="lock-hint">请输入画廊密码以继续</p>
      <div class="lock-input-wrap">
        <input
          v-model="lockPassword"
          type="password"
          class="lock-input"
          placeholder="请输入密码"
          autofocus
          @keydown="onLockKeydown"
        />
      </div>
      <p v-if="lockError" class="lock-error">{{ lockError }}</p>
      <button
        class="lock-btn"
        :disabled="lockLoading || !lockPassword.trim()"
        @click="verifyPassword"
      >
        {{ lockLoading ? '验证中...' : '解锁' }}
      </button>
      <button class="lock-back" @click="router.push('/')">← 返回首页</button>
    </div>
  </div>

  <!-- 画廊主体 -->
  <template v-else>
    <TopBar title="💕 心动画廊" @back="router.push('/')">
      <template v-if="authStore.isAdmin">
        <input ref="uploadInput" type="file" accept="image/*" multiple hidden @change="handleUpload" />
        <input ref="importInput" type="file" accept=".zip" hidden @change="handleImport" />
        <button class="gallery-action-btn" :disabled="uploading" @click="uploadInput?.click()">📷 上传</button>
        <button class="gallery-action-btn" :disabled="uploading" @click="importInput?.click()">📦 导入</button>
      </template>
      <span class="photo-count">{{ photos.length ? `共 ${photos.length} 张` : '' }}</span>
    </TopBar>

    <p v-if="actionError" class="gallery-error">{{ actionError }}</p>

    <div class="gallery" v-if="photos.length">
      <div
        v-for="(photo, i) in photos"
        :key="photo.id || i"
        class="gallery-item"
        @click="openLightbox(i)"
      >
        <img :src="photo.thumbnail_url || photo.url" :alt="photo.description || `照片 ${i + 1}`" loading="lazy" />
        <div class="photo-info" v-if="photo.description || photo.created_at">
          <p class="photo-date">{{ photo.created_at?.split(' ')[0] || '' }}</p>
          <p class="photo-desc" v-if="photo.description">{{ photo.description }}</p>
        </div>
      </div>
    </div>

    <div class="empty-state" v-else>还没有照片哦，快去上传吧 📸</div>

    <!-- Lightbox -->
    <Teleport to="body">
      <div class="lightbox" :class="{ 'is-active': lightboxActive }" @click.self="closeLightbox">
        <button class="lightbox-close" @click="closeLightbox">✕</button>
        <button class="lightbox-nav lightbox-prev" @click="navigate(-1)">‹</button>
        <div class="lightbox-content" v-if="photos.length">
          <img
            :key="currentIndex"
            :src="photos[currentIndex]?.url"
            :alt="photos[currentIndex]?.description || '大图'"
            @touchstart="onTouchStart"
            @touchend="onTouchEnd"
          />
          <div class="lightbox-caption" v-if="photos[currentIndex]?.description || photos[currentIndex]?.created_at">
            <span class="caption-date" v-if="photos[currentIndex]?.created_at">{{ photos[currentIndex].created_at }}</span>
            <p class="caption-desc" v-if="photos[currentIndex]?.description">{{ photos[currentIndex].description }}</p>
          </div>
        </div>
        <button class="lightbox-nav lightbox-next" @click="navigate(1)">›</button>
        <div class="lightbox-bottom">
          <div class="lightbox-counter">{{ currentIndex + 1 }} / {{ photos.length }}</div>
          <button
            v-if="authStore.isAdmin"
            class="lightbox-delete"
            :disabled="deleting"
            @click.stop="handleDelete"
          >🗑️ {{ deleting ? '删除中...' : '删除' }}</button>
        </div>
      </div>
    </Teleport>
  </template>
</template>

<style scoped>
/* ===== 密码锁 ===== */
.lock-screen {
  position: fixed;
  inset: 0;
  z-index: 50;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #0a0a1a 0%, #1a1035 50%, #0d0d2b 100%);
}

.lock-card {
  width: 92%;
  max-width: 380px;
  background: rgba(30, 30, 55, 0.85);
  backdrop-filter: blur(40px);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 28px;
  padding: 48px 32px 36px;
  text-align: center;
  animation: lockCardIn 0.5s cubic-bezier(0.16, 1, 0.3, 1);
}

@keyframes lockCardIn {
  from { opacity: 0; transform: scale(0.92) translateY(20px); }
  to { opacity: 1; transform: scale(1) translateY(0); }
}

.lock-icon {
  font-size: 56px;
  margin-bottom: 16px;
  animation: lockPulse 2s ease-in-out infinite;
}

@keyframes lockPulse {
  0%, 100% { transform: scale(1); }
  50% { transform: scale(1.08); }
}

.lock-title {
  font-size: 22px;
  font-weight: 700;
  margin-bottom: 8px;
  background: linear-gradient(135deg, #ff6b9d, #c084fc);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.lock-hint {
  font-size: 14px;
  color: rgba(255, 255, 255, 0.45);
  margin-bottom: 28px;
}

.lock-input-wrap {
  margin-bottom: 12px;
}

.lock-input {
  width: 100%;
  padding: 14px 18px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 14px;
  background: rgba(255, 255, 255, 0.06);
  color: #fff;
  font-size: 16px;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
  box-sizing: border-box;
}

.lock-input:focus {
  border-color: rgba(192, 132, 252, 0.5);
  box-shadow: 0 0 0 3px rgba(192, 132, 252, 0.15);
}

.lock-input::placeholder {
  color: rgba(255, 255, 255, 0.25);
}

.lock-error {
  color: #ff6b6b;
  font-size: 13px;
  margin-bottom: 8px;
  animation: shakeError 0.4s ease;
}

@keyframes shakeError {
  0%, 100% { transform: translateX(0); }
  20%, 60% { transform: translateX(-6px); }
  40%, 80% { transform: translateX(6px); }
}

.lock-btn {
  width: 100%;
  padding: 14px;
  border: none;
  border-radius: 14px;
  background: linear-gradient(135deg, #ff6b9d, #c084fc);
  color: #fff;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  margin-bottom: 12px;
}

.lock-btn:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 8px 24px rgba(192, 132, 252, 0.3);
}

.lock-btn:active:not(:disabled) {
  transform: translateY(0);
}

.lock-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.lock-back {
  background: none;
  border: none;
  color: rgba(255, 255, 255, 0.35);
  font-size: 13px;
  cursor: pointer;
  padding: 8px;
  transition: color 0.2s;
}

.lock-back:hover {
  color: rgba(255, 255, 255, 0.6);
}

/* ===== 画廊 ===== */
.photo-count { font-size: 13px; color: var(--text-secondary); margin-left: auto; }

.gallery-error {
  max-width: 1400px;
  margin: 88px auto 0;
  padding: 0 24px;
  color: #ff7b7b;
  font-size: 14px;
}

.gallery {
  padding: 80px 24px 40px;
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 20px;
  max-width: 1400px;
  margin: 0 auto;
}

.gallery-item {
  border-radius: 16px;
  overflow: hidden;
  cursor: pointer;
  transition: transform 0.3s, box-shadow 0.3s;
  background: rgba(25, 25, 40, 0.4);
  display: flex;
  flex-direction: column;
}

.gallery-item:hover {
  transform: translateY(-4px);
  box-shadow: 0 12px 30px rgba(0, 0, 0, 0.4);
}

.gallery-item img {
  width: 100%;
  aspect-ratio: 1 / 1;
  object-fit: cover;
  display: block;
}

.photo-info {
  padding: 12px 14px;
  background: rgba(25, 25, 40, 0.9);
  border-top: 1px solid rgba(255, 255, 255, 0.04);
}

.photo-date {
  font-size: 11px;
  color: rgba(255, 255, 255, 0.35);
  margin: 0 0 4px 0;
  letter-spacing: 0.5px;
}

.photo-desc {
  font-size: 13px;
  color: rgba(255, 255, 255, 0.85);
  margin: 0;
  line-height: 1.5;
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

.lightbox-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  max-width: 92vw;
  max-height: 90vh;
}

.lightbox-content img {
  max-width: 100%;
  max-height: calc(90vh - 80px); /* 留出底部文字的空间 */
  border-radius: 12px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.6);
  object-fit: contain;
}

.lightbox-caption {
  margin-top: 16px;
  text-align: center;
  max-width: 800px;
}

.caption-date {
  display: block;
  font-size: 12px;
  color: rgba(255, 255, 255, 0.5);
  margin-bottom: 6px;
}

.caption-desc {
  font-size: 15px;
  color: #fff;
  margin: 0;
  line-height: 1.6;
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

.lightbox-bottom {
  position: absolute; bottom: 20px; left: 50%; transform: translateX(-50%);
  display: flex; align-items: center; gap: 16px;
}

.lightbox-counter {
  padding: 6px 16px; border-radius: 20px;
  background: rgba(0, 0, 0, 0.5); font-size: 13px; color: rgba(255, 255, 255, 0.8);
}

.lightbox-delete {
  padding: 6px 16px; border-radius: 20px;
  background: rgba(220, 50, 50, 0.7); border: none;
  color: #fff; font-size: 13px; cursor: pointer;
  transition: all 0.2s; white-space: nowrap;
}

.lightbox-delete:hover:not(:disabled) { background: rgba(220, 50, 50, 0.9); }
.lightbox-delete:disabled { opacity: 0.5; cursor: not-allowed; }

@media (max-width: 1100px) { .gallery { grid-template-columns: repeat(3, 1fr); } }
@media (max-width: 768px) { .gallery { grid-template-columns: repeat(2, 1fr); padding-top: 70px; gap: 16px; } }
@media (max-width: 480px) { .gallery { grid-template-columns: repeat(1, 1fr); gap: 12px; padding: 60px 16px 30px; } }
/* ===== 上传/导入按钮 ===== */
.gallery-action-btn {
  padding: 6px 14px;
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.1);
  color: var(--text-primary);
  font-size: 13px;
  cursor: pointer;
  transition: all 0.2s;
  white-space: nowrap;
}

.gallery-action-btn:hover { background: rgba(255, 255, 255, 0.2); }
.gallery-action-btn:disabled { opacity: 0.5; cursor: not-allowed; }

@media (max-width: 720px) {
  .gallery-error { margin-top: 78px; padding: 0 12px; font-size: 13px; }
  .gallery { column-count: 2; padding: 72px 12px 24px; column-gap: 10px; }
  .gallery-item { margin-bottom: 10px; border-radius: 12px; }
  .lock-card { padding: 36px 20px 28px; }
  .gallery-action-btn { padding: 4px 10px; font-size: 12px; }
}
</style>
