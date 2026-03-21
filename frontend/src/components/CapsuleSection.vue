<script setup>
/**
 * 时间胶囊组件 — 从 HomeView 拆出
 */
import { ref, onMounted } from 'vue'
import { capsuleApi } from '../api'
import { useToast } from '../composables/useToast'

const { error: toastError, success: toastSuccess } = useToast()

const capsules = ref([])
const capsuleModal = ref(false)
const capsuleForm = ref({ content: '', open_date: '' })

async function loadCapsules() {
  try { capsules.value = await capsuleApi.list() } catch { /* API layer handles toast */ }
}

async function saveCapsule() {
  if (!capsuleForm.value.content || !capsuleForm.value.open_date) {
    toastError('请填写内容和开启日期')
    return
  }
  try {
    await capsuleApi.create(capsuleForm.value)
    capsuleModal.value = false
    capsuleForm.value = { content: '', open_date: '' }
    toastSuccess('胶囊已保存 💊')
    loadCapsules()
  } catch {
    toastError('保存失败')
  }
}

async function openCapsule(id) {
  try {
    await capsuleApi.open(id)
    toastSuccess('胶囊已开启 🎉')
    loadCapsules()
  } catch { /* API layer handles toast */ }
}

defineExpose({ loadCapsules })

onMounted(() => {
  loadCapsules()
})
</script>

<template>
  <section class="capsule-section" v-if="capsules.length">
    <h3>⏰ 时间胶囊</h3>
    <div class="capsule-list">
      <div v-for="c in capsules.slice(0, 5)" :key="c.id" class="capsule-card">
        <template v-if="c.is_opened">
          <div class="capsule-content">{{ c.content }}</div>
          <div class="capsule-date">{{ c.open_date }} 已开启</div>
        </template>
        <template v-else>
          <div class="capsule-locked">🔒 {{ c.open_date }} 开启</div>
          <button v-if="new Date(c.open_date) <= new Date()" class="btn-primary btn-small" @click="openCapsule(c.id)">开启</button>
        </template>
      </div>
    </div>
  </section>
</template>

<style scoped>
.capsule-section { margin: 32px 0; text-align: left; }
.capsule-section h3 { font-size: 18px; margin-bottom: 14px; }
.capsule-list { display: flex; gap: 12px; overflow-x: auto; padding: 4px 0; }
.capsule-card {
  min-width: 200px; padding: 16px; border-radius: 16px;
  background: var(--glass-bg); backdrop-filter: blur(20px);
  border: 1px solid var(--glass-border); flex-shrink: 0;
}
.capsule-content { font-size: 14px; line-height: 1.5; margin-bottom: 8px; }
.capsule-date { font-size: 12px; color: var(--accent); }
.capsule-locked { font-size: 14px; color: var(--text-secondary); }
.btn-small { padding: 6px 14px; font-size: 12px; margin-top: 8px; }
</style>
