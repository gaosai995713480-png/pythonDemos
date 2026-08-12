<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { tripstarApi } from '../../api'

const props = defineProps({
  plan: {
    type: Object,
    required: true,
  },
})

const loading = ref(false)
const errorMsg = ref('')
const notes = ref([])
const query = ref('')

const keyword = computed(() => {
  const preferences = props.plan?.preferences || []
  const mainPreference = preferences.find((item) => String(item).includes('美食')) || preferences[0]
  const firstAttraction = (props.plan?.days || [])
    .flatMap((day) => day.attractions || [])
    .map((item) => item.name)
    .find(Boolean)

  return [...new Set(['旅行攻略', mainPreference, firstAttraction]
    .map((item) => String(item || '').trim())
    .filter(Boolean))]
    .join(' ')
})

const stateText = computed(() => {
  if (loading.value) return '加载中'
  if (errorMsg.value) return '暂不可用'
  if (notes.value.length) return '已加载'
  if (query.value) return '暂无推荐'
  return '待加载'
})

function formatCount(value) {
  const count = Number(value || 0)
  if (!Number.isFinite(count) || count <= 0) return '0'
  if (count >= 10000) return `${(count / 10000).toFixed(1)}万`
  return String(count)
}

async function loadXhsNotes() {
  if (!props.plan?.city) return
  loading.value = true
  errorMsg.value = ''
  try {
    const payload = await tripstarApi.searchXhs({
      city: props.plan.city,
      keyword: keyword.value,
      limit: 6,
    })
    notes.value = payload.items || []
    query.value = payload.query || `${props.plan.city} ${keyword.value}`.trim()
  } catch (error) {
    notes.value = []
    errorMsg.value = error?.message || '小红书推荐加载失败'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadXhsNotes()
})

watch(
  () => props.plan,
  () => loadXhsNotes(),
  { deep: true },
)
</script>

<template>
  <article class="xhs-card glass">
    <div class="xhs-header">
      <div>
        <p class="eyebrow">Xiaohongshu</p>
        <h2>小红书推荐</h2>
      </div>
      <span class="xhs-state" :class="{ ready: notes.length, error: errorMsg }">
        {{ stateText }}
      </span>
    </div>

    <p class="xhs-desc">
      根据目的地、偏好和景点拉取小红书笔记，用于补充拍照点、避坑和本地体验。
    </p>
    <p v-if="query" class="xhs-query">搜索词：{{ query }}</p>
    <p v-if="loading" class="xhs-tip">正在加载小红书推荐...</p>
    <p v-if="errorMsg" class="xhs-error">小红书推荐暂不可用：{{ errorMsg }}</p>
    <p v-if="query && !loading && !errorMsg && !notes.length" class="xhs-empty">
      当前搜索词暂无匹配笔记，可以刷新页面或重新生成计划后再试。
    </p>

    <div v-if="notes.length" class="xhs-grid">
      <a
        v-for="note in notes"
        :key="note.id || note.title"
        class="note-card"
        :href="note.note_url || '#'"
        target="_blank"
        rel="noreferrer"
      >
        <img v-if="note.cover_url" :src="note.cover_url" alt="" loading="lazy" />
        <div class="note-body">
          <h3>{{ note.title }}</h3>
          <p v-if="note.desc">{{ note.desc }}</p>
          <div class="note-meta">
            <span>{{ note.author?.nickname || '小红书用户' }}</span>
            <strong>♥ {{ formatCount(note.liked_count) }}</strong>
          </div>
        </div>
      </a>
    </div>
  </article>
</template>

<style scoped>
.xhs-card {
  grid-column: span 2;
  padding: 26px;
}

.xhs-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
}

.eyebrow {
  margin: 0 0 8px;
  color: #fb7185;
  font-size: 12px;
  font-weight: 900;
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

h2,
h3 {
  margin: 0;
}

.xhs-state {
  border-radius: 999px;
  padding: 8px 12px;
  background: rgba(255, 255, 255, 0.08);
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 900;
}

.xhs-state.ready {
  background: rgba(34, 197, 94, 0.18);
  color: #86efac;
}

.xhs-state.error {
  background: rgba(239, 68, 68, 0.18);
  color: #fca5a5;
}

.xhs-desc,
.xhs-query,
.xhs-tip,
.xhs-error,
.xhs-empty {
  color: var(--text-secondary);
  line-height: 1.7;
}

.xhs-query {
  margin-top: 8px;
  color: #fda4af;
  font-size: 13px;
}

.xhs-error {
  color: #fca5a5;
}

.xhs-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
  margin-top: 18px;
}

.note-card {
  overflow: hidden;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 20px;
  background: rgba(255, 255, 255, 0.06);
  color: var(--text-primary);
  text-decoration: none;
  transition: transform 0.2s ease, border-color 0.2s ease;
}

.note-card:hover {
  transform: translateY(-2px);
  border-color: rgba(251, 113, 133, 0.58);
}

.note-card img {
  width: 100%;
  height: 150px;
  object-fit: cover;
  display: block;
}

.note-body {
  padding: 14px;
}

.note-body h3 {
  display: -webkit-box;
  overflow: hidden;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  font-size: 15px;
}

.note-body p {
  display: -webkit-box;
  overflow: hidden;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  min-height: 62px;
  margin: 10px 0;
  color: var(--text-secondary);
  font-size: 13px;
  line-height: 1.6;
}

.note-meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  color: var(--text-secondary);
  font-size: 12px;
}

.note-meta strong {
  color: #fda4af;
}

@media (max-width: 900px) {
  .xhs-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 760px) {
  .xhs-card {
    grid-column: span 1;
  }

  .xhs-grid {
    grid-template-columns: 1fr;
  }
}
</style>
