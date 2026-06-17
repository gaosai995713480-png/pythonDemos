<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import TopBar from '../components/TopBar.vue'
import TripStarMapPanel from '../components/tripstar/TripStarMapPanel.vue'
import TripStarXhsPanel from '../components/tripstar/TripStarXhsPanel.vue'
import { tripstarApi } from '../api'

const route = useRoute()
const router = useRouter()

const taskId = computed(() => String(route.params.taskId || ''))
const status = ref('processing')
const progress = ref(0)
const message = ref('正在连接 TripStar 旅行智能体...')
const result = ref(null)
const errorMsg = ref('')
const polling = ref(false)

let timer = null
let requestInFlight = false

const plan = computed(() => result.value?.data || null)
const budgetItems = computed(() => plan.value?.budget?.items || [])
const isTerminal = computed(() => ['completed', 'failed'].includes(status.value))

function stopPolling() {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
  polling.value = false
}

function applyStatus(payload) {
  status.value = payload.status || 'processing'
  progress.value = Number(payload.progress || 0)
  message.value = payload.message || payload.progress_text || ''
  if (payload.result) {
    result.value = payload.result
  }
  if (payload.error) {
    errorMsg.value = payload.error
  }
  if (status.value === 'completed' || status.value === 'failed') {
    stopPolling()
  }
}

async function loadStatus() {
  if (!taskId.value || requestInFlight || isTerminal.value) return
  requestInFlight = true
  try {
    const payload = await tripstarApi.getStatus(taskId.value)
    applyStatus(payload)
  } catch (error) {
    status.value = 'failed'
    progress.value = 100
    errorMsg.value = error?.message || '查询 TripStar 任务状态失败'
    message.value = errorMsg.value
    stopPolling()
  } finally {
    requestInFlight = false
  }
}

function startPolling() {
  if (timer || isTerminal.value) return
  polling.value = true
  timer = setInterval(loadStatus, 1000)
}

function retry() {
  router.push('/tripstar')
}

onMounted(async () => {
  await loadStatus()
  if (!isTerminal.value) {
    startPolling()
  }
})

onUnmounted(() => {
  stopPolling()
})
</script>

<template>
  <main class="tripstar-result-page">
    <TopBar title="旅行星辰" subtitle="规划结果" />

    <section class="status-card glass">
      <div class="status-header">
        <div>
          <p class="eyebrow">Task {{ taskId }}</p>
          <h1>{{ status === 'completed' ? '旅行计划已生成' : status === 'failed' ? '规划失败' : '正在生成旅行计划' }}</h1>
        </div>
        <span class="status-pill" :class="status">{{ status }}</span>
      </div>

      <div class="progress-track">
        <div class="progress-bar" :style="{ width: `${progress}%` }" />
      </div>
      <p class="status-message">{{ message }}</p>
      <p v-if="polling && !isTerminal" class="polling-tip">正在自动刷新进度，任务完成或失败后会停止轮询。</p>
      <p v-if="errorMsg" class="error-msg">{{ errorMsg }}</p>
      <button v-if="status === 'failed'" class="ghost-btn" @click="retry">重新规划</button>
    </section>

    <section v-if="plan" class="result-grid">
      <article class="overview-card glass">
        <p class="eyebrow">Overview</p>
        <h2>{{ plan.city }} · {{ plan.travel_days }} 天</h2>
        <p>{{ plan.overview }}</p>
        <div class="meta-list">
          <span>出发：{{ plan.start_date }}</span>
          <span>结束：{{ plan.end_date }}</span>
          <span v-if="plan.preferences?.length">偏好：{{ plan.preferences.join('、') }}</span>
        </div>
      </article>

      <article class="budget-card glass">
        <p class="eyebrow">Budget</p>
        <h2>{{ plan.budget?.total_estimate || '预算待补充' }}</h2>
        <ul>
          <li v-for="item in budgetItems" :key="item.category">
            <span>{{ item.category }}</span>
            <strong>{{ item.amount }}</strong>
          </li>
        </ul>
      </article>

      <TripStarMapPanel :plan="plan" />

      <TripStarXhsPanel :plan="plan" />

      <article
        v-for="day in plan.days"
        :key="day.day"
        class="day-card glass"
      >
        <div class="day-index">Day {{ day.day }}</div>
        <h2>{{ day.title }}</h2>
        <p>{{ day.summary }}</p>
        <div class="attractions">
          <div v-for="attraction in day.attractions" :key="attraction.name" class="attraction">
            <strong>{{ attraction.name }}</strong>
            <span>{{ attraction.duration }}</span>
            <p>{{ attraction.description }}</p>
          </div>
        </div>
      </article>
    </section>
  </main>
</template>

<style scoped>
.tripstar-result-page {
  min-height: 100vh;
  padding: 88px 24px 48px;
  color: var(--text-primary);
}

.glass {
  border: 1px solid var(--glass-border);
  border-radius: 28px;
  background: var(--glass-bg);
  backdrop-filter: blur(24px);
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.18);
}

.status-card {
  max-width: 1080px;
  margin: 0 auto 20px;
  padding: 30px;
}

.status-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 20px;
}

.eyebrow {
  margin: 0 0 8px;
  color: var(--primary);
  font-size: 12px;
  font-weight: 900;
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

h1,
h2 {
  margin: 0;
}

.status-pill {
  border-radius: 999px;
  padding: 8px 14px;
  background: rgba(255, 255, 255, 0.12);
  font-size: 12px;
  font-weight: 900;
  text-transform: uppercase;
}

.status-pill.completed { background: rgba(34, 197, 94, 0.22); color: #86efac; }
.status-pill.failed { background: rgba(239, 68, 68, 0.22); color: #fca5a5; }

.progress-track {
  height: 10px;
  margin: 24px 0 12px;
  overflow: hidden;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.08);
}

.progress-bar {
  height: 100%;
  border-radius: inherit;
  background: linear-gradient(90deg, var(--primary), #8b5cf6, #38bdf8);
  transition: width 0.3s ease;
}

.status-message,
.polling-tip,
.error-msg {
  margin: 8px 0 0;
  color: var(--text-secondary);
}

.error-msg {
  color: #ff8a8a;
}

.ghost-btn {
  margin-top: 16px;
  border: 1px solid rgba(255, 255, 255, 0.16);
  border-radius: 999px;
  padding: 11px 18px;
  background: rgba(255, 255, 255, 0.08);
  color: var(--text-primary);
  cursor: pointer;
}

.result-grid {
  max-width: 1080px;
  margin: 0 auto;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 18px;
}

.overview-card,
.budget-card,
.day-card {
  padding: 26px;
}

.overview-card {
  grid-column: span 2;
}

.meta-list {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 16px;
}

.meta-list span,
.day-index {
  border-radius: 999px;
  padding: 7px 12px;
  background: rgba(255, 255, 255, 0.08);
  color: var(--text-secondary);
  font-size: 13px;
}

.budget-card ul {
  list-style: none;
  padding: 0;
  margin: 18px 0 0;
}

.budget-card li {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  padding: 11px 0;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.day-card {
  grid-column: span 2;
}

.day-card > p,
.overview-card > p,
.attraction p {
  color: var(--text-secondary);
  line-height: 1.75;
}

.day-index {
  display: inline-flex;
  margin-bottom: 12px;
}

.attractions {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
  margin-top: 18px;
}

.attraction {
  border-radius: 18px;
  padding: 16px;
  background: rgba(255, 255, 255, 0.06);
}

.attraction span {
  display: block;
  margin-top: 6px;
  color: var(--primary);
  font-size: 13px;
  font-weight: 800;
}

@media (max-width: 760px) {
  .tripstar-result-page {
    padding: 72px 14px 36px;
  }

  .result-grid,
  .attractions {
    grid-template-columns: 1fr;
  }

  .overview-card,
  .day-card {
    grid-column: span 1;
  }
}
</style>
