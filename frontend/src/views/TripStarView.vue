<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import TopBar from '../components/TopBar.vue'
import { tripstarApi } from '../api'
import { clearRememberedTripStarTask, getRememberedTripStarTask, rememberTripStarTask } from '../utils/tripstarResume'

const router = useRouter()

const form = reactive({
  city: '',
  start_date: '',
  end_date: '',
  travel_days: 3,
  preferences: '历史文化,本地美食',
  language: 'zh',
  budget: '',
  companions: '',
  special_requirements: '',
})

const submitting = ref(false)
const errorMsg = ref('')

function normalizePayload() {
  const preferences = form.preferences
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)

  return {
    city: form.city.trim(),
    start_date: form.start_date,
    end_date: form.end_date,
    travel_days: Number(form.travel_days || 1),
    preferences,
    language: form.language,
    budget: form.budget.trim() || null,
    companions: form.companions.trim() || null,
    special_requirements: form.special_requirements.trim() || null,
  }
}

async function submitPlan() {
  errorMsg.value = ''
  const payload = normalizePayload()
  if (!payload.city) {
    errorMsg.value = '请输入目的地城市'
    return
  }
  if (!payload.start_date || !payload.end_date) {
    errorMsg.value = '请选择出发和结束日期'
    return
  }

  submitting.value = true
  try {
    const result = await tripstarApi.createPlan(payload)
    if (!result?.task_id) {
      throw new Error(result?.detail || result?.error || result?.message || 'TripStar 未返回任务 ID')
    }
    rememberTripStarTask(result.task_id)
    router.push(`/tripstar/result/${result.task_id}`)
  } catch (error) {
    errorMsg.value = error?.message || '提交旅行规划失败，请稍后重试'
  } finally {
    submitting.value = false
  }
}

async function resumeLatestTaskIfNeeded() {
  const rememberedTaskId = getRememberedTripStarTask()
  if (!rememberedTaskId) return
  try {
    await tripstarApi.getStatus(rememberedTaskId)
    router.replace(`/tripstar/result/${rememberedTaskId}`)
  } catch {
    clearRememberedTripStarTask()
  }
}

onMounted(() => {
  resumeLatestTaskIfNeeded()
})
</script>

<template>
  <main class="tripstar-page">
    <TopBar title="旅行星辰" subtitle="AI 旅行智能体" @back="router.push('/')" />

    <section class="hero glass">
      <p class="eyebrow">TripStar Agent</p>
      <h1>把“想去哪里玩”变成清晰行程</h1>
      <p class="hero-desc">
        当前先接入稳定闭环：提交任务、查看进度、展示规划结果。没有大模型 token 时会使用 mock 模式，避免页面无限等待。
      </p>
    </section>

    <section class="planner glass">
      <form class="plan-form" @submit.prevent="submitPlan">
        <label>
          <span>目的地城市</span>
          <input v-model="form.city" id="tripstar-city-input" placeholder="例如：西安" />
        </label>

        <div class="form-row">
          <label>
            <span>出发日期</span>
            <input v-model="form.start_date" type="date" />
          </label>
          <label>
            <span>结束日期</span>
            <input v-model="form.end_date" type="date" />
          </label>
        </div>

        <div class="form-row">
          <label>
            <span>旅行天数</span>
            <input v-model.number="form.travel_days" type="number" min="1" max="30" />
          </label>
          <label>
            <span>语言</span>
            <select v-model="form.language">
              <option value="zh">中文</option>
              <option value="en">English</option>
              <option value="ja">日本語</option>
            </select>
          </label>
        </div>

        <label>
          <span>偏好标签，用英文逗号分隔</span>
          <input v-model="form.preferences" placeholder="历史文化,本地美食,轻松休闲" />
        </label>

        <div class="form-row">
          <label>
            <span>预算</span>
            <input v-model="form.budget" placeholder="例如：人均 2000" />
          </label>
          <label>
            <span>同行人</span>
            <input v-model="form.companions" placeholder="例如：情侣/朋友/亲子" />
          </label>
        </div>

        <label>
          <span>特殊需求</span>
          <textarea v-model="form.special_requirements" rows="4" placeholder="例如：少走路、想看夜景、避开排队景点" />
        </label>

        <p v-if="errorMsg" class="error-msg">{{ errorMsg }}</p>
        <button class="submit-btn" :disabled="submitting">
          {{ submitting ? '正在提交...' : '生成旅行计划' }}
        </button>
      </form>
    </section>
  </main>
</template>

<style scoped>
.tripstar-page {
  min-height: 100vh;
  padding: 88px 24px 48px;
  color: var(--text-primary);
}

.glass {
  max-width: 960px;
  margin: 0 auto 20px;
  border: 1px solid var(--glass-border);
  border-radius: 28px;
  background: var(--glass-bg);
  backdrop-filter: blur(24px);
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.18);
}

.hero {
  padding: 34px 38px;
}

.eyebrow {
  margin: 0 0 10px;
  color: var(--primary);
  font-weight: 800;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.hero h1 {
  margin: 0;
  font-size: clamp(30px, 5vw, 56px);
  line-height: 1.05;
}

.hero-desc {
  max-width: 720px;
  margin: 16px 0 0;
  color: var(--text-secondary);
  line-height: 1.8;
}

.planner {
  padding: 30px;
}

.plan-form {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.form-row {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

label {
  display: flex;
  flex-direction: column;
  gap: 8px;
  font-weight: 700;
}

label span {
  color: var(--text-secondary);
  font-size: 14px;
}

input,
select,
textarea {
  width: 100%;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.08);
  color: var(--text-primary);
  padding: 13px 15px;
  outline: none;
}

textarea {
  resize: vertical;
}

.error-msg {
  margin: 0;
  color: #ff8a8a;
}

.submit-btn {
  align-self: flex-start;
  border: none;
  border-radius: 999px;
  padding: 14px 26px;
  background: linear-gradient(135deg, var(--primary), #8b5cf6);
  color: #fff;
  font-weight: 800;
  cursor: pointer;
  box-shadow: 0 12px 32px rgba(255, 107, 157, 0.28);
}

.submit-btn:disabled {
  opacity: 0.65;
  cursor: not-allowed;
}

@media (max-width: 720px) {
  .tripstar-page {
    padding: 72px 14px 36px;
  }

  .hero,
  .planner {
    padding: 22px;
  }

  .form-row {
    grid-template-columns: 1fr;
  }
}
</style>
