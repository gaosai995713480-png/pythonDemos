<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import TopBar from '../components/TopBar.vue'
import GlassModal from '../components/GlassModal.vue'
import { moodApi } from '../api'

const router = useRouter()
const MOODS = ['😆', '😊', '😌', '😐', '😢', '😤', '🥰', '😴', '🤔', '🎉']
const LEVEL_LABELS = ['低落', '一般', '还行', '开心', '超开心']

const currentYear = ref(new Date().getFullYear())
const currentMonth = ref(new Date().getMonth() + 1)
const moodData = ref({})
const showModal = ref(false)
const selectedDate = ref('')
const selectedEmoji = ref('😊')
const selectedLevel = ref(3)
const noteInput = ref('')

const weekdays = ['日', '一', '二', '三', '四', '五', '六']

async function loadMonth() {
  try {
    const items = await moodApi.list(currentYear.value, currentMonth.value)
    const map = {}
    items.forEach(item => { map[item.mood_date] = item })
    moodData.value = map
  } catch { moodData.value = {} }
}

function getCalendarDays() {
  const firstDay = new Date(currentYear.value, currentMonth.value - 1, 1).getDay()
  const daysInMonth = new Date(currentYear.value, currentMonth.value, 0).getDate()
  const today = new Date().toISOString().split('T')[0]
  const days = []
  for (let i = 0; i < firstDay; i++) days.push({ empty: true })
  for (let d = 1; d <= daysInMonth; d++) {
    const dateStr = `${currentYear.value}-${String(currentMonth.value).padStart(2, '0')}-${String(d).padStart(2, '0')}`
    const mood = moodData.value[dateStr]
    days.push({ day: d, dateStr, isToday: dateStr === today, mood })
  }
  return days
}

function getStats() {
  const entries = Object.values(moodData.value)
  const count = entries.length
  const avgLevel = count ? (entries.reduce((s, e) => s + e.level, 0) / count).toFixed(1) : '-'
  const emojiCount = {}
  entries.forEach(e => { emojiCount[e.emoji] = (emojiCount[e.emoji] || 0) + 1 })
  const topEmoji = Object.entries(emojiCount).sort((a, b) => b[1] - a[1])[0]
  return { count, avgLevel, topEmoji, avgLabel: count ? LEVEL_LABELS[Math.round(avgLevel) - 1] || '' : '' }
}

function openPicker(dateStr, existing) {
  selectedDate.value = dateStr
  selectedEmoji.value = existing ? existing.emoji : '😊'
  selectedLevel.value = existing ? existing.level : 3
  noteInput.value = existing ? (existing.note || '') : ''
  showModal.value = true
}

async function save() {
  try {
    await moodApi.save({ mood_date: selectedDate.value, emoji: selectedEmoji.value, note: noteInput.value, level: selectedLevel.value })
    showModal.value = false
    loadMonth()
  } catch { alert('保存失败') }
}

function prevMonth() {
  currentMonth.value--
  if (currentMonth.value < 1) { currentMonth.value = 12; currentYear.value-- }
  loadMonth()
}

function nextMonth() {
  currentMonth.value++
  if (currentMonth.value > 12) { currentMonth.value = 1; currentYear.value++ }
  loadMonth()
}

onMounted(loadMonth)
</script>

<template>
  <TopBar title="😊 心情日历" @back="router.push('/')" />

  <div class="container">
    <!-- Stats -->
    <div class="stats">
      <div class="stat-card"><div class="label">打卡天数</div><div class="value">{{ getStats().count }}</div></div>
      <div class="stat-card"><div class="label">平均心情</div><div class="value">{{ getStats().avgLevel }}</div><div class="sub">{{ getStats().avgLabel }}</div></div>
      <div class="stat-card"><div class="label">最常心情</div><div class="value">{{ getStats().topEmoji ? getStats().topEmoji[0] : '-' }}</div><div class="sub">{{ getStats().topEmoji ? getStats().topEmoji[1] + '次' : '' }}</div></div>
    </div>

    <!-- Calendar Header -->
    <div class="cal-header">
      <button @click="prevMonth">‹</button>
      <span class="month-label">{{ currentYear }}年{{ currentMonth }}月</span>
      <button @click="nextMonth">›</button>
    </div>

    <!-- Calendar Grid -->
    <div class="cal-grid">
      <div v-for="w in weekdays" :key="w" class="weekday">{{ w }}</div>
      <div
        v-for="(cell, i) in getCalendarDays()"
        :key="i"
        class="cal-day"
        :class="{
          'is-empty': cell.empty,
          'is-today': cell.isToday,
          'has-mood': cell.mood,
          [`level-${cell.mood?.level}`]: cell.mood,
        }"
        @click="!cell.empty && openPicker(cell.dateStr, cell.mood)"
      >
        <span v-if="cell.mood" class="emoji">{{ cell.mood.emoji }}</span>
        <span class="day-num" :style="{ fontSize: cell.mood ? '11px' : '14px' }">{{ cell.day }}</span>
      </div>
    </div>
  </div>

  <!-- Mood Picker Modal -->
  <GlassModal v-model="showModal" title="今天心情如何？">
    <div class="date-info">{{ selectedDate }}</div>
    <div class="emoji-picker">
      <button
        v-for="emoji in MOODS"
        :key="emoji"
        class="emoji-option"
        :class="{ 'is-selected': selectedEmoji === emoji }"
        @click="selectedEmoji = emoji"
      >{{ emoji }}</button>
    </div>
    <div>
      <label class="picker-label">心情等级</label>
      <div class="level-picker">
        <button
          v-for="lv in 5"
          :key="lv"
          class="level-btn"
          :class="{ 'is-selected': selectedLevel === lv }"
          :data-level="lv"
          :title="LEVEL_LABELS[lv - 1]"
          @click="selectedLevel = lv"
        >{{ lv }}</button>
      </div>
    </div>
    <input class="note-input" v-model="noteInput" placeholder="一句话记录今天..." maxlength="200" />
    <div class="modal-actions">
      <button class="btn-cancel" @click="showModal = false">取消</button>
      <button class="btn-primary" @click="save">打卡</button>
    </div>
  </GlassModal>
</template>

<style scoped>
.container { max-width: 700px; margin: 0 auto; padding: 90px 20px 60px; }

.stats { display: flex; gap: 14px; margin-bottom: 28px; flex-wrap: wrap; }
.stat-card { flex: 1; min-width: 120px; padding: 18px; border-radius: 16px; background: var(--glass-bg); backdrop-filter: blur(20px); border: 1px solid var(--glass-border); text-align: center; }
.stat-card .label { font-size: 12px; color: var(--text-secondary); margin-bottom: 6px; }
.stat-card .value { font-size: 28px; font-weight: 700; }
.stat-card .sub { font-size: 13px; color: var(--text-secondary); margin-top: 4px; }

.cal-header { display: flex; align-items: center; justify-content: center; gap: 20px; margin-bottom: 20px; }
.cal-header button { width: 36px; height: 36px; border-radius: 50%; border: none; background: rgba(255, 255, 255, 0.1); color: #fff; font-size: 18px; cursor: pointer; transition: all 0.2s; }
.cal-header button:hover { background: rgba(255, 255, 255, 0.2); }
.month-label { font-size: 20px; font-weight: 700; min-width: 140px; text-align: center; }

.cal-grid { display: grid; grid-template-columns: repeat(7, 1fr); gap: 8px; padding: 20px; border-radius: 20px; background: var(--glass-bg); backdrop-filter: blur(20px); border: 1px solid var(--glass-border); }
.weekday { text-align: center; font-size: 12px; color: var(--text-secondary); font-weight: 600; padding: 4px 0; }

.cal-day { aspect-ratio: 1; border-radius: 12px; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 2px; font-size: 13px; cursor: pointer; transition: all 0.2s; background: rgba(255, 255, 255, 0.03); }
.cal-day:hover { background: rgba(255, 255, 255, 0.12); transform: scale(1.05); }
.cal-day.is-today { border: 2px solid var(--primary); box-shadow: 0 0 12px rgba(255, 107, 157, 0.3); }
.cal-day.is-empty { pointer-events: none; background: transparent; }
.cal-day .emoji { font-size: 18px; line-height: 1; }
.cal-day .day-num { font-size: 11px; color: var(--text-secondary); }

.cal-day.level-1 { background: rgba(100, 130, 180, 0.35); }
.cal-day.level-2 { background: rgba(150, 160, 200, 0.3); }
.cal-day.level-3 { background: rgba(200, 180, 150, 0.3); }
.cal-day.level-4 { background: rgba(255, 160, 130, 0.3); }
.cal-day.level-5 { background: rgba(255, 107, 157, 0.4); box-shadow: 0 0 8px rgba(255, 107, 157, 0.2); }

/* Modal content */
.date-info { font-size: 13px; color: var(--text-secondary); margin-bottom: 18px; text-align: center; }
.emoji-picker { display: flex; justify-content: center; gap: 12px; margin-bottom: 18px; flex-wrap: wrap; }
.emoji-option { width: 52px; height: 52px; border-radius: 14px; border: 2px solid transparent; background: rgba(255, 255, 255, 0.06); font-size: 26px; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: all 0.2s; }
.emoji-option:hover { background: rgba(255, 255, 255, 0.15); transform: scale(1.1); }
.emoji-option.is-selected { border-color: var(--primary); background: rgba(255, 107, 157, 0.15); }

.picker-label { font-size: 12px; color: var(--text-secondary); margin-bottom: 8px; display: block; }
.level-picker { display: flex; justify-content: center; gap: 8px; margin-bottom: 16px; }
.level-btn { width: 40px; height: 40px; border-radius: 10px; border: 2px solid transparent; font-size: 14px; font-weight: 700; cursor: pointer; transition: all 0.2s; color: #fff; }
.level-btn:hover { transform: scale(1.1); }
.level-btn.is-selected { border-color: #fff; }
.level-btn[data-level="1"] { background: rgba(100, 130, 180, 0.5); }
.level-btn[data-level="2"] { background: rgba(150, 160, 200, 0.5); }
.level-btn[data-level="3"] { background: rgba(200, 180, 150, 0.5); }
.level-btn[data-level="4"] { background: rgba(255, 160, 130, 0.5); }
.level-btn[data-level="5"] { background: rgba(255, 107, 157, 0.6); }

.note-input { width: 100%; padding: 10px 14px; border-radius: 10px; border: 1px solid rgba(255, 255, 255, 0.2); background: rgba(255, 255, 255, 0.06); color: #fff; font-size: 14px; outline: none; margin-bottom: 16px; }
.note-input:focus { border-color: var(--primary); }

.modal-actions { display: flex; gap: 10px; }
.modal-actions button { flex: 1; padding: 10px; border-radius: 12px; border: none; font-size: 14px; font-weight: 600; cursor: pointer; }
.btn-cancel { background: rgba(255, 255, 255, 0.1); color: #fff; }

@media (max-width: 720px) {
  .cal-grid { padding: 14px; gap: 6px; }
  .cal-day .emoji { font-size: 15px; }
  .container { padding: 72px 12px 40px; }
}
</style>
