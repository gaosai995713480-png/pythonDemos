<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import TopBar from '../components/TopBar.vue'
import GlassModal from '../components/GlassModal.vue'
import { timelineApi } from '../api'

const router = useRouter()
const items = ref([])
const showModal = ref(false)
const form = ref({ date: '', title: '', content: '', icon: '💕' })

async function load() {
  try { items.value = await timelineApi.list() } catch { /* ignore */ }
}

function openAdd() {
  form.value = { date: new Date().toISOString().split('T')[0], title: '', content: '', icon: '💕' }
  showModal.value = true
}

async function save() {
  if (!form.value.date || !form.value.title) { alert('日期和标题不能为空'); return }
  try {
    await timelineApi.create({
      event_date: form.value.date,
      title: form.value.title,
      content: form.value.content,
      icon: form.value.icon || '💕',
    })
    showModal.value = false
    load()
  } catch { alert('保存失败') }
}

async function remove(id) {
  if (!confirm('确定要删除这条记录吗？')) return
  try { await timelineApi.remove(id); load() } catch { /* ignore */ }
}

onMounted(load)
</script>

<template>
  <TopBar title="📖 恋爱时间轴" @back="router.push('/')">
    <button class="btn-primary add-btn" @click="openAdd">+ 添加事件</button>
  </TopBar>

  <div class="timeline-wrap" v-if="items.length">
    <div class="timeline-line"></div>
    <div
      v-for="(item, i) in items"
      :key="item.id"
      class="timeline-card"
      :style="{ animationDelay: `${i * 0.1}s` }"
    >
      <div class="dot"></div>
      <div class="icon">{{ item.icon || '💕' }}</div>
      <div class="date">{{ item.event_date }}</div>
      <div class="title">{{ item.title }}</div>
      <div v-if="item.content" class="content">{{ item.content }}</div>
      <img v-if="item.photo_url" class="photo" :src="item.photo_url" alt="" />
      <button class="delete-btn" @click="remove(item.id)">✕</button>
    </div>
  </div>

  <div class="empty-state" v-else>还没有记录哦，点击右上角开始记录你们的故事 ✨</div>

  <GlassModal v-model="showModal" title="📝 记录一个瞬间">
    <div class="form-group">
      <label>日期 *</label>
      <input type="date" v-model="form.date" />
    </div>
    <div class="form-group">
      <label>标题 *</label>
      <input type="text" v-model="form.title" placeholder="例如：第一次牵手" maxlength="100" />
    </div>
    <div class="form-group">
      <label>详细描述</label>
      <textarea v-model="form.content" placeholder="那天发生了什么..."></textarea>
    </div>
    <div class="form-group">
      <label>图标 emoji</label>
      <input type="text" v-model="form.icon" maxlength="4" style="width: 80px" />
    </div>
    <div class="form-actions">
      <button class="btn-cancel" @click="showModal = false">取消</button>
      <button class="btn-primary" @click="save">保存</button>
    </div>
  </GlassModal>
</template>

<style scoped>
.add-btn { margin-left: auto; font-size: 14px; padding: 8px 18px; }

.timeline-wrap { max-width: 900px; margin: 0 auto; padding: 90px 24px 60px; position: relative; }

.timeline-line {
  position: absolute; left: 50%; top: 90px; bottom: 60px; width: 3px;
  background: linear-gradient(180deg, rgba(255, 107, 157, 0.6), rgba(196, 69, 105, 0.2));
  transform: translateX(-50%); border-radius: 2px;
}

.timeline-card {
  position: relative; width: 44%; padding: 24px; margin-bottom: 40px;
  background: var(--glass-bg); backdrop-filter: blur(26px);
  border: 1px solid var(--glass-border); border-radius: 20px;
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.25);
  opacity: 0; transform: translateX(-30px);
  animation: slide-in 0.5s ease forwards;
}

.timeline-card:nth-child(even) { margin-left: 6%; }
.timeline-card:nth-child(odd) { margin-left: 50%; transform: translateX(30px); animation-name: slide-in-right; }

.dot {
  position: absolute; top: 28px; width: 16px; height: 16px;
  border-radius: 50%; background: linear-gradient(135deg, var(--primary), var(--secondary));
  box-shadow: 0 0 12px rgba(255, 107, 157, 0.5);
}

.timeline-card:nth-child(even) .dot { right: -36px; }
.timeline-card:nth-child(odd) .dot { left: -36px; }

.icon { font-size: 28px; margin-bottom: 8px; }
.date { font-size: 12px; color: var(--accent); font-weight: 600; letter-spacing: 0.5px; margin-bottom: 6px; }
.title { font-size: 18px; font-weight: 700; margin-bottom: 8px; }
.content { font-size: 14px; line-height: 1.7; color: var(--text-secondary); }
.photo { width: 100%; border-radius: 12px; margin-top: 12px; object-fit: cover; max-height: 200px; }

.delete-btn {
  position: absolute; top: 12px; right: 12px; width: 28px; height: 28px;
  border-radius: 50%; border: none; background: rgba(255, 255, 255, 0.1);
  color: rgba(255, 255, 255, 0.5); font-size: 14px; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  opacity: 0; transition: all 0.2s;
}

.timeline-card:hover .delete-btn { opacity: 1; }
.delete-btn:hover { background: rgba(255, 80, 80, 0.3); color: #fff; }

.empty-state { text-align: center; padding: 160px 24px 80px; font-size: 18px; color: var(--text-secondary); }

/* Form */
.form-group { margin-bottom: 14px; }
.form-group label { display: block; font-size: 13px; color: var(--text-secondary); margin-bottom: 6px; }
.form-group input, .form-group textarea {
  width: 100%; padding: 10px 14px; border-radius: 10px;
  border: 1px solid rgba(255, 255, 255, 0.2); background: rgba(255, 255, 255, 0.06);
  color: #fff; font-size: 14px; outline: none; transition: border-color 0.2s;
}
.form-group input:focus, .form-group textarea:focus {
  border-color: var(--primary); box-shadow: 0 0 0 3px rgba(255, 107, 157, 0.15);
}
.form-group textarea { resize: vertical; min-height: 80px; }
.form-actions { display: flex; gap: 10px; margin-top: 18px; }
.form-actions button { flex: 1; padding: 10px; border-radius: 12px; border: none; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
.btn-cancel { background: rgba(255, 255, 255, 0.1); color: #fff; border: 1px solid rgba(255, 255, 255, 0.2); }

@media (max-width: 720px) {
  .timeline-line { left: 24px; }
  .timeline-card { width: calc(100% - 50px); margin-left: 50px !important; transform: translateX(20px); }
  .timeline-card:nth-child(odd) { transform: translateX(20px); animation-name: slide-in; }
  .dot { left: -36px !important; right: auto !important; }
}
</style>
