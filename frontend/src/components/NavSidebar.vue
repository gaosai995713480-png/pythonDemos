<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()

const groups = [
  {
    key: 'memories',
    icon: '💕',
    label: '甜蜜回忆',
    items: [
      { to: '/gallery', icon: '📸', label: '心动画廊', desc: '我们的精彩瞬间' },
      { to: '/timeline', icon: '📖', label: '时间轴', desc: '一路走来的故事' },
      { to: '/map', icon: '🗺️', label: '恋爱地图', desc: '我们去过的地方' },
    ],
  },
  {
    key: 'romance',
    icon: '💌',
    label: '浪漫表达',
    items: [
      { to: '/letter', icon: '💌', label: '表白信', desc: '写给你的情书' },
      { to: '/mood', icon: '😊', label: '心情日历', desc: '记录每天的心情' },
      { to: '/wishes', icon: '⭐', label: '星空许愿', desc: '许下我们的愿望' },
    ],
  },
  {
    key: 'music',
    icon: '🎵',
    label: '音乐空间',
    items: [
      { to: '/music', icon: '🎵', label: '音乐时光', desc: '属于我们的歌单' },
      { to: '/jukebox', icon: '🎤', label: '点歌台', desc: '朋友们的歌曲推荐' },
    ],
  },
  {
    key: 'tools',
    icon: '🔧',
    label: '生活工具',
    items: [
      { to: '/express', icon: '📦', label: '快递查询', desc: '查看物流轨迹' },
    ],
  },
]

const activeGroup = ref(null)

function toggleGroup(group) {
  activeGroup.value = activeGroup.value?.key === group.key ? null : group
}

function navigateTo(to) {
  activeGroup.value = null
  router.push(to)
}

function closePanel() {
  activeGroup.value = null
}
</script>

<template>
  <!-- 左侧一级图标栏 -->
  <aside class="nav-sidebar">
    <button
      v-for="g in groups"
      :key="g.key"
      class="sidebar-btn"
      :class="{ 'is-active': activeGroup?.key === g.key }"
      :title="g.label"
      @click.stop="toggleGroup(g)"
    >
      <span class="btn-icon">{{ g.icon }}</span>
      <span class="btn-label">{{ g.label }}</span>
    </button>
  </aside>

  <!-- 居中弹出卡片 -->
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="activeGroup" class="panel-overlay" @click="closePanel">
        <div class="panel-card" @click.stop>
          <div class="panel-header">
            <span class="panel-icon">{{ activeGroup.icon }}</span>
            <span class="panel-title">{{ activeGroup.label }}</span>
            <button class="panel-close" @click="closePanel">✕</button>
          </div>
          <div class="panel-grid">
            <button
              v-for="item in activeGroup.items"
              :key="item.to"
              class="panel-item"
              @click="navigateTo(item.to)"
            >
              <span class="pi-icon">{{ item.icon }}</span>
              <span class="pi-label">{{ item.label }}</span>
              <span class="pi-desc">{{ item.desc }}</span>
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
/* ===== 左侧图标栏 ===== */
.nav-sidebar {
  position: fixed;
  left: 0;
  top: 50%;
  transform: translateY(-50%);
  z-index: 8;
  display: flex;
  flex-direction: column;
  gap: 4px;
  background: var(--glass-bg);
  backdrop-filter: blur(24px);
  border: 1px solid var(--glass-border);
  border-left: none;
  border-radius: 0 16px 16px 0;
  padding: 10px 6px;
  box-shadow: 4px 0 20px rgba(0, 0, 0, 0.15);
}

.sidebar-btn {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 3px;
  padding: 10px 8px;
  border: none;
  border-radius: 12px;
  background: transparent;
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.2s;
  min-width: 52px;
}

.sidebar-btn:hover {
  background: rgba(255, 255, 255, 0.1);
  color: var(--text-primary);
  transform: scale(1.05);
}

.sidebar-btn.is-active {
  background: rgba(255, 107, 157, 0.15);
  color: var(--primary);
}

.btn-icon { font-size: 22px; line-height: 1; }
.btn-label { font-size: 10px; font-weight: 600; white-space: nowrap; }

/* ===== 居中弹出面板 ===== */
.panel-overlay {
  position: fixed;
  inset: 0;
  z-index: 100;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(0, 0, 0, 0.4);
  backdrop-filter: blur(6px);
}

.panel-card {
  background: var(--glass-bg);
  backdrop-filter: blur(30px);
  border: 1px solid var(--glass-border);
  border-radius: 24px;
  padding: 28px 32px 24px;
  min-width: 320px;
  max-width: 460px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
  animation: card-in 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
}

@keyframes card-in {
  from { opacity: 0; transform: scale(0.9) translateY(10px); }
  to { opacity: 1; transform: scale(1) translateY(0); }
}

.panel-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 20px;
  padding-bottom: 14px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.panel-icon { font-size: 28px; }
.panel-title { flex: 1; font-size: 20px; font-weight: 700; }

.panel-close {
  width: 32px; height: 32px; border-radius: 50%;
  border: none; background: rgba(255, 255, 255, 0.08);
  color: var(--text-secondary); font-size: 14px;
  cursor: pointer; transition: all 0.2s;
  display: flex; align-items: center; justify-content: center;
}
.panel-close:hover { background: rgba(255, 80, 80, 0.2); color: #fff; }

.panel-grid {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.panel-item {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 16px 18px;
  border-radius: 16px;
  border: 1px solid rgba(255, 255, 255, 0.06);
  background: rgba(255, 255, 255, 0.03);
  color: var(--text-primary);
  cursor: pointer;
  transition: all 0.2s;
  text-align: left;
}

.panel-item:hover {
  background: rgba(255, 255, 255, 0.1);
  border-color: rgba(255, 255, 255, 0.15);
  transform: translateX(4px);
}

.pi-icon { font-size: 28px; flex-shrink: 0; }
.pi-label { font-size: 15px; font-weight: 700; }
.pi-desc {
  font-size: 12px; color: var(--text-secondary);
  margin-left: auto; flex-shrink: 0;
}

/* 动画 */
.fade-enter-active { transition: opacity 0.2s; }
.fade-leave-active { transition: opacity 0.15s; }
.fade-enter-from, .fade-leave-to { opacity: 0; }

/* Mobile */
@media (max-width: 720px) {
  .nav-sidebar {
    top: auto;
    bottom: 80px;
    transform: none;
    flex-direction: column;
    padding: 8px 5px;
  }

  .sidebar-btn { min-width: 44px; padding: 8px 6px; }
  .btn-icon { font-size: 20px; }
  .btn-label { display: none; }

  .panel-card {
    margin: 0 16px;
    min-width: auto;
    padding: 22px 20px 18px;
  }

  .panel-item { padding: 12px 14px; }
  .pi-desc { display: none; }
}
</style>
