<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import TopBar from '../components/TopBar.vue'
import { usersApi } from '../api'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const authStore = useAuthStore()
const users = ref([])
const inviteCode = ref('')
const newCode = ref('')
const loading = ref(false)
const showCodeEdit = ref(false)

async function loadUsers() {
  try {
    users.value = await usersApi.list()
  } catch { /* handled by api layer */ }
}

async function loadInviteCode() {
  try {
    const data = await usersApi.getInviteCode()
    inviteCode.value = data.code || ''
    newCode.value = inviteCode.value
  } catch { /* handled */ }
}

async function toggleUser(userId) {
  if (!confirm('确定要切换该用户的状态吗？')) return
  await usersApi.toggle(userId)
  await loadUsers()
}

async function saveInviteCode() {
  if (!newCode.value.trim()) return
  loading.value = true
  try {
    await usersApi.updateInviteCode(newCode.value.trim())
    inviteCode.value = newCode.value.trim()
    showCodeEdit.value = false
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  if (!authStore.isAdmin) {
    router.replace('/')
    return
  }
  loadUsers()
  loadInviteCode()
})
</script>

<template>
  <TopBar title="用户管理" />
  <main class="users-page">
    <!-- 邀请码管理 -->
    <section class="invite-section glass-card">
      <h3>🔑 邀请码管理</h3>
      <div class="invite-row" v-if="!showCodeEdit">
        <span class="invite-label">当前邀请码：</span>
        <code class="invite-code">{{ inviteCode }}</code>
        <button class="btn-small" @click="showCodeEdit = true">修改</button>
      </div>
      <div class="invite-row" v-else>
        <input v-model="newCode" class="invite-input" placeholder="输入新邀请码" />
        <button class="btn-small btn-primary" @click="saveInviteCode" :disabled="loading">保存</button>
        <button class="btn-small" @click="showCodeEdit = false">取消</button>
      </div>
    </section>

    <!-- 用户列表 -->
    <section class="glass-card">
      <h3>👥 用户列表（{{ users.length }}）</h3>
      <div class="user-table-wrap">
        <table class="user-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>用户名</th>
              <th>角色</th>
              <th>状态</th>
              <th>注册时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="u in users" :key="u.id" :class="{ 'row-disabled': u.disabled }">
              <td>{{ u.id }}</td>
              <td>{{ u.username }}</td>
              <td><span class="role-badge" :class="u.role">{{ u.role === 'admin' ? '管理员' : '访客' }}</span></td>
              <td>
                <span class="status-dot" :class="u.disabled ? 'off' : 'on'"></span>
                {{ u.disabled ? '已禁用' : '正常' }}
              </td>
              <td class="time-col">{{ u.created_at }}</td>
              <td>
                <button
                  v-if="u.role !== 'admin'"
                  class="btn-small"
                  :class="u.disabled ? 'btn-enable' : 'btn-disable'"
                  @click="toggleUser(u.id)"
                >
                  {{ u.disabled ? '启用' : '禁用' }}
                </button>
                <span v-else class="admin-hint">—</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </main>
</template>

<style scoped>
.users-page {
  max-width: 900px;
  margin: 0 auto;
  padding: 24px 16px 60px;
}

.glass-card {
  backdrop-filter: blur(20px);
  background: var(--glass-bg);
  border: 1px solid var(--glass-border);
  border-radius: 20px;
  padding: 24px;
  margin-bottom: 20px;
}

.glass-card h3 { margin: 0 0 16px; font-size: 20px; }

.invite-section { margin-bottom: 20px; }

.invite-row {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.invite-label { color: var(--text-secondary); font-size: 14px; }

.invite-code {
  background: rgba(255, 255, 255, 0.12);
  padding: 6px 14px;
  border-radius: 8px;
  font-family: monospace;
  font-size: 16px;
  letter-spacing: 1px;
}

.invite-input {
  height: 36px;
  border: 1px solid rgba(255, 255, 255, 0.22);
  border-radius: 10px;
  padding: 0 12px;
  font-size: 14px;
  color: var(--text-primary);
  background: rgba(255, 255, 255, 0.1);
  outline: none;
  min-width: 160px;
}

.btn-small {
  padding: 6px 16px;
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.08);
  color: var(--text-primary);
  font-size: 13px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-small:hover { background: rgba(255, 255, 255, 0.16); }
.btn-small.btn-primary {
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  border-color: transparent;
  font-weight: 600;
}

.btn-disable { color: #ff6b6b; border-color: rgba(255, 107, 107, 0.3); }
.btn-disable:hover { background: rgba(255, 107, 107, 0.15); }
.btn-enable { color: #51cf66; border-color: rgba(81, 207, 102, 0.3); }
.btn-enable:hover { background: rgba(81, 207, 102, 0.15); }

.user-table-wrap { overflow-x: auto; }

.user-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 14px;
}

.user-table th, .user-table td {
  padding: 12px 14px;
  text-align: left;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.user-table th {
  color: var(--text-secondary);
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.row-disabled { opacity: 0.5; }

.role-badge {
  padding: 3px 10px;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 600;
}

.role-badge.admin {
  background: rgba(255, 107, 157, 0.2);
  color: #ff6b9d;
}

.role-badge.visitor {
  background: rgba(100, 180, 255, 0.2);
  color: #64b4ff;
}

.status-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 6px;
}

.status-dot.on { background: #51cf66; box-shadow: 0 0 6px rgba(81, 207, 102, 0.5); }
.status-dot.off { background: #ff6b6b; }

.time-col { font-size: 12px; color: var(--text-secondary); }
.admin-hint { color: var(--text-secondary); font-size: 12px; }

@media (max-width: 600px) {
  .user-table { font-size: 12px; }
  .user-table th, .user-table td { padding: 8px 6px; }
}
</style>
