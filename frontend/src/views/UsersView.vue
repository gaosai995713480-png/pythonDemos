<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import TopBar from '../components/TopBar.vue'
import { configApi, usersApi } from '../api'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const authStore = useAuthStore()
const users = ref([])
const inviteCode = ref('')
const newCode = ref('')
const loading = ref(false)
const showCodeEdit = ref(false)
const configKeys = ref([])
const showConfigAdd = ref(false)
const configLoading = ref(false)
const configError = ref('')
const newConfig = ref({
  key: '',
  value: '',
})

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

async function loadConfigKeys() {
  try {
    const data = await configApi.listKeys()
    configKeys.value = data.items || []
  } catch { /* handled by api layer */ }
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

async function saveConfigKey() {
  const key = newConfig.value.key.trim().toUpperCase()
  if (!key) {
    configError.value = '请输入配置键'
    return
  }
  configError.value = ''
  configLoading.value = true
  try {
    await configApi.saveKey({
      key,
      value: newConfig.value.value,
    })
    newConfig.value = { key: '', value: '' }
    showConfigAdd.value = false
    await loadConfigKeys()
  } finally {
    configLoading.value = false
  }
}

onMounted(() => {
  if (!authStore.isAdmin) {
    router.replace('/')
    return
  }
  loadUsers()
  loadInviteCode()
  loadConfigKeys()
})
</script>

<template>
  <TopBar title="用户管理" @back="router.back()" />
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

    <!-- 系统配置管理 -->
    <section class="config-section glass-card">
      <div class="section-title-row">
        <h3>🧩 系统配置</h3>
        <button
          class="btn-small btn-primary"
          data-test="add-config-key"
          @click="showConfigAdd = !showConfigAdd"
        >
          {{ showConfigAdd ? '收起' : '添加 Key' }}
        </button>
      </div>

      <div v-if="showConfigAdd" class="config-add-panel">
        <input
          v-model="newConfig.key"
          class="invite-input config-key-input"
          data-test="config-key-input"
          placeholder="例如 TRIPSTAR_AMAP_WEB_KEY"
        />
        <input
          v-model="newConfig.value"
          class="invite-input config-value-input"
          data-test="config-value-input"
          placeholder="输入配置值，保存后不回显明文"
        />
        <button
          class="btn-small btn-primary"
          data-test="save-config-key"
          :disabled="configLoading"
          @click="saveConfigKey"
        >
          保存 Key
        </button>
        <p v-if="configError" class="config-error">{{ configError }}</p>
      </div>

      <div class="config-table-wrap">
        <table class="user-table config-table">
          <thead>
            <tr>
              <th>Key</th>
              <th>说明</th>
              <th>状态</th>
              <th>脱敏值</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in configKeys" :key="item.key">
              <td><code class="config-key">{{ item.key }}</code></td>
              <td>{{ item.label }}</td>
              <td>
                <span class="status-dot" :class="item.has_value ? 'on' : 'off'"></span>
                {{ item.has_value ? '已配置' : '未配置' }}
              </td>
              <td class="time-col">{{ item.masked_value || '—' }}</td>
            </tr>
            <tr v-if="configKeys.length === 0">
              <td colspan="4" class="empty-config">暂无配置项</td>
            </tr>
          </tbody>
        </table>
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
              <th>最后登录</th>
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
              <td class="time-col">
                <span v-if="u.last_login_at">{{ u.last_login_at }}</span>
                <span v-else class="admin-hint">从未登录</span>
              </td>
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
  max-width: 960px;
  margin: 0 auto;
  padding: 80px 16px 60px; /* 增加顶部内边距避开 TopBar */
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.glass-card {
  backdrop-filter: blur(40px) saturate(150%);
  background: rgba(40, 40, 45, 0.4);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 24px;
  padding: 28px;
  box-shadow: 0 16px 40px rgba(0, 0, 0, 0.2);
  transition: transform 0.3s ease;
}

.glass-card h3 { 
  margin: 0 0 20px; 
  font-size: 20px; 
  font-weight: 700;
  color: rgba(255, 255, 255, 0.95);
  display: flex; align-items: center; gap: 8px;
}

.section-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 20px;
}

.section-title-row h3 {
  margin: 0;
}

.invite-section { margin-bottom: 0px; }

.config-section { margin-bottom: 0; }

.config-add-panel {
  display: grid;
  grid-template-columns: minmax(220px, 1fr) minmax(260px, 1.2fr) auto;
  gap: 12px;
  align-items: center;
  margin-bottom: 18px;
  background: rgba(0, 0, 0, 0.15);
  padding: 16px;
  border-radius: 16px;
}

.config-key-input {
  text-transform: uppercase;
}

.config-error {
  grid-column: 1 / -1;
  margin: 0;
  color: #fca5a5;
  font-size: 13px;
}

.config-table-wrap {
  overflow-x: auto;
}

.config-table {
  margin-top: 0;
}

.config-key {
  color: #c4b5fd;
  font-family: 'Fira Code', monospace;
  font-size: 12px;
}

.empty-config {
  text-align: center;
  color: rgba(255, 255, 255, 0.45);
}

.invite-row {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
  background: rgba(0, 0, 0, 0.15);
  padding: 16px 20px;
  border-radius: 16px;
}

.invite-label { color: rgba(255, 255, 255, 0.7); font-size: 15px; }

.invite-code {
  background: linear-gradient(135deg, rgba(255,255,255,0.1), rgba(255,255,255,0.02));
  padding: 8px 16px;
  border-radius: 12px;
  font-family: 'Fira Code', monospace;
  font-size: 18px;
  color: #c4b5fd;
  letter-spacing: 2px;
  border: 1px solid rgba(255, 255, 255, 0.15);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.invite-input {
  height: 40px;
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 12px;
  padding: 0 16px;
  font-size: 15px;
  color: #fff;
  background: rgba(0, 0, 0, 0.3);
  outline: none;
  min-width: 200px;
  transition: all 0.2s;
}
.invite-input:focus { border-color: #a78bfa; background: rgba(0, 0, 0, 0.5); }

.btn-small {
  padding: 8px 16px;
  border: none;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.1);
  color: rgba(255, 255, 255, 0.9);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s cubic-bezier(0.34, 1.56, 0.64, 1);
}
.btn-small:hover { 
  background: rgba(255, 255, 255, 0.2); 
  transform: translateY(-2px);
}
.btn-small.btn-primary {
  background: linear-gradient(135deg, #667eea, #764ba2);
  color: #fff;
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
}
.btn-small.btn-primary:active { transform: translateY(0) scale(0.95); }

.user-table-wrap { overflow-x: auto; margin: 0 -8px; padding: 0 8px; }

.user-table {
  width: 100%;
  border-collapse: separate;
  border-spacing: 0 8px;
  font-size: 14px;
}

.user-table th {
  padding: 0 16px 8px;
  text-align: left;
  color: rgba(255, 255, 255, 0.5);
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.user-table td {
  padding: 14px 16px;
  background: rgba(255, 255, 255, 0.04);
  color: rgba(255, 255, 255, 0.85);
}
.user-table tr td:first-child { border-radius: 12px 0 0 12px; }
.user-table tr td:last-child { border-radius: 0 12px 12px 0; }

.user-table tbody tr { transition: all 0.2s; }
.user-table tbody tr:hover td { background: rgba(255, 255, 255, 0.08); }

.row-disabled td { opacity: 0.6; }

.role-badge {
  padding: 4px 12px;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.5px;
}
.role-badge.admin { background: rgba(244, 114, 182, 0.15); color: #f472b6; border: 1px solid rgba(244, 114, 182, 0.3); }
.role-badge.visitor { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }

.status-dot {
  display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 8px;
}
.status-dot.on { background: #34d399; box-shadow: 0 0 8px rgba(52, 211, 153, 0.8); animation: pulse-green 2s infinite; }
.status-dot.off { background: #f87171; }

@keyframes pulse-green {
  0% { box-shadow: 0 0 0 0 rgba(52, 211, 153, 0.4); }
  70% { box-shadow: 0 0 0 6px rgba(52, 211, 153, 0); }
  100% { box-shadow: 0 0 0 0 rgba(52, 211, 153, 0); }
}

.time-col { font-size: 13px; color: rgba(255, 255, 255, 0.5); font-variant-numeric: tabular-nums; }
.admin-hint { color: rgba(255, 255, 255, 0.3); font-size: 12px; font-style: italic; }

.btn-disable { background: rgba(248, 113, 113, 0.1); color: #fca5a5; border: 1px solid rgba(248, 113, 113, 0.2); }
.btn-disable:hover { background: rgba(248, 113, 113, 0.2); transform: translateY(-2px); box-shadow: 0 4px 12px rgba(248, 113, 113, 0.2); }
.btn-enable { background: rgba(52, 211, 153, 0.1); color: #6ee7b7; border: 1px solid rgba(52, 211, 153, 0.2); }
.btn-enable:hover { background: rgba(52, 211, 153, 0.2); transform: translateY(-2px); box-shadow: 0 4px 12px rgba(52, 211, 153, 0.2); }

@media (max-width: 600px) {
  .users-page { padding: 70px 12px 60px; }
  .user-table { font-size: 13px; }
  .user-table th, .user-table td { padding: 12px 8px; }
  .glass-card { padding: 20px; }
  .row-disabled td { opacity: 0.5; }
  .section-title-row { align-items: flex-start; flex-direction: column; }
  .config-add-panel { grid-template-columns: 1fr; }
}
</style>
