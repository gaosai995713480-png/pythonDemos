<script setup>
import { ref, reactive, nextTick, onMounted, computed } from 'vue'
import { useAuthStore } from '../stores/auth'

const authStore = useAuthStore()

const isOpen = ref(false)
const isLoading = ref(false)
const inputText = ref('')
let abortController = null
const listRef = ref(null)

// 当前选中的供应商
const activeProvider = ref('codex') // 'codex' | 'claude'

// 各供应商状态
const providerStatus = reactive({
  claude: { available: false, model: '' },
  codex: { available: false, model: '', base_url: '' },
  glm: { available: false, model: '', base_url: '' },
  grok: { available: false, model: '', base_url: '' },
})

// 各供应商独立对话历史
const claudeMessages = ref([])
const codexMessages = ref([])
const glmMessages = ref([])
const grokMessages = ref([])

const currentMessages = computed(() => {
  if (activeProvider.value === 'claude') return claudeMessages.value
  if (activeProvider.value === 'glm') return glmMessages.value
  if (activeProvider.value === 'grok') return grokMessages.value
  return codexMessages.value
})

// ===== localStorage 持久化 =====
const MAX_MESSAGES = 50

function chatStorageKey(provider) {
  const user = authStore.username || 'anonymous'
  return `ai_chat_${provider}_${user}`
}

function loadMessages(provider) {
  try {
    const raw = localStorage.getItem(chatStorageKey(provider))
    if (raw) return JSON.parse(raw)
  } catch { /* 脏数据容错 */ }
  return []
}

function saveMessages(provider) {
  const msgsMap = { claude: claudeMessages.value, codex: codexMessages.value, glm: glmMessages.value, grok: grokMessages.value }
  const msgs = msgsMap[provider]
  const toSave = msgs.slice(-MAX_MESSAGES)
  try {
    localStorage.setItem(chatStorageKey(provider), JSON.stringify(toSave))
  } catch { /* 存储满容错 */ }
}

// 配置面板
const showConfig = ref(false)
const configSaving = ref(false)
const claudeConfig = ref({ model: 'claude-sonnet-4-20250514' })
const codexConfig = ref({ base_url: '', api_key: '', model: 'gpt-5.4-codex' })
const glmConfig = ref({ base_url: 'https://open.bigmodel.cn/api/paas/v4', api_key: '', model: 'glm-4-flash' })
const grokConfig = ref({ base_url: 'https://api.x.ai', api_key: '', model: 'grok-3' })

// 检查供应商状态
async function checkStatus() {
  try {
    const res = await fetch('/api/ai/status')
    if (res.ok) {
      const data = await res.json()
      Object.assign(providerStatus.claude, data.claude)
      Object.assign(providerStatus.codex, data.codex)
      Object.assign(providerStatus.glm, data.glm)
      if (data.grok) Object.assign(providerStatus.grok, data.grok)
    }
  } catch { /* ignore */ }
}

// 加载配置
async function loadConfig() {
  try {
    const [cRes, xRes, gRes, kRes] = await Promise.all([
      fetch('/api/ai/config/claude'),
      fetch('/api/ai/config/codex'),
      fetch('/api/ai/config/glm'),
      fetch('/api/ai/config/grok'),
    ])
    if (cRes.ok) {
      const d = await cRes.json()
      claudeConfig.value.model = d.model || ''
    }
    if (xRes.ok) {
      const d = await xRes.json()
      codexConfig.value.base_url = d.base_url || ''
      codexConfig.value.model = d.model || ''
    }
    if (gRes.ok) {
      const d = await gRes.json()
      glmConfig.value.base_url = d.base_url || ''
      glmConfig.value.model = d.model || ''
    }
    if (kRes.ok) {
      const d = await kRes.json()
      grokConfig.value.base_url = d.base_url || ''
      grokConfig.value.model = d.model || ''
    }
  } catch { /* ignore */ }
}

// 保存 Claude 配置
async function saveClaudeConfig() {
  configSaving.value = true
  try {
    await fetch('/api/ai/config/claude', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(claudeConfig.value),
    })
    await checkStatus()
  } catch { /* ignore */ }
  configSaving.value = false
}

// 保存 Codex 配置
async function saveCodexConfig() {
  configSaving.value = true
  try {
    await fetch('/api/ai/config/codex', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(codexConfig.value),
    })
    await checkStatus()
  } catch { /* ignore */ }
  configSaving.value = false
}

// 保存 GLM 配置
async function saveGlmConfig() {
  configSaving.value = true
  try {
    await fetch('/api/ai/config/glm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(glmConfig.value),
    })
    await checkStatus()
  } catch { /* ignore */ }
  configSaving.value = false
}

// 保存 Grok 配置
async function saveGrokConfig() {
  configSaving.value = true
  try {
    await fetch('/api/ai/config/grok', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(grokConfig.value),
    })
    await checkStatus()
  } catch { /* ignore */ }
  configSaving.value = false
}

function openConfig() {
  loadConfig()
  loadSkills()
  showConfig.value = true
}

// ===== 技能预设 =====
const skillsList = ref([])
const showSkillDropdown = ref(false)
const showSkillForm = ref(false)
const editingSkill = ref(null)
const skillForm = ref({ name: '', icon: '🤖', system_prompt: '' })

// 每个供应商独立的激活技能
const activeSkills = reactive({}) // { codex: {id,name,icon,...}, glm: null, ... }

function skillStorageKey() {
  const user = authStore.username || 'anonymous'
  return `ai_active_skills_${user}`
}

function loadActiveSkills() {
  try {
    const raw = localStorage.getItem(skillStorageKey())
    if (raw) Object.assign(activeSkills, JSON.parse(raw))
  } catch { /* ignore */ }
}

function saveActiveSkills() {
  try {
    localStorage.setItem(skillStorageKey(), JSON.stringify(activeSkills))
  } catch { /* ignore */ }
}

function setActiveSkill(provider, skill) {
  activeSkills[provider] = skill
  saveActiveSkills()
  showSkillDropdown.value = false
}

function clearActiveSkill(provider) {
  activeSkills[provider] = null
  saveActiveSkills()
}

async function loadSkills() {
  try {
    const res = await fetch('/api/ai/skills')
    if (res.ok) skillsList.value = await res.json()
  } catch { /* ignore */ }
}

async function saveSkill() {
  const body = { name: skillForm.value.name, icon: skillForm.value.icon, system_prompt: skillForm.value.system_prompt }
  try {
    let res
    if (editingSkill.value) {
      res = await fetch(`/api/ai/skills/${editingSkill.value.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
    } else {
      res = await fetch('/api/ai/skills', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
    }
    if (!res.ok) {
      const err = await res.text()
      console.error('Skill save failed:', res.status, err)
      alert(`保存失败: ${res.status}`)
      return
    }
    await loadSkills()
    showSkillForm.value = false
    editingSkill.value = null
    skillForm.value = { name: '', icon: '🤖', system_prompt: '' }
  } catch (e) { console.error('Skill save error:', e) }
}

function startEditSkill(skill) {
  editingSkill.value = skill
  skillForm.value = { name: skill.name, icon: skill.icon, system_prompt: skill.system_prompt }
  showSkillForm.value = true
}

function startCreateSkill() {
  editingSkill.value = null
  skillForm.value = { name: '', icon: '🤖', system_prompt: '' }
  showSkillForm.value = true
}

async function deleteSkill(skill) {
  try {
    await fetch(`/api/ai/skills/${skill.id}`, { method: 'DELETE' })
    await loadSkills()
    // 如果删除的是当前激活的，清除激活
    for (const p of ['codex', 'glm', 'grok', 'claude']) {
      if (activeSkills[p]?.id === skill.id) activeSkills[p] = null
    }
    saveActiveSkills()
  } catch { /* ignore */ }
}

onMounted(() => {
  checkStatus()
  initMessages('claude')
  initMessages('codex')
  initMessages('glm')
  initMessages('grok')
  loadSkills()
  loadActiveSkills()
})

function toggleChat() {
  isOpen.value = !isOpen.value
  if (isOpen.value) scrollToBottom()
}

function initMessages(provider) {
  const msgsMap = { claude: claudeMessages, codex: codexMessages, glm: glmMessages, grok: grokMessages }
  const msgs = msgsMap[provider]
  if (msgs.value.length > 0) return

  const saved = loadMessages(provider)
  if (saved.length > 0) {
    msgs.value = saved
  } else {
    const labels = { claude: 'Claude', codex: 'Codex', glm: 'GLM', grok: 'Grok' }
    msgs.value.push({
      role: 'assistant',
      content: `你好！我是 ${labels[provider]}，有什么可以帮你的吗？ 😊`,
    })
  }
}

function switchProvider(p) {
  if (isLoading.value) return
  activeProvider.value = p
  showConfig.value = false
  scrollToBottom()
}

function scrollToBottom() {
  nextTick(() => {
    if (listRef.value) listRef.value.scrollTop = listRef.value.scrollHeight
  })
}

function stopGeneration() {
  if (abortController) {
    abortController.abort()
    abortController = null
  }
  isLoading.value = false
}

async function sendMessage() {
  const text = inputText.value.trim()
  if (!text || isLoading.value) return

  const msgsMap = { claude: claudeMessages, codex: codexMessages, glm: glmMessages, grok: grokMessages }
  const msgs = msgsMap[activeProvider.value]

  msgs.value.push({ role: 'user', content: text })
  inputText.value = ''
  scrollToBottom()

  const history = msgs.value
    .filter((m, i) => !(i === 0 && m.role === 'assistant'))
    .slice(0, -1)
    .map(m => ({ role: m.role, content: m.content }))

  msgs.value.push({ role: 'assistant', content: '' })
  const aiMsg = msgs.value[msgs.value.length - 1]  // 获取响应式代理引用
  isLoading.value = true
  abortController = new AbortController()
  scrollToBottom()

  try {
    const res = await fetch('/api/ai/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: text,
        history,
        provider: activeProvider.value,
        skill_id: activeSkills[activeProvider.value]?.id || null,
      }),
      signal: abortController.signal,
    })

    if (!res.ok) {
      aiMsg.content = `请求失败 (${res.status})`
      isLoading.value = false
      return
    }

    const reader = res.body.getReader()
    const decoder = new TextDecoder()
    let sseBuffer = ''

    // 打字机缓冲区
    let textBuffer = ''       // SSE 收到但尚未渲染的字符
    let typewriterDone = false
    let streamDone = false
    const CHAR_INTERVAL = 18  // 每个字符的渲染间隔(ms)

    // 启动逐字输出定时器
    let lastTime = 0
    function typewriterTick(timestamp) {
      if (!lastTime) lastTime = timestamp
      const elapsed = timestamp - lastTime

      if (elapsed >= CHAR_INTERVAL && textBuffer.length > 0) {
        // 每次取 1~3 个字符（buffer 积压多时加速）
        const chunkSize = textBuffer.length > 50 ? 3 : textBuffer.length > 20 ? 2 : 1
        aiMsg.content += textBuffer.slice(0, chunkSize)
        textBuffer = textBuffer.slice(chunkSize)
        lastTime = timestamp
        scrollToBottom()
      }

      if (!streamDone || textBuffer.length > 0) {
        requestAnimationFrame(typewriterTick)
      } else {
        typewriterDone = true
      }
    }
    requestAnimationFrame(typewriterTick)

    // SSE 读取循环 — 数据写入 buffer 而非直接渲染
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      sseBuffer += decoder.decode(value, { stream: true })

      const lines = sseBuffer.split('\n')
      sseBuffer = lines.pop()

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue
        const data = line.slice(6)
        if (data === '[DONE]') break

        try {
          textBuffer += JSON.parse(data)
        } catch {
          textBuffer += data
        }
      }
    }

    // SSE 结束，flush 缓冲区剩余内容
    streamDone = true
    // 等待打字机输出完毕（最多 5 秒）
    if (textBuffer.length > 0) {
      await new Promise(resolve => {
        const checkFlush = () => {
          if (typewriterDone || textBuffer.length === 0) {
            // 确保全部输出
            if (textBuffer.length > 0) {
              aiMsg.content += textBuffer
              textBuffer = ''
              scrollToBottom()
            }
            resolve()
          } else {
            setTimeout(checkFlush, 50)
          }
        }
        checkFlush()
      })
    }

    if (!aiMsg.content) aiMsg.content = '抱歉，没有收到回复。'
  } catch (e) {
    if (e.name === 'AbortError') {
      // 停止生成时，flush 剩余 buffer
      if (!aiMsg.content) aiMsg.content = '（已停止生成）'
    } else {
      aiMsg.content += `\n\n连接失败: ${e.message}`
    }
  } finally {
    isLoading.value = false
    abortController = null
    saveMessages(activeProvider.value)
    scrollToBottom()
  }
}

function handleKeydown(e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault()
    sendMessage()
  }
}

function clearChat() {
  const msgsMap = { claude: claudeMessages, codex: codexMessages, glm: glmMessages, grok: grokMessages }
  const labels = { claude: 'Claude', codex: 'Codex', glm: 'GLM', grok: 'Grok' }
  const msgs = msgsMap[activeProvider.value]
  msgs.value = [{
    role: 'assistant',
    content: `你好！我是 ${labels[activeProvider.value]}，有什么可以帮你的吗？ 😊`,
  }]
  saveMessages(activeProvider.value)
}

async function handleBubbleClick(e) {
  const btn = e.target.closest('.code-copy-btn')
  if (!btn) return

  const code = decodeURIComponent(btn.dataset.code || '')
  if (!code) return

  let success = false

  // 优先使用现代 Clipboard API（仅 HTTPS / localhost 可用）
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(code)
      success = true
    } catch { /* fallback below */ }
  }

  // 降级方案：通过临时 textarea + execCommand 实现（兼容 HTTP 环境）
  if (!success) {
    const ta = document.createElement('textarea')
    ta.value = code
    ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0'
    document.body.appendChild(ta)
    ta.select()
    try {
      success = document.execCommand('copy')
    } catch { /* ignore */ }
    document.body.removeChild(ta)
  }

  if (success) {
    const originalHTML = btn.innerHTML
    btn.innerHTML = `<svg class="copy-icon success" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M5 13L9 17L19 7" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`
    btn.classList.add('copied')
    setTimeout(() => {
      btn.innerHTML = originalHTML
      btn.classList.remove('copied')
    }, 2000)
  }
}
</script>

<template>
  <Teleport to="body">
    <!-- 悬浮气泡 -->
    <button class="ai-fab" :class="{ 'is-open': isOpen }" @click="toggleChat">
      <span class="ai-fab-icon">{{ isOpen ? '✕' : '🤖' }}</span>
      <span v-if="!isOpen" class="ai-fab-pulse"></span>
    </button>

    <!-- 聊天面板 -->
    <Transition name="chat-slide">
      <div v-if="isOpen" class="ai-chat-panel">
        <!-- 标题栏 -->
        <div class="chat-header">
          <span class="chat-header-icon">🤖</span>

          <!-- 供应商切换器 -->
          <div class="provider-switcher">
            <button
              class="provider-tab"
              :class="{ active: activeProvider === 'codex' }"
              @click="switchProvider('codex')"
            >
              <span class="provider-dot" :class="{ online: providerStatus.codex.available }"></span>
              Codex
            </button>
            <button
              class="provider-tab"
              :class="{ active: activeProvider === 'glm' }"
              @click="switchProvider('glm')"
            >
              <span class="provider-dot" :class="{ online: providerStatus.glm.available }"></span>
              GLM
            </button>
            <button
              class="provider-tab"
              :class="{ active: activeProvider === 'grok' }"
              @click="switchProvider('grok')"
            >
              <span class="provider-dot" :class="{ online: providerStatus.grok.available }"></span>
              Grok
            </button>
            <button
              class="provider-tab"
              :class="{ active: activeProvider === 'claude' }"
              @click="switchProvider('claude')"
            >
              <span class="provider-dot" :class="{ online: providerStatus.claude.available }"></span>
              Claude
            </button>
          </div>

          <button class="chat-header-btn" title="配置" @click="openConfig">⚙️</button>
          <button class="chat-header-btn" title="清空对话" @click="clearChat">🗑️</button>
          <button class="chat-header-close" @click="isOpen = false">✕</button>
        </div>

        <!-- 技能选择器 -->
        <div v-if="!showConfig" class="skill-selector-bar">
          <div class="skill-active-tag" v-if="activeSkills[activeProvider]" @click="showSkillDropdown = !showSkillDropdown">
            <span>{{ activeSkills[activeProvider].icon }} {{ activeSkills[activeProvider].name }}</span>
            <button class="skill-clear-btn" @click.stop="clearActiveSkill(activeProvider)">×</button>
          </div>
          <button v-else class="skill-select-btn" @click="showSkillDropdown = !showSkillDropdown">
            🎭 选择技能
          </button>
          <div v-if="showSkillDropdown" class="skill-dropdown">
            <div v-if="skillsList.length === 0" class="skill-dropdown-empty">
              暂无技能预设，点击 ⚙️ 创建
            </div>
            <button
              v-for="s in skillsList"
              :key="s.id"
              class="skill-dropdown-item"
              :class="{ active: activeSkills[activeProvider]?.id === s.id }"
              @click="setActiveSkill(activeProvider, s)"
            >
              <span class="skill-dropdown-icon">{{ s.icon }}</span>
              <span class="skill-dropdown-name">{{ s.name }}</span>
            </button>
          </div>
        </div>

        <!-- 配置面板 -->
        <div v-if="showConfig" class="chat-config">
          <div class="config-title">
            <span>AI 设置</span>
            <button class="config-back" @click="showConfig = false">← 返回</button>
          </div>

          <!-- 技能管理（所有登录用户） -->
          <div class="config-section">
            <div class="config-section-title">🎭 技能预设</div>
            <div class="config-hint">💡 创建自定义角色（系统提示词），对话时选择激活</div>

            <div v-if="showSkillForm" class="skill-form">
              <div class="config-field">
                <label>图标 + 名称</label>
                <div class="skill-name-row">
                  <input v-model="skillForm.icon" type="text" class="skill-icon-input" maxlength="4" />
                  <input v-model="skillForm.name" type="text" placeholder="技能名称" class="skill-name-input" />
                </div>
              </div>
              <div class="config-field">
                <label>系统提示词</label>
                <textarea v-model="skillForm.system_prompt" placeholder="你是一个 Python 专家，擅长..." rows="4" class="skill-prompt-input"></textarea>
              </div>
              <div class="skill-form-actions">
                <button class="config-save" :disabled="!skillForm.name || !skillForm.system_prompt" @click="saveSkill">
                  {{ editingSkill ? '✅ 更新' : '➕ 创建' }}
                </button>
                <button class="skill-cancel-btn" @click="showSkillForm = false">取消</button>
              </div>
            </div>

            <div v-else>
              <div v-if="skillsList.length === 0" class="skill-empty">还没有技能，点击下方按钮创建第一个！</div>
              <div v-for="s in skillsList" :key="s.id" class="skill-card">
                <div class="skill-card-info">
                  <span class="skill-card-icon">{{ s.icon }}</span>
                  <div>
                    <div class="skill-card-name">{{ s.name }}</div>
                    <div class="skill-card-preview">{{ s.system_prompt.slice(0, 60) }}{{ s.system_prompt.length > 60 ? '...' : '' }}</div>
                  </div>
                </div>
                <div class="skill-card-actions">
                  <button @click="startEditSkill(s)" title="编辑">✏️</button>
                  <button @click="deleteSkill(s)" title="删除">🗑️</button>
                </div>
              </div>
              <button class="skill-add-btn" @click="startCreateSkill">➕ 新建技能</button>
            </div>
          </div>

          <!-- 管理员供应商配置 -->
          <template v-if="authStore.isAdmin">
            <div class="config-divider"></div>
            <div style="padding: 0 14px; color: rgba(255,255,255,0.5); font-size: 11px; text-align: center;">—— 以下为管理员配置 ——</div>

            <div class="config-section">
              <div class="config-section-title">🟢 Codex</div>
              <div class="config-field"><label>API 地址</label><input v-model="codexConfig.base_url" type="text" placeholder="https://ai.qaq.al" /></div>
              <div class="config-field"><label>API Key</label><input v-model="codexConfig.api_key" type="password" placeholder="sk-..." /></div>
              <div class="config-field"><label>模型</label><input v-model="codexConfig.model" type="text" placeholder="gpt-5.4-codex" /></div>
              <button class="config-save" :disabled="!codexConfig.base_url || !codexConfig.api_key || configSaving" @click="saveCodexConfig">{{ configSaving ? '保存中...' : '💾 保存 Codex' }}</button>
            </div>
            <div class="config-divider"></div>
            <div class="config-section">
              <div class="config-section-title">🔵 GLM</div>
              <div class="config-field"><label>API 地址</label><input v-model="glmConfig.base_url" type="text" placeholder="https://open.bigmodel.cn/api/paas/v4" /></div>
              <div class="config-field"><label>API Key</label><input v-model="glmConfig.api_key" type="password" placeholder="智谱 API Key" /></div>
              <div class="config-field"><label>模型</label><input v-model="glmConfig.model" type="text" placeholder="glm-4-flash" /></div>
              <button class="config-save" :disabled="!glmConfig.base_url || !glmConfig.api_key || configSaving" @click="saveGlmConfig">{{ configSaving ? '保存中...' : '💾 保存 GLM' }}</button>
            </div>
            <div class="config-divider"></div>
            <div class="config-section">
              <div class="config-section-title">🟠 Grok</div>
              <div class="config-field"><label>API 地址</label><input v-model="grokConfig.base_url" type="text" placeholder="https://api.x.ai" /></div>
              <div class="config-field"><label>API Key</label><input v-model="grokConfig.api_key" type="password" placeholder="xai-..." /></div>
              <div class="config-field"><label>模型</label><input v-model="grokConfig.model" type="text" placeholder="grok-3" /></div>
              <button class="config-save" :disabled="!grokConfig.base_url || !grokConfig.api_key || configSaving" @click="saveGrokConfig">{{ configSaving ? '保存中...' : '💾 保存 Grok' }}</button>
            </div>
            <div class="config-divider"></div>
            <div class="config-section">
              <div class="config-section-title">🟣 Claude (CLI)</div>
              <div class="config-hint">💡 使用本地 Claude CLI，无需 API 地址和密钥</div>
              <div class="config-field"><label>模型</label><input v-model="claudeConfig.model" type="text" placeholder="claude-sonnet-4-20250514" /></div>
              <button class="config-save" :disabled="configSaving" @click="saveClaudeConfig">{{ configSaving ? '保存中...' : '💾 保存 Claude' }}</button>
            </div>
          </template>
        </div>

        <!-- 不可用提示 -->
        <div v-else-if="!providerStatus[activeProvider]?.available" class="chat-unavailable">
          <p>⚠️ {{ { claude: 'Claude CLI', codex: 'Codex API', glm: 'GLM API', grok: 'Grok API' }[activeProvider] }} 未配置</p>
          <p v-if="authStore.isAdmin" class="chat-unavailable-hint">点击 ⚙️ 进行配置</p>
          <p v-else class="chat-unavailable-hint">请联系管理员配置</p>
        </div>

        <!-- 消息列表 -->
        <div v-else ref="listRef" class="chat-messages" @click="handleBubbleClick">
          <div
            v-for="(msg, i) in currentMessages"
            :key="`${activeProvider}-${i}`"
            class="chat-msg"
            :class="msg.role"
          >
            <!-- 助手头像 -->
            <div class="msg-avatar assistant-avatar" v-if="msg.role === 'assistant'">
              <span class="avatar-icon">{{ { claude: '🟣', codex: '🟢', glm: '🔵', grok: '🟠' }[activeProvider] }}</span>
            </div>
            
            <div class="msg-content-wrapper">
              <div class="msg-name" v-if="msg.role === 'assistant'">{{ { claude: 'Claude', codex: 'Codex', glm: 'GLM', grok: 'Grok' }[activeProvider] }}</div>
              <div class="msg-bubble">
                <span class="msg-text" v-html="renderMarkdown(msg.content)"></span>
                <span v-if="isLoading && i === currentMessages.length - 1 && msg.role === 'assistant'" class="msg-cursor">▊</span>
              </div>
            </div>

            <!-- 用户头像 -->
            <div class="msg-avatar user-avatar" v-if="msg.role === 'user'">
              <img v-if="authStore.user?.avatar" :src="authStore.user.avatar" class="avatar-img" />
              <span v-else class="avatar-icon">😎</span>
            </div>
          </div>
        </div>

        <!-- 输入区 -->
        <div class="chat-input-bar" v-if="providerStatus[activeProvider]?.available && !showConfig">
          <textarea
            v-model="inputText"
            class="chat-input"
            placeholder="输入消息…"
            rows="1"
            :disabled="isLoading"
            @keydown="handleKeydown"
          ></textarea>
          <button v-if="isLoading" class="chat-stop" @click="stopGeneration" title="停止生成">
            ⏹
          </button>
          <button v-else class="chat-send" :disabled="!inputText.trim()" @click="sendMessage">
            ➤
          </button>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script>
function renderMarkdown(text) {
  if (!text) return ''

  // 1. 代码块保护（先提取，防止内部被误处理）
  const codeBlocks = []
  text = text.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
    const escapedCode = code.replace(/</g, '&lt;').replace(/>/g, '&gt;')
    const safeCode = encodeURIComponent(code)
    const copySvg = `<svg class="copy-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8 5H6C4.89543 5 4 5.89543 4 7V19C4 20.1046 4.89543 21 6 21H16C17.1046 21 18 20.1046 18 19V17M8 5C8 6.10457 8.89543 7 10 7H12C13.1046 7 14 6.10457 14 5M8 5C8 3.89543 8.89543 3 10 3H12C13.1046 3 14 3.89543 14 5M14 5H16C17.1046 5 18 5.89543 18 7V10" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><rect x="14" y="14" width="6" height="6" rx="1" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`
    
    codeBlocks.push(`
      <div class="code-block-wrapper">
        <div class="code-block-header">
          <span class="code-lang">${lang || ''}</span>
          <button class="code-copy-btn" data-code="${safeCode}" title="复制代码">
            ${copySvg}
          </button>
        </div>
        <pre><code>${escapedCode}</code></pre>
      </div>
    `)
    return `%%CODE_BLOCK_${codeBlocks.length - 1}%%`
  })

  // 2. 行内代码
  text = text.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>')

  // 3. 按行处理
  const lines = text.split('\n')
  const result = []
  let inList = false
  let listType = ''

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i]

    // 代码块占位符直接输出
    if (line.match(/%%CODE_BLOCK_\d+%%/)) {
      if (inList) { result.push(listType === 'ul' ? '</ul>' : '</ol>'); inList = false }
      result.push(line)
      continue
    }

    // 分割线
    if (/^---+$/.test(line.trim())) {
      if (inList) { result.push(listType === 'ul' ? '</ul>' : '</ol>'); inList = false }
      result.push('<hr class="md-hr">')
      continue
    }

    // 独立图片行 ![alt](url)
    const imgLine = line.trim().match(/^!\[([^\]]*)\]\(([^)]+)\)$/)
    if (imgLine) {
      if (inList) { result.push(listType === 'ul' ? '</ul>' : '</ol>'); inList = false }
      result.push(`<div class="md-img-wrap"><img src="${imgLine[2]}" alt="${imgLine[1]}" class="md-img" loading="lazy" onerror="this.style.display='none';this.nextElementSibling.style.display='block'" /><span class="md-img-error" style="display:none">⚠️ 图片加载失败</span></div>`)
      continue
    }

    // 标题
    const h3 = line.match(/^### (.+)/)
    if (h3) { if (inList) { result.push(listType === 'ul' ? '</ul>' : '</ol>'); inList = false }; result.push(`<h4 class="md-h3">${applyInline(h3[1])}</h4>`); continue }
    const h2 = line.match(/^## (.+)/)
    if (h2) { if (inList) { result.push(listType === 'ul' ? '</ul>' : '</ol>'); inList = false }; result.push(`<h3 class="md-h2">${applyInline(h2[1])}</h3>`); continue }
    const h1 = line.match(/^# (.+)/)
    if (h1) { if (inList) { result.push(listType === 'ul' ? '</ul>' : '</ol>'); inList = false }; result.push(`<h2 class="md-h1">${applyInline(h1[1])}</h2>`); continue }

    // 无序列表
    const ul = line.match(/^[-*] (.+)/)
    if (ul) {
      if (!inList || listType !== 'ul') {
        if (inList) result.push(listType === 'ul' ? '</ul>' : '</ol>')
        result.push('<ul class="md-list">'); inList = true; listType = 'ul'
      }
      result.push(`<li>${applyInline(ul[1])}</li>`)
      continue
    }

    // 有序列表
    const ol = line.match(/^\d+\. (.+)/)
    if (ol) {
      if (!inList || listType !== 'ol') {
        if (inList) result.push(listType === 'ul' ? '</ul>' : '</ol>')
        result.push('<ol class="md-list">'); inList = true; listType = 'ol'
      }
      result.push(`<li>${applyInline(ol[1])}</li>`)
      continue
    }

    // 关闭列表
    if (inList && line.trim() === '') {
      result.push(listType === 'ul' ? '</ul>' : '</ol>'); inList = false
    }

    // 普通段落
    if (line.trim()) {
      result.push(`<p class="md-p">${applyInline(line)}</p>`)
    } else if (!inList) {
      result.push('')
    }
  }
  if (inList) result.push(listType === 'ul' ? '</ul>' : '</ol>')

  // 4. 还原代码块
  let html = result.join('\n')
  codeBlocks.forEach((block, i) => {
    html = html.replace(`%%CODE_BLOCK_${i}%%`, block)
  })
  return html
}

function applyInline(text) {
  return text
    .replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1" class="md-img-inline" loading="lazy" />')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
}
</script>

<style scoped>
/* ===== 悬浮气泡 ===== */
.ai-fab {
  position: fixed;
  right: 32px;
  bottom: 108px;
  z-index: 50;
  width: 56px;
  height: 56px;
  border-radius: 50%;
  border: none;
  background: linear-gradient(135deg, #667eea, #764ba2);
  color: #fff;
  font-size: 24px;
  cursor: pointer;
  box-shadow: 0 6px 24px rgba(102, 126, 234, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}
.ai-fab:hover { transform: translateY(-3px) scale(1.05); box-shadow: 0 10px 32px rgba(102, 126, 234, 0.6); }
.ai-fab.is-open { background: rgba(255,255,255,0.15); box-shadow: 0 4px 16px rgba(0,0,0,0.2); }
.ai-fab-icon { position: relative; z-index: 1; transition: transform 0.3s; }
.ai-fab.is-open .ai-fab-icon { transform: rotate(90deg); }
.ai-fab-pulse {
  position: absolute; inset: -4px; border-radius: 50%;
  border: 2px solid rgba(102, 126, 234, 0.4);
  animation: fab-pulse 2s ease-in-out infinite;
}
@keyframes fab-pulse {
  0%, 100% { opacity: 0.4; transform: scale(1); }
  50% { opacity: 0.8; transform: scale(1.15); }
}

/* ===== 聊天面板 ===== */
.ai-chat-panel {
  position: fixed; right: 24px; bottom: 176px; z-index: 49;
  width: 400px; height: 560px;
  display: flex; flex-direction: column;
  background: rgba(20, 20, 40, 0.92);
  backdrop-filter: blur(30px);
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 20px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
  overflow: hidden;
}

/* ===== 标题栏 ===== */
.chat-header {
  display: flex; align-items: center; gap: 6px;
  padding: 10px 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(255, 255, 255, 0.03);
  flex-shrink: 0;
}
.chat-header-icon { font-size: 20px; }

/* ===== 供应商切换器 ===== */
.provider-switcher {
  flex: 1;
  display: flex;
  background: rgba(255, 255, 255, 0.06);
  border-radius: 8px;
  padding: 2px;
  gap: 2px;
}
.provider-tab {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 5px;
  padding: 5px 8px;
  border: none;
  border-radius: 6px;
  background: transparent;
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}
.provider-tab.active {
  background: rgba(102, 126, 234, 0.25);
  color: #fff;
}
.provider-tab:hover:not(.active) { background: rgba(255,255,255,0.05); }
.provider-dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: rgba(255,255,255,0.2);
}
.provider-dot.online { background: #4ade80; }

.chat-header-btn, .chat-header-close {
  width: 28px; height: 28px; border-radius: 50%; border: none;
  background: rgba(255, 255, 255, 0.06);
  color: var(--text-secondary); font-size: 12px; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  transition: all 0.2s;
}
.chat-header-btn:hover { background: rgba(255, 200, 100, 0.15); }
.chat-header-close:hover { background: rgba(255, 80, 80, 0.2); color: #fff; }

/* ===== 配置面板 ===== */
.chat-config {
  flex: 1; overflow-y: auto; padding: 14px;
  display: flex; flex-direction: column; gap: 12px;
}
.config-title {
  display: flex; align-items: center; justify-content: space-between;
  font-size: 15px; font-weight: 700; color: var(--text-primary);
}
.config-back {
  background: none; border: none; color: var(--text-secondary);
  font-size: 13px; cursor: pointer; padding: 4px 8px; border-radius: 6px;
}
.config-back:hover { background: rgba(255,255,255,0.08); color: var(--text-primary); }
.config-section { display: flex; flex-direction: column; gap: 10px; }
.config-section-title {
  font-size: 13px; font-weight: 700; color: var(--text-primary);
}
.config-divider {
  height: 1px; background: rgba(255,255,255,0.08); margin: 4px 0;
}
.config-hint {
  padding: 8px 12px;
  background: rgba(102, 126, 234, 0.1);
  border: 1px solid rgba(102, 126, 234, 0.2);
  border-radius: 8px; font-size: 12px;
  color: var(--text-secondary); line-height: 1.4;
}
.config-field { display: flex; flex-direction: column; gap: 4px; }
.config-field label {
  font-size: 11px; color: var(--text-secondary);
  font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
}
.config-field input, .config-field select {
  background: rgba(255, 255, 255, 0.06);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 8px; padding: 8px 10px;
  color: var(--text-primary); font-size: 13px;
  outline: none; transition: border-color 0.2s;
}
.config-field input:focus { border-color: rgba(102, 126, 234, 0.5); }
.config-field input::placeholder { color: rgba(255,255,255,0.3); }
.config-save {
  padding: 10px; border: none; border-radius: 10px;
  background: linear-gradient(135deg, #667eea, #764ba2);
  color: #fff; font-size: 13px; font-weight: 600;
  cursor: pointer; transition: all 0.2s;
}
.config-save:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 16px rgba(102, 126, 234, 0.4);
}
.config-save:disabled { opacity: 0.4; cursor: not-allowed; }

/* ===== 技能选择器 ===== */
.skill-selector-bar {
  padding: 6px 14px; position: relative;
  border-bottom: 1px solid rgba(255,255,255,0.06);
}
.skill-select-btn {
  background: rgba(255,255,255,0.06); border: 1px dashed rgba(255,255,255,0.15);
  border-radius: 16px; padding: 4px 12px; color: var(--text-secondary);
  font-size: 12px; cursor: pointer; transition: all 0.2s;
}
.skill-select-btn:hover { background: rgba(255,255,255,0.1); color: var(--text-primary); }
.skill-active-tag {
  display: inline-flex; align-items: center; gap: 6px;
  background: rgba(102, 126, 234, 0.15); border: 1px solid rgba(102, 126, 234, 0.3);
  border-radius: 16px; padding: 4px 10px; font-size: 12px;
  color: #a5b4fc; cursor: pointer; transition: all 0.2s;
}
.skill-active-tag:hover { background: rgba(102, 126, 234, 0.25); }
.skill-clear-btn {
  background: none; border: none; color: rgba(255,255,255,0.4);
  font-size: 14px; cursor: pointer; line-height: 1; padding: 0 2px;
}
.skill-clear-btn:hover { color: #f87171; }
.skill-dropdown {
  position: absolute; top: 100%; left: 14px; right: 14px; z-index: 20;
  background: var(--card-bg); border: 1px solid rgba(255,255,255,0.1);
  border-radius: 10px; padding: 6px; margin-top: 4px;
  box-shadow: 0 8px 24px rgba(0,0,0,0.4); max-height: 200px; overflow-y: auto;
}
.skill-dropdown-empty {
  padding: 12px; text-align: center; font-size: 12px;
  color: var(--text-secondary);
}
.skill-dropdown-item {
  display: flex; align-items: center; gap: 8px; width: 100%;
  padding: 8px 10px; border: none; background: transparent;
  color: var(--text-primary); font-size: 13px; cursor: pointer;
  border-radius: 8px; transition: background 0.15s;
}
.skill-dropdown-item:hover { background: rgba(255,255,255,0.08); }
.skill-dropdown-item.active { background: rgba(102, 126, 234, 0.2); color: #a5b4fc; }
.skill-dropdown-icon { font-size: 16px; }

/* ===== 技能管理面板 ===== */
.skill-form { display: flex; flex-direction: column; gap: 10px; }
.skill-name-row { display: flex; gap: 8px; }
.skill-icon-input {
  width: 44px; text-align: center; font-size: 18px;
  background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1);
  border-radius: 8px; padding: 6px; color: var(--text-primary); outline: none;
}
.skill-name-input {
  flex: 1; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1);
  border-radius: 8px; padding: 8px 10px; color: var(--text-primary);
  font-size: 13px; outline: none;
}
.skill-name-input:focus, .skill-icon-input:focus { border-color: rgba(102, 126, 234, 0.5); }
.skill-prompt-input {
  width: 100%; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1);
  border-radius: 8px; padding: 8px 10px; color: var(--text-primary);
  font-size: 13px; outline: none; resize: vertical; min-height: 80px;
  font-family: inherit; line-height: 1.5;
}
.skill-prompt-input:focus { border-color: rgba(102, 126, 234, 0.5); }
.skill-prompt-input::placeholder { color: rgba(255,255,255,0.3); }
.skill-form-actions { display: flex; gap: 8px; }
.skill-cancel-btn {
  flex: 1; padding: 10px; border: 1px solid rgba(255,255,255,0.15); border-radius: 10px;
  background: transparent; color: var(--text-secondary); font-size: 13px; cursor: pointer;
}
.skill-cancel-btn:hover { background: rgba(255,255,255,0.06); }
.skill-empty {
  padding: 16px; text-align: center; font-size: 13px; color: var(--text-secondary);
}
.skill-card {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 12px; border-radius: 10px; background: rgba(255,255,255,0.04);
  border: 1px solid rgba(255,255,255,0.06); transition: background 0.15s;
}
.skill-card:hover { background: rgba(255,255,255,0.08); }
.skill-card + .skill-card { margin-top: 6px; }
.skill-card-info { display: flex; align-items: center; gap: 10px; min-width: 0; flex: 1; }
.skill-card-icon { font-size: 22px; flex-shrink: 0; }
.skill-card-name { font-size: 13px; font-weight: 600; color: var(--text-primary); }
.skill-card-preview {
  font-size: 11px; color: var(--text-secondary); margin-top: 2px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 200px;
}
.skill-card-actions { display: flex; gap: 4px; flex-shrink: 0; }
.skill-card-actions button {
  background: none; border: none; cursor: pointer; padding: 4px; font-size: 14px;
  opacity: 0.5; transition: opacity 0.15s;
}
.skill-card-actions button:hover { opacity: 1; }
.skill-add-btn {
  width: 100%; margin-top: 8px; padding: 10px; border: 1px dashed rgba(255,255,255,0.15);
  border-radius: 10px; background: transparent; color: var(--text-secondary);
  font-size: 13px; cursor: pointer; transition: all 0.2s;
}
.skill-add-btn:hover { background: rgba(102, 126, 234, 0.1); color: #a5b4fc; border-color: rgba(102, 126, 234, 0.3); }

/* ===== 消息列表 & 头像 ===== */
.chat-messages {
  flex: 1; overflow-y: auto; padding: 16px 20px;
  display: flex; flex-direction: column; gap: 20px;
}
.chat-messages::-webkit-scrollbar { width: 5px; }
.chat-messages::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 3px; }

.chat-msg {
  display: flex; width: 100%; gap: 12px;
  align-items: flex-start;
}
.chat-msg.user {
  flex-direction: row-reverse;
}
.msg-avatar {
  width: 36px; height: 36px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0; font-size: 18px;
}
.assistant-avatar {
  background: rgba(255, 255, 255, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.15);
  box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}
.user-avatar {
  background: linear-gradient(135deg, #667eea, #764ba2);
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
}
.avatar-img { width: 100%; height: 100%; border-radius: 50%; object-fit: cover; }

.msg-content-wrapper {
  display: flex; flex-direction: column; max-width: calc(100% - 48px);
}
.msg-name {
  font-size: 12px; color: rgba(255, 255, 255, 0.5);
  margin-bottom: 4px; padding-left: 4px;
}

.msg-bubble {
  padding: 12px 16px;
  font-size: 14px; line-height: 1.65; word-break: break-word;
  letter-spacing: 0.3px;
}
.chat-msg.user .msg-bubble {
  background: linear-gradient(135deg, #667eea, #764ba2);
  color: #fff;
  border-radius: 18px 4px 18px 18px;
  box-shadow: 0 6px 16px rgba(102, 126, 234, 0.25);
  max-width: calc(100% - 48px);
}
.chat-msg.assistant .msg-bubble {
  background: rgba(40, 40, 50, 0.6);
  color: rgba(255, 255, 255, 0.95);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 4px 18px 18px 18px;
  box-shadow: 0 6px 16px rgba(0, 0, 0, 0.15);
  backdrop-filter: blur(20px);
}
.msg-cursor {
  display: inline-block; animation: blink 0.8s step-end infinite;
  color: #a78bfa; margin-left: 4px; font-weight: bold;
}
@keyframes blink { 50% { opacity: 0; } }

/* markdown 元素复用之前你优化的那套 */
.msg-bubble :deep(.code-block-wrapper) {
  margin: 12px 0; border-radius: 8px; overflow: hidden;
  background: rgba(10, 10, 15, 0.9);
  border: 1px solid rgba(255, 255, 255, 0.08);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
}
.msg-bubble :deep(.code-block-header) {
  display: flex; justify-content: space-between; align-items: center;
  padding: 6px 12px; background: rgba(255, 255, 255, 0.05);
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
}
.msg-bubble :deep(.code-lang) {
  font-size: 12px; color: rgba(255, 255, 255, 0.5);
  font-family: 'Fira Code', 'Consolas', monospace;
  text-transform: lowercase;
}
.msg-bubble :deep(.code-copy-btn) {
  background: transparent; border: none; cursor: pointer;
  padding: 4px; border-radius: 4px; display: flex; align-items: center; justify-content: center;
  color: rgba(255, 255, 255, 0.5); transition: all 0.2s;
}
.msg-bubble :deep(.code-copy-btn:hover) {
  background: rgba(255, 255, 255, 0.1); color: #fff;
}
.msg-bubble :deep(.copy-icon) { width: 14px; height: 14px; }
.msg-bubble :deep(pre) {
  padding: 12px 14px; margin: 0; overflow-x: auto; font-size: 13px;
  background: transparent; border: none; border-radius: 0;
}
.msg-bubble :deep(code) { font-family: 'Fira Code', 'Consolas', monospace; }
.msg-bubble :deep(.inline-code) {
  background: rgba(255,255,255,0.12); padding: 2px 6px; border-radius: 6px; font-size: 13px;
  color: #e2e8f0; font-weight: 500;
}
.msg-bubble :deep(.md-h1) {
  font-size: 17px; font-weight: 800; margin: 16px 0 8px;
  padding-bottom: 6px; border-bottom: 1px solid rgba(255,255,255,0.15);
  background: linear-gradient(to right, #c4b5fd, #e9d5ff);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.msg-bubble :deep(.md-h2) {
  font-size: 15px; font-weight: 700; margin: 14px 0 6px;
  color: #ddd6fe;
}
.msg-bubble :deep(.md-h3) {
  font-size: 14px; font-weight: 700; margin: 10px 0 4px;
  color: #e9d5ff; opacity: 0.9;
}
.msg-bubble :deep(.md-list) {
  margin: 6px 0; padding-left: 20px; line-height: 1.7;
}
.msg-bubble :deep(.md-list li) {
  margin: 4px 0; padding-left: 2px;
}
.msg-bubble :deep(.md-hr) {
  border: none; border-top: 1px solid rgba(255,255,255,0.1);
  margin: 14px 0;
}
.msg-bubble :deep(.md-img-wrap) {
  margin: 10px 0; text-align: center;
}
.msg-bubble :deep(.md-img) {
  max-width: 100%; max-height: 360px; border-radius: 8px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
  cursor: pointer; transition: transform 0.2s;
}
.msg-bubble :deep(.md-img:hover) {
  transform: scale(1.02);
}
.msg-bubble :deep(.md-img-inline) {
  max-width: 100%; max-height: 200px; border-radius: 6px;
  vertical-align: middle; margin: 2px 4px;
}
.msg-bubble :deep(.md-img-error) {
  font-size: 12px; color: rgba(255, 255, 255, 0.4);
  padding: 8px;
}
.msg-bubble :deep(.md-p) {
  margin: 6px 0;
}

/* ===== 输入区 ===== */
.chat-input-bar {
  display: flex; align-items: flex-end; gap: 10px;
  padding: 12px 16px;
  background: rgba(25, 25, 30, 0.8);
  border-top: 1px solid rgba(255, 255, 255, 0.05);
  backdrop-filter: blur(20px);
  flex-shrink: 0;
}
.chat-input {
  flex: 1;
  background: rgba(255, 255, 255, 0.08);
  border: 1px solid rgba(255, 255, 255, 0.05);
  border-radius: 20px; padding: 12px 16px;
  color: rgba(255, 255, 255, 0.95); font-size: 14px;
  resize: none; outline: none; max-height: 100px;
  line-height: 1.5; transition: all 0.2s;
}
.chat-input::placeholder { color: rgba(255, 255, 255, 0.35); }
.chat-input:focus { 
  border-color: rgba(102, 126, 234, 0.6); 
  background: rgba(255, 255, 255, 0.1);
}
.chat-send {
  width: 44px; height: 44px; border-radius: 50%; border: none;
  background: linear-gradient(135deg, #667eea, #764ba2);
  color: #fff; font-size: 18px; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  transition: all 0.2s; flex-shrink: 0;
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
}
.chat-send:hover:not(:disabled) { 
  transform: scale(1.05) translateY(-2px); 
  box-shadow: 0 6px 16px rgba(102, 126, 234, 0.4); 
}
.chat-send:disabled { opacity: 0.4; cursor: not-allowed; box-shadow: none; }
.chat-stop {
  width: 44px; height: 44px; border-radius: 50%; border: none;
  background: linear-gradient(135deg, #ef4444, #dc2626);
  color: #fff; font-size: 16px; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0;
  box-shadow: 0 4px 12px rgba(239, 68, 68, 0.4);
  animation: stop-pulse 1.5s ease-in-out infinite;
  transition: all 0.2s;
}
.chat-stop:hover {
  transform: scale(1.08);
  box-shadow: 0 6px 20px rgba(239, 68, 68, 0.5);
}
@keyframes stop-pulse {
  0%, 100% { box-shadow: 0 4px 12px rgba(239, 68, 68, 0.4); }
  50% { box-shadow: 0 4px 20px rgba(239, 68, 68, 0.7); }
}

/* ===== 覆盖外层聊天面板背景 ===== */
.ai-chat-panel {
  background: rgba(30, 30, 35, 0.85) !important;
  backdrop-filter: blur(40px) saturate(150%) !important;
  border: 1px solid rgba(255, 255, 255, 0.08) !important;
  box-shadow: 0 24px 80px rgba(0, 0, 0, 0.6) !important;
}

/* ===== 不可用提示 ===== */
.chat-unavailable {
  flex: 1; display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  gap: 8px; color: rgba(255, 255, 255, 0.6); padding: 32px; text-align: center;
}
.chat-unavailable p:first-child { font-size: 18px; color: #a78bfa; }
.chat-unavailable-hint { font-size: 13px; opacity: 0.8; }

/* ===== 动画 ===== */
.chat-slide-enter-active { animation: chat-in 0.4s cubic-bezier(0.2, 0.8, 0.2, 1); }
.chat-slide-leave-active { animation: chat-in 0.3s cubic-bezier(0.8, 0.2, 1, 0.2) reverse; }
@keyframes chat-in {
  from { opacity: 0; transform: translateY(30px) scale(0.96); }
  to { opacity: 1; transform: translateY(0) scale(1); }
}

/* ===== 移动端 ===== */
@media (max-width: 720px) {
  .ai-fab { right: 16px; bottom: 80px; width: 48px; height: 48px; font-size: 20px; }
  .ai-chat-panel { right: 0; bottom: 0; width: 100vw; height: 100vh; border-radius: 0 !important; z-index: 200; }
}
</style>
