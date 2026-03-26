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
})

// 各供应商独立对话历史
const claudeMessages = ref([])
const codexMessages = ref([])

const currentMessages = computed(() =>
  activeProvider.value === 'claude' ? claudeMessages.value : codexMessages.value
)

// 配置面板
const showConfig = ref(false)
const configSaving = ref(false)
const claudeConfig = ref({ model: 'claude-sonnet-4-20250514' })
const codexConfig = ref({ base_url: '', api_key: '', model: 'gpt-5.4-codex' })

// 检查供应商状态
async function checkStatus() {
  try {
    const res = await fetch('/api/ai/status')
    if (res.ok) {
      const data = await res.json()
      Object.assign(providerStatus.claude, data.claude)
      Object.assign(providerStatus.codex, data.codex)
    }
  } catch { /* ignore */ }
}

// 加载配置
async function loadConfig() {
  try {
    const [cRes, xRes] = await Promise.all([
      fetch('/api/ai/config/claude'),
      fetch('/api/ai/config/codex'),
    ])
    if (cRes.ok) {
      const d = await cRes.json()
      claudeConfig.value.model = d.model || ''
    }
    if (xRes.ok) {
      const d = await xRes.json()
      codexConfig.value.base_url = d.base_url || ''
      codexConfig.value.model = d.model || ''
      // api_key 不回填
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

function openConfig() {
  loadConfig()
  showConfig.value = true
}

onMounted(checkStatus)

function toggleChat() {
  isOpen.value = !isOpen.value
  if (isOpen.value) {
    initMessages('claude')
    initMessages('codex')
  }
}

function initMessages(provider) {
  const msgs = provider === 'claude' ? claudeMessages : codexMessages
  if (msgs.value.length === 0) {
    const label = provider === 'claude' ? 'Claude' : 'Codex'
    msgs.value.push({
      role: 'assistant',
      content: `你好！我是 ${label}，有什么可以帮你的吗？ 😊`,
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

  const msgs = activeProvider.value === 'claude' ? claudeMessages : codexMessages

  msgs.value.push({ role: 'user', content: text })
  inputText.value = ''
  scrollToBottom()

  const history = msgs.value
    .filter((m, i) => !(i === 0 && m.role === 'assistant'))
    .slice(0, -1)
    .map(m => ({ role: m.role, content: m.content }))

  const aiMsg = { role: 'assistant', content: '' }
  msgs.value.push(aiMsg)
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
    let buffer = ''

    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })

      const lines = buffer.split('\n')
      buffer = lines.pop()

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue
        const data = line.slice(6)
        if (data === '[DONE]') break
        
        try {
          // 后端现在对内容做了 JSON 编码，可以直接解析保留换行符
          aiMsg.content += JSON.parse(data)
        } catch {
          // 容错：如果不是合法 JSON，直接追加
          aiMsg.content += data
        }
        scrollToBottom()
      }
    }

    if (!aiMsg.content) aiMsg.content = '抱歉，没有收到回复。'
  } catch (e) {
    if (e.name === 'AbortError') {
      if (!aiMsg.content) aiMsg.content = '（已停止生成）'
    } else {
      aiMsg.content += `\n\n连接失败: ${e.message}`
    }
  } finally {
    isLoading.value = false
    abortController = null
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
  const msgs = activeProvider.value === 'claude' ? claudeMessages : codexMessages
  const label = activeProvider.value === 'claude' ? 'Claude' : 'Codex'
  msgs.value = [{
    role: 'assistant',
    content: `你好！我是 ${label}，有什么可以帮你的吗？ 😊`,
  }]
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
              :class="{ active: activeProvider === 'claude' }"
              @click="switchProvider('claude')"
            >
              <span class="provider-dot" :class="{ online: providerStatus.claude.available }"></span>
              Claude
            </button>
          </div>

          <button v-if="authStore.isAdmin" class="chat-header-btn" title="配置" @click="openConfig">⚙️</button>
          <button class="chat-header-btn" title="清空对话" @click="clearChat">🗑️</button>
          <button class="chat-header-close" @click="isOpen = false">✕</button>
        </div>

        <!-- 配置面板 -->
        <div v-if="showConfig && authStore.isAdmin" class="chat-config">
          <div class="config-title">
            <span>AI 服务配置</span>
            <button class="config-back" @click="showConfig = false">← 返回</button>
          </div>

          <!-- Codex 配置 -->
          <div class="config-section">
            <div class="config-section-title">🟢 Codex (API 直连)</div>
            <div class="config-field">
              <label>API 地址</label>
              <input v-model="codexConfig.base_url" type="text" placeholder="https://ai.qaq.al" />
            </div>
            <div class="config-field">
              <label>API Key</label>
              <input v-model="codexConfig.api_key" type="password" placeholder="sk-..." />
            </div>
            <div class="config-field">
              <label>模型</label>
              <input v-model="codexConfig.model" type="text" placeholder="gpt-5.4-codex" />
            </div>
            <button
              class="config-save"
              :disabled="!codexConfig.base_url || !codexConfig.api_key || configSaving"
              @click="saveCodexConfig"
            >
              {{ configSaving ? '保存中...' : '💾 保存 Codex' }}
            </button>
          </div>

          <div class="config-divider"></div>

          <!-- Claude 配置 -->
          <div class="config-section">
            <div class="config-section-title">🟣 Claude (CLI 本地)</div>
            <div class="config-hint">💡 使用本地 Claude CLI，无需 API 地址和密钥</div>
            <div class="config-field">
              <label>模型</label>
              <input v-model="claudeConfig.model" type="text" placeholder="claude-sonnet-4-20250514" />
            </div>
            <button class="config-save" :disabled="configSaving" @click="saveClaudeConfig">
              {{ configSaving ? '保存中...' : '💾 保存 Claude' }}
            </button>
          </div>
        </div>

        <!-- 不可用提示 -->
        <div v-else-if="!providerStatus[activeProvider]?.available" class="chat-unavailable">
          <p>⚠️ {{ activeProvider === 'claude' ? 'Claude CLI' : 'Codex API' }} 未配置</p>
          <p v-if="authStore.isAdmin" class="chat-unavailable-hint">点击 ⚙️ 进行配置</p>
          <p v-else class="chat-unavailable-hint">请联系管理员配置</p>
        </div>

        <!-- 消息列表 -->
        <div v-else ref="listRef" class="chat-messages">
          <div
            v-for="(msg, i) in currentMessages"
            :key="`${activeProvider}-${i}`"
            class="chat-msg"
            :class="msg.role"
          >
            <!-- 助手头像 -->
            <div class="msg-avatar assistant-avatar" v-if="msg.role === 'assistant'">
              <span class="avatar-icon">{{ activeProvider === 'claude' ? '🟣' : '🟢' }}</span>
            </div>
            
            <div class="msg-content-wrapper">
              <div class="msg-name" v-if="msg.role === 'assistant'">{{ activeProvider === 'claude' ? 'Claude' : 'Codex' }}</div>
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
    codeBlocks.push(`<pre><code>${code.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code></pre>`)
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
.msg-bubble :deep(pre) {
  background: rgba(10, 10, 15, 0.8); border-radius: 10px;
  padding: 12px 14px; margin: 10px 0; overflow-x: auto; font-size: 13px;
  border: 1px solid rgba(255, 255, 255, 0.08);
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
