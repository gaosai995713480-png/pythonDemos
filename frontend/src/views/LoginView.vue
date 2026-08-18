<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
const router = useRouter()
const authStore = useAuthStore()
const username = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

async function handleLogin() {
  error.value = ''
  if (!username.value || !password.value) {
    error.value = '请输入用户名和密码'
    return
  }
  loading.value = true
  try {
    const data = await authStore.login(username.value, password.value)
    if (data.ok) {
      router.replace('/')
    } else {
      error.value = data.error || '登录失败'
    }
  } catch {
    error.value = '登录失败，请稍后重试'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <main class="login-shell">
    <section class="hero">
      <h1>只道当时是寻常</h1>
      <div class="hero-note">系统已开启访问控制，仅允许授权用户进入。</div>
    </section>
    <section class="panel">
      <h2>欢迎回来</h2>
      <p class="subtitle">请输入账号密码继续访问</p>
      <form @submit.prevent="handleLogin" novalidate>
        <div class="form-row">
          <label for="username">用户名</label>
          <input
            id="username"
            v-model="username"
            type="text"
            autocomplete="username"
            placeholder="请输入用户名"
            @input="error = ''"
          />
        </div>
        <div class="form-row">
          <label for="password">密码</label>
          <input
            id="password"
            v-model="password"
            type="password"
            autocomplete="current-password"
            placeholder="请输入密码"
            @input="error = ''"
          />
        </div>
        <button class="submit-btn" type="submit" :disabled="loading">
          {{ loading ? '登录中...' : '进入页面' }}
        </button>
        <p class="error-text" role="status" aria-live="polite">{{ error }}</p>
        <p class="register-link">还没有账号？<router-link to="/register">立即注册</router-link></p>
      </form>
    </section>
  </main>
</template>

<style scoped>
.login-shell {
  position: relative;
  width: min(940px, 92vw);
  display: grid;
  grid-template-columns: 1.1fr 0.9fr;
  gap: 24px;
  z-index: 1;
  margin: auto;
  min-height: 100vh;
  align-content: center;
}

.hero, .panel {
  backdrop-filter: blur(26px);
  background: var(--glass-bg);
  border: 1px solid var(--glass-border);
  border-radius: 24px;
  box-shadow: 0 18px 45px rgba(0, 0, 0, 0.26);
  animation: card-enter 0.45s ease both;
}

.hero {
  padding: clamp(28px, 3.2vw, 42px);
}

.hero h1 {
  margin: 0 0 14px;
  font-size: clamp(32px, 4.6vw, 54px);
  letter-spacing: -0.03em;
  text-shadow: 0 8px 28px rgba(255, 107, 157, 0.38);
}

.hero p {
  margin: 0;
  font-size: clamp(16px, 2vw, 22px);
  line-height: 1.7;
  color: var(--text-secondary);
}

.hero-note {
  margin-top: 24px;
  padding: 14px 16px;
  border-radius: 14px;
  background: rgba(255, 255, 255, 0.08);
  border: 1px solid rgba(255, 255, 255, 0.16);
  font-size: 14px;
  line-height: 1.6;
  color: rgba(255, 255, 255, 0.84);
}

.panel {
  padding: clamp(22px, 2.8vw, 34px);
}

.panel h2 {
  margin: 0 0 6px;
  font-size: 28px;
  font-weight: 700;
}

.subtitle {
  margin: 0 0 22px;
  color: var(--text-secondary);
  font-size: 14px;
}

.form-row {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-bottom: 16px;
}

.form-row label {
  font-size: 13px;
  color: rgba(255, 255, 255, 0.8);
}

.form-row input {
  height: 44px;
  border: 1px solid rgba(255, 255, 255, 0.22);
  border-radius: 12px;
  padding: 0 14px;
  font-size: 15px;
  color: var(--text-primary);
  background: rgba(255, 255, 255, 0.1);
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
}

.form-row input::placeholder {
  color: rgba(255, 255, 255, 0.5);
}

.form-row input:focus {
  border-color: rgba(255, 255, 255, 0.7);
  box-shadow: 0 0 0 3px rgba(255, 255, 255, 0.16);
}

.submit-btn {
  width: 100%;
  height: 46px;
  border: none;
  border-radius: 13px;
  color: #fff;
  font-size: 15px;
  font-weight: 700;
  cursor: pointer;
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  box-shadow: 0 10px 24px rgba(255, 107, 157, 0.34);
  transition: transform 0.2s, filter 0.2s;
}

.submit-btn:hover {
  transform: translateY(-1px);
  filter: brightness(1.03);
}

.submit-btn:disabled {
  cursor: not-allowed;
  opacity: 0.75;
}

.error-text {
  min-height: 20px;
  margin: 10px 0 0;
  font-size: 13px;
  color: var(--error);
}

.register-link {
  margin-top: 14px;
  font-size: 13px;
  color: rgba(255, 255, 255, 0.64);
  text-align: center;
}

.register-link a {
  color: var(--primary);
  text-decoration: none;
  font-weight: 600;
}

.register-link a:hover {
  text-decoration: underline;
}

@media (max-width: 860px) {
  .login-shell {
    grid-template-columns: 1fr;
    width: min(560px, 92vw);
    gap: 16px;
  }

  .hero { padding-bottom: 22px; }
  .hero p { font-size: 15px; }
}
</style>
