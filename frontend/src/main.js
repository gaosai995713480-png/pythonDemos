import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router'
import { useThemeStore } from './stores/theme'
import App from './App.vue'
import './styles/base.css'

const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
app.use(router)

// 初始化主题
const themeStore = useThemeStore()
themeStore.init()

app.mount('#app')
