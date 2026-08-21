import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router'
import { useThemeStore } from './stores/theme'
import { useLyricFxStore } from './stores/lyricFx'
import { clickOutside } from './directives/clickOutside'
import App from './App.vue'
import './styles/base.css'

const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
app.use(router)
app.directive('click-outside', clickOutside)

// 初始化主题
const themeStore = useThemeStore()
themeStore.init()

// 初始化歌词漂浮效果偏好
const lyricFxStore = useLyricFxStore()
lyricFxStore.init()

app.mount('#app')
