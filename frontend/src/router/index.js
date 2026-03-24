import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/LoginView.vue'),
    meta: { guest: true },
  },
  {
    path: '/register',
    name: 'Register',
    component: () => import('../views/RegisterView.vue'),
    meta: { guest: true },
  },
  {
    path: '/',
    name: 'Home',
    component: () => import('../views/HomeView.vue'),
  },
  {
    path: '/gallery',
    name: 'Gallery',
    component: () => import('../views/GalleryView.vue'),
  },
  {
    path: '/music',
    name: 'Music',
    component: () => import('../views/MusicView.vue'),
  },
  {
    path: '/timeline',
    name: 'Timeline',
    component: () => import('../views/TimelineView.vue'),
  },
  {
    path: '/letter',
    name: 'Letter',
    component: () => import('../views/LetterView.vue'),
  },
  {
    path: '/mood',
    name: 'Mood',
    component: () => import('../views/MoodView.vue'),
  },
  {
    path: '/wishes',
    name: 'Wishes',
    component: () => import('../views/WishesView.vue'),
  },
  {
    path: '/map',
    name: 'Map',
    component: () => import('../views/MapView.vue'),
  },
  {
    path: '/jukebox',
    name: 'Jukebox',
    component: () => import('../views/JukeboxView.vue'),
  },
  {
    path: '/express',
    name: 'Express',
    component: () => import('../views/ExpressView.vue'),
  },
  {
    path: '/users',
    name: 'Users',
    component: () => import('../views/UsersView.vue'),
    meta: { adminOnly: true },
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/',
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// 全局前置守卫：未认证跳转登录
router.beforeEach(async (to) => {
  const authStore = useAuthStore()

  // 首次加载检查认证状态
  if (authStore.checking) {
    await authStore.checkAuth()
  }

  if (to.meta.guest) {
    // guest 页面：已登录则跳转首页
    if (authStore.authenticated) return '/'
    return true
  }

  // 非 guest 页面：未登录跳转登录
  if (!authStore.authenticated) {
    return '/login'
  }

  // adminOnly 页面：非 admin 跳转首页
  if (to.meta.adminOnly && !authStore.isAdmin) {
    return '/'
  }

  return true
})

export default router
