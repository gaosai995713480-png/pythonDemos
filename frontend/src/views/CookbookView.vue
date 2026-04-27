<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { cookingApi, recipeApi } from '../api'

const router = useRouter()

const activeTab = ref('library')
const loading = ref(false)
const recipes = ref([])
const total = ref(0)
const categories = ref([])
const selectedRecipe = ref(null)
const menus = ref([])
const errorMessage = ref('')

const filters = ref({
  keyword: '',
  category: '',
  difficulty: '',
  only_favorite: false,
  only_want_to_cook: false,
  only_cooked: false,
  page: 1,
  page_size: 20,
})

const recordForm = ref({
  cooked_date: new Date().toISOString().slice(0, 10),
  rating: 5,
  mood: '',
  note: '',
  next_time_improvement: '',
})

const menuForm = ref({
  title: '',
  menu_date: '',
  description: '',
})

const difficultyMap = {
  easy: '简单',
  medium: '适中',
  hard: '困难',
  unknown: '未知',
}

const visibleRecipes = computed(() => recipes.value)

async function loadRecipes() {
  loading.value = true
  errorMessage.value = ''
  try {
    const data = await recipeApi.list({ ...filters.value })
    recipes.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    errorMessage.value = error.message || '加载菜谱失败'
  } finally {
    loading.value = false
  }
}

async function loadCategories() {
  const data = await recipeApi.categories()
  categories.value = data.items || []
}

async function openRecipe(recipe) {
  if (!recipe?.id) {
    errorMessage.value = '没有找到可打开的菜谱，请先导入 HowToCook 菜谱。'
    return
  }
  selectedRecipe.value = await recipeApi.detail(recipe.id)
  if (!menus.value.length) {
    await loadMenus()
  }
}

async function toggleFavorite(recipe) {
  await recipeApi.updateState(recipe.id, {
    is_favorite: !recipe.is_favorite,
    want_to_cook: recipe.want_to_cook,
    rating: recipe.rating,
    note: '',
  })
  await loadRecipes()
}

async function toggleWantToCook(recipe) {
  await recipeApi.updateState(recipe.id, {
    is_favorite: recipe.is_favorite,
    want_to_cook: !recipe.want_to_cook,
    rating: recipe.rating,
    note: '',
  })
  await loadRecipes()
}

async function addRecord() {
  if (!selectedRecipe.value) return
  await recipeApi.addRecord(selectedRecipe.value.id, { ...recordForm.value })
  recordForm.value.note = ''
  recordForm.value.next_time_improvement = ''
  await loadRecipes()
  selectedRecipe.value = await recipeApi.detail(selectedRecipe.value.id)
}

async function randomPick() {
  errorMessage.value = ''
  try {
    const recipe = await recipeApi.random({
      category: filters.value.category,
      difficulty: filters.value.difficulty,
    })
    if (!recipe?.id) {
      errorMessage.value = recipe?.detail || recipe?.error || '没有可推荐的菜谱，请先导入 HowToCook 菜谱。'
      return
    }
    await openRecipe(recipe)
  } catch (error) {
    errorMessage.value = error.message || '随机推荐失败，请稍后重试。'
  }
}

async function switchTab(tab) {
  activeTab.value = tab
  if (tab === 'favorites') {
    filters.value.only_favorite = true
    filters.value.only_want_to_cook = false
    filters.value.only_cooked = false
    await loadRecipes()
  } else if (tab === 'want') {
    filters.value.only_favorite = false
    filters.value.only_want_to_cook = true
    filters.value.only_cooked = false
    await loadRecipes()
  } else if (tab === 'cooked') {
    filters.value.only_favorite = false
    filters.value.only_want_to_cook = false
    filters.value.only_cooked = true
    await loadRecipes()
  } else if (tab === 'menus') {
    await loadMenus()
  } else {
    filters.value.only_favorite = false
    filters.value.only_want_to_cook = false
    filters.value.only_cooked = false
    await loadRecipes()
  }
}

async function loadMenus() {
  const data = await cookingApi.menus()
  menus.value = data.items || []
}

async function createMenu() {
  if (!menuForm.value.title.trim()) return
  await cookingApi.createMenu({ ...menuForm.value })
  menuForm.value = { title: '', menu_date: '', description: '' }
  await loadMenus()
}

async function addSelectedToMenu(menu) {
  if (!selectedRecipe.value) return
  await cookingApi.addMenuItem(menu.id, {
    recipe_id: selectedRecipe.value.id,
    note: selectedRecipe.value.title,
  })
  await loadMenus()
}

async function completeMenu(menu) {
  await cookingApi.completeMenu(menu.id)
  await loadMenus()
}

async function removeMenuItem(menu, item) {
  await cookingApi.removeMenuItem(menu.id, item.id)
  await loadMenus()
}

onMounted(async () => {
  await Promise.all([loadCategories(), loadRecipes(), loadMenus()])
})
</script>

<template>
  <main class="cookbook-page">
    <header class="hero">
      <button class="back-btn" @click="router.push('/')">← 回到首页</button>
      <p class="eyebrow">HowToCook 上游快照已入库，本页运行时只访问本项目 API</p>
      <h1>我们的小厨房</h1>
      <p class="subtitle">一起决定今天吃什么，记录每一次把日子做成热饭的瞬间。</p>
      <div class="hero-actions">
        <button class="primary-btn" @click="randomPick">🎲 随机一道菜</button>
        <button class="ghost-btn" @click="switchTab('want')">📝 想做清单</button>
        <button class="ghost-btn" @click="switchTab('menus')">📅 纪念日菜单</button>
      </div>
    </header>

    <section class="tabs">
      <button :class="{ active: activeTab === 'library' }" @click="switchTab('library')">菜谱库</button>
      <button data-test="tab-favorites" :class="{ active: activeTab === 'favorites' }" @click="switchTab('favorites')">我的收藏</button>
      <button :class="{ active: activeTab === 'want' }" @click="switchTab('want')">想做</button>
      <button :class="{ active: activeTab === 'cooked' }" @click="switchTab('cooked')">已做</button>
      <button data-test="tab-menus" :class="{ active: activeTab === 'menus' }" @click="switchTab('menus')">纪念日菜单</button>
    </section>

    <section v-if="activeTab !== 'menus'" class="content-grid">
      <aside class="filters-card">
        <label>
          搜索菜名
          <input v-model="filters.keyword" placeholder="番茄炒蛋、红烧肉..." @keyup.enter="loadRecipes" />
        </label>
        <label>
          分类
          <select v-model="filters.category" @change="loadRecipes">
            <option value="">全部分类</option>
            <option v-for="item in categories" :key="item.category" :value="item.category">
              {{ item.category }}（{{ item.count }}）
            </option>
          </select>
        </label>
        <label>
          难度
          <select v-model="filters.difficulty" @change="loadRecipes">
            <option value="">全部难度</option>
            <option value="easy">简单</option>
            <option value="medium">适中</option>
            <option value="hard">困难</option>
            <option value="unknown">未知</option>
          </select>
        </label>
        <button class="primary-btn full" @click="loadRecipes">搜索菜谱</button>
        <p class="source-note">部分基础菜谱来源于 HowToCook，上游内容已同步入库，不在页面运行时读取 GitHub。</p>
      </aside>

      <section class="recipe-list">
        <div class="list-header">
          <h2>{{ activeTab === 'library' ? '菜谱库' : '清单结果' }}</h2>
          <span>{{ loading ? '加载中...' : `共 ${total} 道菜` }}</span>
        </div>
        <p v-if="errorMessage" class="error">{{ errorMessage }}</p>
        <article v-for="recipe in visibleRecipes" :key="recipe.id" class="recipe-card" @click="openRecipe(recipe)">
          <div>
            <h3>{{ recipe.title }}</h3>
            <p>{{ recipe.description || '来自 HowToCook 的结构化菜谱' }}</p>
            <div class="badges">
              <span>{{ recipe.category || '未分类' }}</span>
              <span>{{ difficultyMap[recipe.difficulty] || recipe.difficulty }}</span>
              <span v-if="recipe.cook_time_minutes">{{ recipe.cook_time_minutes }} 分钟</span>
              <span v-if="recipe.cooked_count">做过 {{ recipe.cooked_count }} 次</span>
            </div>
          </div>
          <div class="card-actions" @click.stop>
            <button :data-test="`favorite-${recipe.id}`" @click="toggleFavorite(recipe)">
              {{ recipe.is_favorite ? '❤️ 已收藏' : '🤍 收藏' }}
            </button>
            <button @click="toggleWantToCook(recipe)">
              {{ recipe.want_to_cook ? '✅ 想做中' : '📝 想做' }}
            </button>
          </div>
        </article>
      </section>

      <aside class="detail-card">
        <template v-if="selectedRecipe">
          <h2>{{ selectedRecipe.title }}</h2>
          <p class="meta">{{ selectedRecipe.category }} · {{ difficultyMap[selectedRecipe.difficulty] || '未知难度' }}</p>
          <section>
            <h3>必备原料</h3>
            <ul>
              <li v-for="item in selectedRecipe.ingredients" :key="item">{{ item }}</li>
            </ul>
          </section>
          <section>
            <h3>操作步骤</h3>
            <ol>
              <li v-for="step in selectedRecipe.steps" :key="step">{{ step }}</li>
            </ol>
          </section>
          <section v-if="selectedRecipe.tips">
            <h3>小贴士</h3>
            <p>{{ selectedRecipe.tips }}</p>
          </section>
          <form class="record-form" @submit.prevent="addRecord">
            <h3>记录这次一起做饭</h3>
            <input v-model="recordForm.cooked_date" type="date" />
            <select v-model="recordForm.rating">
              <option :value="5">5 分</option>
              <option :value="4">4 分</option>
              <option :value="3">3 分</option>
              <option :value="2">2 分</option>
              <option :value="1">1 分</option>
            </select>
            <input v-model="recordForm.mood" placeholder="今天的心情" />
            <textarea v-model="recordForm.note" placeholder="这次做饭有什么故事？"></textarea>
            <textarea v-model="recordForm.next_time_improvement" placeholder="下次想怎么改进？"></textarea>
            <button class="primary-btn">🍽 标记已做</button>
          </form>
          <section v-if="menus.length">
            <h3>加入菜单</h3>
            <button v-for="menu in menus" :key="menu.id" class="menu-chip" @click="addSelectedToMenu(menu)">
              加入 {{ menu.title }}
            </button>
          </section>
          <p class="source-note">来源：{{ selectedRecipe.source_repo || 'HowToCook' }} · {{ selectedRecipe.source_path }}</p>
        </template>
        <p v-else class="empty-detail">点一道菜，看看材料和做法。</p>
      </aside>
    </section>

    <section v-else class="menus-panel">
      <form data-test="create-menu" class="menu-form" @submit.prevent="createMenu">
        <h2>创建纪念日菜单</h2>
        <input data-test="menu-title" v-model="menuForm.title" placeholder="例如：纪念日晚餐" />
        <input v-model="menuForm.menu_date" type="date" />
        <textarea v-model="menuForm.description" placeholder="写下这顿饭的计划"></textarea>
        <button class="primary-btn">创建菜单</button>
      </form>

      <div class="menu-list">
        <article v-for="menu in menus" :key="menu.id" class="menu-card">
          <div class="menu-card-header">
            <div>
              <h3>{{ menu.title }}</h3>
              <p>{{ menu.menu_date || '还没定日期' }} · {{ menu.status }}</p>
            </div>
            <button
              v-if="menu.status !== 'done'"
              :data-test="`complete-menu-${menu.id}`"
              class="menu-chip"
              @click="completeMenu(menu)"
            >
              标记完成
            </button>
          </div>
          <p>{{ menu.description }}</p>
          <ul v-if="menu.items?.length" class="menu-items">
            <li v-for="item in menu.items" :key="item.id">
              <span>{{ item.title }}</span>
              <small v-if="item.note">{{ item.note }}</small>
              <button
                :data-test="`remove-menu-item-${menu.id}-${item.id}`"
                @click="removeMenuItem(menu, item)"
              >
                移除
              </button>
            </li>
          </ul>
          <p v-else class="empty-detail">这个菜单还没有菜，先从菜谱详情里加入一道吧。</p>
        </article>
        <p v-if="!menus.length" class="empty-detail">还没有菜单，先为某个周末或纪念日安排一桌菜吧。</p>
      </div>
    </section>
  </main>
</template>

<style scoped>
.cookbook-page {
  min-height: 100vh;
  padding: 28px;
  color: var(--text-primary);
}

.hero,
.filters-card,
.recipe-card,
.detail-card,
.menus-panel,
.menu-form,
.menu-card {
  background: var(--glass-bg);
  border: 1px solid var(--glass-border);
  border-radius: 24px;
  backdrop-filter: blur(24px);
  box-shadow: 0 18px 50px rgba(0, 0, 0, 0.18);
}

.hero {
  position: relative;
  max-width: 1180px;
  margin: 0 auto 18px;
  padding: 30px;
}

.back-btn {
  border: none;
  color: var(--text-primary);
  background: rgba(255, 255, 255, 0.08);
  border-radius: 999px;
  padding: 8px 14px;
  cursor: pointer;
}

.eyebrow,
.source-note,
.meta {
  color: var(--text-secondary);
  font-size: 13px;
}

.hero h1 {
  margin: 14px 0 8px;
  font-size: clamp(36px, 6vw, 64px);
}

.subtitle {
  max-width: 720px;
  color: var(--text-secondary);
  font-size: 18px;
}

.hero-actions,
.tabs,
.card-actions,
.badges {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

button {
  cursor: pointer;
}

.primary-btn,
.ghost-btn,
.tabs button,
.recipe-card button,
.menu-chip {
  border: 1px solid rgba(255, 255, 255, 0.16);
  border-radius: 999px;
  padding: 10px 16px;
  color: var(--text-primary);
  background: rgba(255, 255, 255, 0.08);
}

.primary-btn {
  border: none;
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  color: #fff;
}

.full {
  width: 100%;
}

.tabs {
  max-width: 1180px;
  margin: 0 auto 18px;
}

.tabs button.active {
  background: rgba(255, 107, 157, 0.28);
  color: #fff;
}

.content-grid {
  max-width: 1180px;
  margin: 0 auto;
  display: grid;
  grid-template-columns: 260px minmax(0, 1fr) 360px;
  gap: 18px;
  align-items: start;
}

.filters-card,
.detail-card {
  padding: 18px;
}

label,
.record-form {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

label {
  margin-bottom: 14px;
}

input,
select,
textarea {
  border: 1px solid rgba(255, 255, 255, 0.14);
  border-radius: 14px;
  padding: 11px 12px;
  color: var(--text-primary);
  background: rgba(255, 255, 255, 0.08);
}

textarea {
  min-height: 70px;
  resize: vertical;
}

.list-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.recipe-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.recipe-card {
  padding: 18px;
  display: flex;
  justify-content: space-between;
  gap: 18px;
}

.recipe-card h3,
.detail-card h2,
.menu-card h3 {
  margin: 0 0 8px;
}

.recipe-card p {
  margin: 0 0 10px;
  color: var(--text-secondary);
}

.badges span {
  padding: 4px 9px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.08);
  font-size: 12px;
}

.card-actions {
  flex-direction: column;
  min-width: 110px;
}

.detail-card {
  position: sticky;
  top: 20px;
}

.empty-detail,
.error {
  color: var(--text-secondary);
}

.error {
  color: #ffb3b3;
}

.menus-panel {
  max-width: 900px;
  margin: 0 auto;
  padding: 22px;
  display: grid;
  grid-template-columns: 320px 1fr;
  gap: 18px;
}

.menu-form,
.menu-card {
  padding: 18px;
}

.menu-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.menu-card-header {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  align-items: flex-start;
}

.menu-items {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding-left: 0;
  list-style: none;
}

.menu-items li {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 8px 10px;
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.06);
}

.menu-items small {
  color: var(--text-secondary);
}

@media (max-width: 980px) {
  .content-grid,
  .menus-panel {
    grid-template-columns: 1fr;
  }

  .detail-card {
    position: static;
  }
}
</style>
