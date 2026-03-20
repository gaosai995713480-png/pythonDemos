# Bug Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the 5 core frontend bugs (Danmu interval cleared, Memory leak in Wishes, Auto-play audio blocked in Letter, Promise.all missing catch in Weather, unhandled music promise)

**Architecture:** We are directly patching existing Vue 3 components and Pinia store logic on the frontend to be memory safe and edge-case resilient according to the specification.

**Tech Stack:** Vue 3, Pinia, Vanilla JS.

---

### Task 1: Fix Danmu timer logic (HomeView.vue)

**Files:**
- Modify: `d:\pythonDemo\pythonDemo\frontend\src\views\HomeView.vue:64-70`

- [ ] **Step 1: Write minimal implementation**
Modify `clearDanmuTimers()` to only clear `danmuTimers` array that contains the main `setInterval`. We need a separate way to clear the individual `spawnDanmu` timeouts or just let them run out. Alternatively, keep the `setInterval` ID out of `danmuTimers`.

```javascript
// Remove the main interval from danmuTimers
let danmuMainTimer = null

function clearDanmuTimers() {
  danmuTimers.forEach(t => clearTimeout(t))
  danmuTimers = []
  const layer = document.getElementById('danmu-layer')
  if (layer) layer.innerHTML = ''
}

// In onMounted:
danmuMainTimer = setInterval(launchAllDanmu, danmuSpeed.value * 1000 + 2000)

// In onUnmounted:
if (danmuMainTimer) clearInterval(danmuMainTimer)
```

- [ ] **Step 2: Compile & Verify**
Run: `npm run build` or load in browser to verify vue compiles.
Expected: PASS

- [ ] **Step 3: Commit**
```bash
git add frontend/src/views/HomeView.vue
git commit -m "fix(home): separate main danmu interval from timeout array to prevent premature clearing"
```


### Task 2: Fix Memory Leaks (WishesView.vue, HomeView.vue)

**Files:**
- Modify: `d:\pythonDemo\pythonDemo\frontend\src\views\WishesView.vue:81-83`
- Modify: `d:\pythonDemo\pythonDemo\frontend\src\views\HomeView.vue:243-247`

- [ ] **Step 1: Write implementation for WishesView.vue**
```javascript
let shootingStarTimer = null
onMounted(() => {
  loadWishes()
  createBackgroundStars()
  spawnShootingStar()
  shootingStarTimer = setInterval(spawnShootingStar, 5000 + Math.random() * 8000)
})
import { onUnmounted } from 'vue'
onUnmounted(() => {
  if (shootingStarTimer) clearInterval(shootingStarTimer)
})
```

- [ ] **Step 2: Write implementation for HomeView.vue weather timer**
```javascript
onUnmounted(() => {
  document.removeEventListener('click', closeCitySearch)
  if (weatherRefreshTimer) clearInterval(weatherRefreshTimer)
  if (searchTimer) clearTimeout(searchTimer)
})
```

- [ ] **Step 3: Commit**
```bash
git add frontend/src/views/WishesView.vue frontend/src/views/HomeView.vue
git commit -m "fix(views): clear intervals and timeouts in onUnmounted to prevent memory leak"
```


### Task 3: Fix LetterView Autoplay Error

**Files:**
- Modify: `d:\pythonDemo\pythonDemo\frontend\src\views\LetterView.vue:34-40`

- [ ] **Step 1: Implement fallback/resume for AudioContext**
```javascript
function typeSound() {
  if (!audioCtx) {
    try { audioCtx = new (window.AudioContext || window.webkitAudioContext)() }
    catch { return }
  }
  // 如果处于 suspended 状态，说明被浏览器拦截了，我们静默忽略，不调用 start()
  if (audioCtx.state === 'suspended') {
    audioCtx.resume().catch(() => {})
  }
  if (audioCtx.state === 'suspended') return;
  
  const osc = audioCtx.createOscillator()
...
```

- [ ] **Step 2: Commit**
```bash
git add frontend/src/views/LetterView.vue
git commit -m "fix(letter): catch audio context suspension to avoid unhandled browser autoplay error"
```


### Task 4: Fix weather Promise.all fetching

**Files:**
- Modify: `d:\pythonDemo\pythonDemo\frontend\src\views\HomeView.vue:143-160`

- [ ] **Step 1: Rewrite Promise.all to Promise.allSettled**
```javascript
    // 并行请求：base 获取实时天气，all 获取预报
    const results = await Promise.allSettled([
      weatherApi.weather(code, 'base'),
      weatherApi.weather(code, 'all'),
    ])
    const baseData = results[0].status === 'fulfilled' ? results[0].value : {}
    const allData = results[1].status === 'fulfilled' ? results[1].value : {}
```

- [ ] **Step 2: Commit**
```bash
git add frontend/src/views/HomeView.vue
git commit -m "fix(home): catch individual weather API failures via Promise.allSettled"
```


### Task 5: Handle music togglePlay Promise Rejection

**Files:**
- Modify: `d:\pythonDemo\pythonDemo\frontend\src\stores\music.js:134-140`

- [ ] **Step 1: Add await / catch to `play(0)`**
```javascript
      if (currentIndex.value < 0) {
        play(0).catch(() => {
           isPlaying.value = false
           playError.value = '播放请求失败'
        })
      } else {
```
Also in `play` function, make sure it returns a Promise by returning the await chain.

- [ ] **Step 2: Commit**
```bash
git add frontend/src/stores/music.js
git commit -m "fix(store): catch unhandled promise rejection in music player togglePlay"
```
