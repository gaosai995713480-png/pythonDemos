# 2026-03-20 页面全面 Bug 修复设计文档

## 目标

修复 Vue 页面及 Store 中发现的四个主要高风险 Bug（弹幕轮播失效、内存泄漏、打字声音异常、全盘崩溃的请求并发），保障系统性能和鲁棒性。

## 修改范围

- `frontend/src/views/HomeView.vue`
- `frontend/src/views/WishesView.vue`
- `frontend/src/views/LetterView.vue`
- `frontend/src/stores/music.js`

## 具体修复设计

### 1. 弹幕定时器被清空导致无法轮播 (HomeView.vue)

**问题**：由于 `onMounted` 里先放入了弹幕定时器 ID，随后 `launchAllDanmu` 被执行，并内部调用 `clearDanmuTimers()`，清空了一切已有定时器，导致轮播永久失效。
**解决方案**：
- `launchAllDanmu` 内部不再调用完全清除 `danmuTimers` 数组。可以定义用来清理单独每条弹幕生命周期的数组，与轮播主 `setInterval` 区分开。
- 在 `onUnmounted` 中确保清除轮播主定时器。
- 修改 `clearDanmuTimers`，仅清除每个单独展示弹幕的 `setTimeout`（如果有必要的话）。

### 2. 流星雨与天气组件内存泄漏 (WishesView.vue, HomeView.vue)

**问题**：`setInterval(spawnShootingStar, ...)` 初始化后没有通过 `onUnmounted` 被注销；`onCitySearch` 的 debounce 定时器也未在生命周期后注销。
**解决方案**：
- 在 `WishesView.vue` 中保存 `setInterval` 返回的 ID，在 `onUnmounted` 生命周期内统一 `clearInterval`。
- 在 `HomeView.vue` 中保存市搜索等定时器的 ID，在 `onUnmounted` 中释放。

### 3. 表白信初次声音播放报错 (LetterView.vue)

**问题**：依赖原生 `AudioContext` 播放打字声，但浏览器策略禁止自动播放音频。
**解决方案**：
- 在用户发生第一次真实交互（例如页面点击）前不要初始化并播放 `AudioContext`。
- 给第一个信件设定一个触发按钮（例如：“点击开启表白信”），或者捕获报错静默降级（没有声音直接展示文字，避免报错打断流程）。
- 目前为了最大程度保持体验：可以通过监听第一次全局 click / touch 或者在进入 `LetterView` 时加一个中间点击层再启动播放。最简单的方案是在初始化 `AudioContext` 时加入简单的 `resume()` 调用，并且使用 `catch` 防止报错污染控制台，如果有交互则自然能带上音效。

### 4. 音乐异步调用处理 (stores/music.js)

**问题**：`togglePlay` 中直接调用 `play(0)`，但未对可能发生的错误作 `.catch`。如果在此时出错，`isPlaying.value` 依然会被保持为 `true` 的错觉或者无法回到正确状态。
**解决方案**：
- 为 `togglePlay` 内部分支增加错误捕获。

### 5. 天气预报和实时请求并行异常接管 (HomeView.vue)

**问题**：并行加载 API 是通过 `Promise.all`。一个垮掉会导致两者都失败。
**解决方案**：
- 改用 `Promise.allSettled` 代替 `Promise.all`。
- 分别校验结果：实时天气和预报信息哪个返回了成功状态就直接使用，不必强依赖各自的成败。

## 影响面

上述所有改动涉及纯净的前端逻辑纠正和防泄漏优化，对后端（main.py）及页面 UI 布局无破坏性影响，风险低且收益极高。
