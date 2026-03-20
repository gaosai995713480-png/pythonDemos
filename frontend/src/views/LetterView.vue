<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import TopBar from '../components/TopBar.vue'

const router = useRouter()

const LETTERS = [
  {
    title: '第一封信', date: '写于心动的那一天', salutation: '亲爱的路路：',
    body: `你好呀，是我。\n\n当你看到这封信的时候，我可能正在某个角落里偷偷想你。\n\n还记得我们第一次见面吗？那天的阳光刚刚好，你笑起来的样子像极了春天里最温柔的风。从那一刻起，我的世界就多了一种颜色——是你的颜色。\n\n我不太会说那些甜到腻的情话，但我想让你知道：\n\n遇见你之前，我从来不知道"心动"是什么感觉。\n遇见你之后，我才明白，原来一个人对另一个人的喜欢，可以是一瞬间的事，也可以是一辈子的事。\n\n你的每一个表情我都想好好记住。\n你开心的时候，我的整个世界都在发光。\n你难过的时候，我恨不得把所有温柔都给你。\n\n谢谢你出现在我的生命里。\n谢谢你让平凡的日子变得值得期待。\n谢谢你成为我心里最柔软的那个角落。\n\n往后的日子，我想慢慢地、认真地，和你一起走。无论是阳光灿烂的日子，还是风雨交加的夜晚，我都想站在你身边，做你最坚定的依靠。`,
    sign: '永远为你心动的人',
  },
  {
    title: '给未来的你', date: '写于某个想你的深夜', salutation: '致最特别的你：',
    body: `夜深了，窗外的月光很温柔，像你的眼睛。\n\n今天突然很想你，想你笑起来嘴角弯弯的样子，想你撒娇时故意嘟嘴的模样，想你认真做事时专注的侧脸。\n\n你知道吗？\n\n和你在一起的每一天，我都觉得自己是这个世界上最幸运的人。\n\n有人说喜欢是一阵风，来得快也去得快。\n可是我对你的喜欢，像是种在心里的树。\n每一天都在生长，每一天都更加枝繁叶茂。\n\n我想象过很多关于未来的画面：\n\n我们一起去看海，让浪花打湿你的裙摆。\n我们一起走过四季，春天赏花、夏天听蝉、秋天踩落叶、冬天围炉吃火锅。\n我们一起变老，即使满头白发也要手牵手散步。\n\n这些画面里，每一帧都有你。\n\n所以，请你也要好好的。\n好好吃饭，好好睡觉，好好笑。\n因为你好了，我的全世界就都好了。`,
    sign: '最爱你的人',
  },
  {
    title: '生日快乐', date: '写于你的专属日子', salutation: '我最珍贵的宝贝：',
    body: `今天是你的生日，是这个世界上最重要的日子。\n\n因为这一天，你来到了这个世界。\n因为你来到了这个世界，我才有了遇见你的可能。\n因为遇见了你，我的人生才有了心动的故事。\n\n所以今天，我要对全世界说：\n谢谢这个世界送给我的最好的礼物——你。\n\n生日快乐，我的女孩。\n\n愿你的每一个愿望都能实现。\n愿你永远被温柔以待。\n愿你的笑容永远灿烂如花。\n愿你的眼里永远有星星。\n\n而我会做那个，\n永远站在你身后为你鼓掌的人，\n永远在你需要时第一个出现的人，\n永远把你放在心尖最柔软的地方的人。\n\n今天你是小公主，\n以后的每一天你也是。\n\n我爱你，不止在今天。`,
    sign: '你的专属守护者',
  },
]

const currentLetter = ref(0)
const displayText = ref('')
const showCursor = ref(true)
const showSign = ref(false)
let typingTimer = null
let audioCtx = null

function typeSound() {
  if (!audioCtx) {
    try { audioCtx = new (window.AudioContext || window.webkitAudioContext)() }
    catch { return }
  }
  if (audioCtx.state === 'suspended') {
    audioCtx.resume().catch(() => {})
  }
  if (audioCtx.state === 'suspended') return

  const osc = audioCtx.createOscillator()
  const gain = audioCtx.createGain()
  osc.type = 'sine'
  osc.frequency.setValueAtTime(600 + Math.random() * 400, audioCtx.currentTime)
  gain.gain.setValueAtTime(0.03, audioCtx.currentTime)
  gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.05)
  osc.connect(gain)
  gain.connect(audioCtx.destination)
  osc.start(audioCtx.currentTime)
  osc.stop(audioCtx.currentTime + 0.05)
}

function playLetter(index) {
  if (typingTimer) { clearTimeout(typingTimer); typingTimer = null }
  currentLetter.value = index
  const letter = LETTERS[index]
  displayText.value = ''
  showSign.value = false
  showCursor.value = true

  const text = letter.body
  let charIndex = 0

  function typeNext() {
    if (charIndex >= text.length) {
      showCursor.value = false
      showSign.value = true
      return
    }
    const char = text[charIndex]
    displayText.value += char
    if (char.trim()) typeSound()
    charIndex++
    let delay = 55
    if ('，。！？、；：'.includes(char)) delay = 300
    else if ('。！？'.includes(char)) delay = 500
    else if (char === '\n') delay = 200
    typingTimer = setTimeout(typeNext, delay)
  }

  typingTimer = setTimeout(typeNext, 500)
}

onMounted(() => playLetter(0))
onUnmounted(() => { if (typingTimer) clearTimeout(typingTimer) })
</script>

<template>
  <TopBar title="💌 表白信" @back="router.push('/')">
    <button class="btn-ghost replay-btn" @click="playLetter(currentLetter)">重新播放 ↻</button>
  </TopBar>

  <div class="letter-nav">
    <button
      v-for="(l, i) in LETTERS"
      :key="i"
      class="letter-tab"
      :class="{ 'is-active': currentLetter === i }"
      @click="playLetter(i)"
    >{{ l.title }}</button>
  </div>

  <div class="letter-wrap">
    <div class="letter-seal">💕</div>
    <div class="letter-date">{{ LETTERS[currentLetter].date }}</div>
    <div class="letter-salutation">{{ LETTERS[currentLetter].salutation }}</div>
    <div class="letter-body">{{ displayText }}<span v-if="showCursor" class="cursor"></span></div>
    <div class="letter-sign" :class="{ 'is-visible': showSign }">— {{ LETTERS[currentLetter].sign }}</div>
  </div>
</template>

<style scoped>
.replay-btn { margin-left: auto; font-size: 13px; }

.letter-nav {
  display: flex; gap: 8px; margin: 80px auto 20px;
  max-width: 640px; width: 90%; justify-content: center; flex-wrap: wrap;
}

.letter-tab {
  padding: 6px 16px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.15);
  background: transparent; color: var(--text-secondary); font-size: 13px; cursor: pointer;
}

.letter-tab.is-active { background: rgba(255, 255, 255, 0.15); color: #fff; border-color: var(--primary); }

.letter-wrap {
  max-width: 640px; width: 90%; margin: 0 auto 60px; padding: 40px;
  background: var(--glass-bg); backdrop-filter: blur(30px);
  border: 1px solid var(--glass-border); border-radius: 24px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3); position: relative;
  font-family: "Georgia", "Songti SC", "STSong", serif;
}

.letter-seal { position: absolute; right: 24px; top: 24px; font-size: 36px; opacity: 0.3; }
.letter-date { font-size: 13px; color: var(--text-secondary); margin-bottom: 20px; font-family: -apple-system, sans-serif; }
.letter-salutation { font-size: 22px; font-weight: 700; margin-bottom: 24px; color: var(--accent); }

.letter-body {
  font-size: 17px; line-height: 2; color: rgba(255, 255, 255, 0.9);
  min-height: 200px; white-space: pre-wrap;
}

.cursor {
  display: inline-block; width: 2px; height: 1.2em; background: var(--accent);
  vertical-align: text-bottom; margin-left: 2px;
  animation: blink 0.6s ease-in-out infinite alternate;
}

.letter-sign {
  margin-top: 30px; text-align: right; font-size: 16px;
  color: var(--primary); font-style: italic;
  opacity: 0; transition: opacity 1s;
}

.letter-sign.is-visible { opacity: 1; }

@media (max-width: 720px) {
  .letter-wrap { margin-top: 20px; padding: 28px 24px; }
  .letter-body { font-size: 15px; line-height: 1.9; }
}
</style>
