<script setup>
import { ref } from 'vue'
import { useLyricFxStore } from '../stores/lyricFx'

const lyricFxStore = useLyricFxStore()
const open = ref(false)

function toggle() {
  open.value = !open.value
}

function select(effect) {
  lyricFxStore.apply(effect.key)
  open.value = false
}

// 点击外部关闭
function onClickOutside() {
  open.value = false
}
</script>

<template>
  <div class="fx-wrap" v-click-outside="onClickOutside">
    <button class="fx-btn" type="button" title="歌词漂浮效果" @click.stop="toggle">
      {{ lyricFxStore.current.emoji }}
    </button>
    <div class="fx-dropdown" :class="{ 'is-open': open }">
      <button
        v-for="effect in lyricFxStore.effects"
        :key="effect.key"
        type="button"
        class="fx-item"
        :class="{ 'is-active': lyricFxStore.currentKey === effect.key }"
        @click="select(effect)"
      >
        <span class="fx-item-emoji">{{ effect.emoji }}</span>
        <span class="fx-item-text">
          <span class="fx-item-name">{{ effect.name }}</span>
          <span class="fx-item-desc">{{ effect.desc }}</span>
        </span>
      </button>
    </div>
  </div>
</template>

<style scoped>
.fx-wrap {
  position: relative;
}

.fx-btn {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  border: 1px solid rgba(255, 255, 255, 0.15);
  background: rgba(255, 255, 255, 0.1);
  color: #fff;
  font-size: 18px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}

.fx-btn:hover {
  background: rgba(255, 255, 255, 0.2);
  transform: scale(1.05);
}

.fx-dropdown {
  position: absolute;
  top: calc(100% + 8px);
  right: 0;
  background: rgba(20, 20, 30, 0.92);
  backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.15);
  border-radius: 14px;
  padding: 8px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  width: 200px;
  opacity: 0;
  pointer-events: none;
  transform: translateY(-6px);
  transition: all 0.2s ease;
  z-index: 50;
}

.fx-dropdown.is-open {
  opacity: 1;
  pointer-events: auto;
  transform: translateY(0);
}

.fx-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border: 1px solid transparent;
  border-radius: 10px;
  background: transparent;
  color: #fff;
  text-align: left;
  cursor: pointer;
  transition: all 0.2s;
}

.fx-item:hover {
  background: rgba(255, 255, 255, 0.12);
}

.fx-item.is-active {
  border-color: rgba(255, 255, 255, 0.5);
  background: rgba(255, 255, 255, 0.16);
}

.fx-item-emoji {
  font-size: 16px;
  line-height: 1;
}

.fx-item-text {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.fx-item-name {
  font-size: 13px;
  font-weight: 600;
}

.fx-item-desc {
  font-size: 11px;
  opacity: 0.6;
}
</style>
