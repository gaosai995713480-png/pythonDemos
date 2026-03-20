<script setup>
const props = defineProps({
  modelValue: { type: Boolean, default: false },
  title: { type: String, default: '' },
})

const emit = defineEmits(['update:modelValue'])

function close() {
  emit('update:modelValue', false)
}

function onBackdropClick(e) {
  if (e.target === e.currentTarget) close()
}
</script>

<template>
  <Teleport to="body">
    <div class="modal-backdrop" :class="{ 'is-visible': modelValue }" @click="onBackdropClick">
      <div class="modal-card" :class="{ 'is-visible': modelValue }">
        <h2 v-if="title">{{ title }}</h2>
        <slot />
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  z-index: 30;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.3s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-backdrop.is-visible {
  opacity: 1;
  pointer-events: auto;
}

.modal-card {
  width: 92%;
  max-width: 480px;
  max-height: 85vh;
  overflow-y: auto;
  background: rgba(30, 30, 50, 0.96);
  backdrop-filter: blur(40px);
  border: 1px solid var(--glass-border);
  border-radius: 24px;
  padding: 28px 24px;
  transform: scale(0.95);
  transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
  opacity: 0;
  pointer-events: none;
}

.modal-card.is-visible {
  opacity: 1;
  transform: scale(1);
  pointer-events: auto;
}

h2 {
  font-size: 20px;
  font-weight: 700;
  margin-bottom: 20px;
  text-align: center;
}
</style>
