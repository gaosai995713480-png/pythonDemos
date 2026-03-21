<script setup>
import { useToast } from '../composables/useToast'

const { toast } = useToast()
</script>

<template>
  <Transition name="toast-slide">
    <div v-if="toast.visible" class="app-toast" :class="`toast--${toast.type}`">
      <span class="toast-icon">
        {{ toast.type === 'success' ? '✅' : toast.type === 'error' ? '❌' : toast.type === 'warning' ? '⚠️' : 'ℹ️' }}
      </span>
      <span class="toast-msg">{{ toast.message }}</span>
    </div>
  </Transition>
</template>

<style scoped>
.app-toast {
  position: fixed;
  top: 24px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 9999;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  border-radius: 12px;
  font-size: 14px;
  font-weight: 500;
  color: #fff;
  backdrop-filter: blur(12px);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
  pointer-events: none;
  max-width: 90vw;
}

.toast--info {
  background: rgba(56, 189, 248, 0.85);
}
.toast--success {
  background: rgba(34, 197, 94, 0.85);
}
.toast--error {
  background: rgba(239, 68, 68, 0.85);
}
.toast--warning {
  background: rgba(245, 158, 11, 0.85);
}

.toast-icon {
  font-size: 16px;
}

.toast-msg {
  line-height: 1.4;
}

/* Transition */
.toast-slide-enter-active {
  transition: all 0.3s ease-out;
}
.toast-slide-leave-active {
  transition: all 0.2s ease-in;
}
.toast-slide-enter-from {
  opacity: 0;
  transform: translateX(-50%) translateY(-20px);
}
.toast-slide-leave-to {
  opacity: 0;
  transform: translateX(-50%) translateY(-10px);
}
</style>
