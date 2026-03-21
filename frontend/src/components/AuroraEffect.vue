<template>
  <div class="aurora-layer">
    <div class="aurora-band band-1"></div>
    <div class="aurora-band band-2"></div>
    <div class="aurora-band band-3"></div>
  </div>
</template>

<style scoped>
.aurora-layer {
  position: fixed;
  inset: 0;
  overflow: hidden;
  pointer-events: none;
  z-index: 1;
}

.aurora-band {
  position: absolute;
  width: 200%;
  height: 40%;
  border-radius: 50%;
  filter: blur(80px);
  opacity: 0.3;
  will-change: transform, opacity;
}

.band-1 {
  top: -10%;
  left: -50%;
  background: linear-gradient(90deg, transparent, rgba(52, 211, 153, 0.4), rgba(99, 102, 241, 0.3), transparent);
  animation: aurora-drift-1 12s ease-in-out infinite alternate;
}

.band-2 {
  top: 10%;
  left: -30%;
  background: linear-gradient(90deg, transparent, rgba(167, 139, 250, 0.35), rgba(52, 211, 153, 0.25), transparent);
  animation: aurora-drift-2 16s ease-in-out infinite alternate;
}

.band-3 {
  top: -5%;
  left: -40%;
  background: linear-gradient(90deg, transparent, rgba(99, 102, 241, 0.3), rgba(167, 139, 250, 0.2), transparent);
  animation: aurora-drift-3 20s ease-in-out infinite alternate;
}

@keyframes aurora-drift-1 {
  0% { transform: translateX(0) translateY(0) rotate(-5deg); opacity: 0.25; }
  100% { transform: translateX(25%) translateY(10%) rotate(5deg); opacity: 0.4; }
}

@keyframes aurora-drift-2 {
  0% { transform: translateX(0) translateY(0) rotate(3deg); opacity: 0.2; }
  100% { transform: translateX(-20%) translateY(-5%) rotate(-3deg); opacity: 0.35; }
}

@keyframes aurora-drift-3 {
  0% { transform: translateX(10%) translateY(5%) rotate(-2deg); opacity: 0.15; }
  100% { transform: translateX(-15%) translateY(-8%) rotate(4deg); opacity: 0.3; }
}

@media (prefers-reduced-motion: reduce) {
  .aurora-band { animation: none; }
}
</style>