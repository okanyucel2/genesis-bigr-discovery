<script setup lang="ts">
defineProps<{
  sender: 'bigr' | 'user'
  message: string
  animated?: boolean
}>()
</script>

<template>
  <div
    class="chat-bubble flex"
    :class="sender === 'bigr' ? 'justify-start' : 'justify-end'"
  >
    <div
      class="max-w-[85%] rounded-2xl px-4 py-3 text-sm"
      :class="[
        sender === 'bigr'
          ? 'bg-white/5 text-slate-200 rounded-tl-sm'
          : 'bg-cyan-500/20 text-cyan-300 rounded-tr-sm',
        animated ? 'chat-fade-in' : '',
      ]"
    >
      <slot>{{ message }}</slot>
    </div>
  </div>
</template>

<style scoped>
.chat-fade-in {
  animation: chatFadeIn 0.3s ease-out;
}

@keyframes chatFadeIn {
  from {
    opacity: 0;
    transform: translateY(8px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
</style>
