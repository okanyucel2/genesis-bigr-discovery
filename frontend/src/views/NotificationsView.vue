<script setup lang="ts">
import { onMounted } from 'vue'
import {
  RefreshCw,
  Loader2,
  AlertTriangle,
  Shield,
  CheckCheck,
} from 'lucide-vue-next'
import NotificationCard from '@/components/notifications/NotificationCard.vue'
import { useNotifications } from '@/composables/useNotifications'

const {
  filteredNotifications,
  criticalNotifications,
  warningNotifications,
  infoNotifications,
  loading,
  error,
  unreadCount,
  activeSeverityFilter,
  fetchSampleNotifications,
  markAsRead,
  markAllAsRead,
  setSeverityFilter,
} = useNotifications()

function handleAction(notificationId: string, _actionType: string) {
  // Mark as read when user takes action
  markAsRead(notificationId)
  // In a real implementation, this would trigger the backend action
  // For now, it just marks the notification as read
}

function handleDismiss(notificationId: string) {
  markAsRead(notificationId)
}

onMounted(() => {
  fetchSampleNotifications()
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white">Bildirimler</h1>
        <p class="mt-1 text-sm text-slate-400">
          Sen kahveni yudumla, arkanı biz kollarız.
        </p>
      </div>
      <div class="flex items-center gap-3">
        <button
          v-if="unreadCount > 0"
          class="flex items-center gap-2 rounded-lg bg-cyan-500/20 px-4 py-2 text-sm font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
          @click="markAllAsRead"
        >
          <CheckCheck class="h-4 w-4" />
          Tumunu Okundu Isaretle ({{ unreadCount }})
        </button>
        <button
          class="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-2 text-xs text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
          :disabled="loading"
          @click="fetchSampleNotifications"
        >
          <RefreshCw class="h-3.5 w-3.5" :class="{ 'animate-spin': loading }" />
          Yenile
        </button>
      </div>
    </div>

    <!-- Loading State -->
    <div
      v-if="loading && filteredNotifications.length === 0"
      class="flex flex-col items-center justify-center py-20"
    >
      <Loader2 class="h-8 w-8 animate-spin text-cyan-400" />
      <p class="mt-3 text-sm text-slate-400">Bildirimler yukleniyor...</p>
    </div>

    <!-- Error State -->
    <div
      v-else-if="error && filteredNotifications.length === 0"
      class="glass-card mx-auto max-w-md rounded-xl p-8 text-center"
    >
      <AlertTriangle class="mx-auto h-10 w-10 text-amber-400" />
      <h2 class="mt-3 text-lg font-semibold text-white">Veri Yuklenemedi</h2>
      <p class="mt-2 text-sm text-slate-400">{{ error }}</p>
      <button
        class="mt-4 rounded-lg bg-cyan-500/20 px-4 py-2 text-sm font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
        @click="fetchSampleNotifications"
      >
        Tekrar Dene
      </button>
    </div>

    <!-- Content -->
    <template v-else>
      <!-- Severity Summary Cards -->
      <div class="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <button
          class="glass-card rounded-xl p-5 text-center border transition-all"
          :class="activeSeverityFilter === null ? 'border-cyan-500/30 ring-1 ring-cyan-500/20' : 'border-white/5 hover:border-white/10'"
          @click="setSeverityFilter(null)"
        >
          <div class="text-3xl font-bold text-white">
            {{ criticalNotifications.length + warningNotifications.length + infoNotifications.length }}
          </div>
          <div class="mt-1 text-xs text-slate-400">Toplam</div>
        </button>
        <button
          class="glass-card rounded-xl p-5 text-center border transition-all"
          :class="activeSeverityFilter === 'critical' ? 'border-red-500/30 ring-1 ring-red-500/20' : 'border-red-500/10 hover:border-red-500/20'"
          @click="setSeverityFilter(activeSeverityFilter === 'critical' ? null : 'critical')"
        >
          <div class="text-3xl font-bold text-red-400">{{ criticalNotifications.length }}</div>
          <div class="mt-1 text-xs text-slate-400">Kritik</div>
        </button>
        <button
          class="glass-card rounded-xl p-5 text-center border transition-all"
          :class="activeSeverityFilter === 'warning' ? 'border-amber-500/30 ring-1 ring-amber-500/20' : 'border-amber-500/10 hover:border-amber-500/20'"
          @click="setSeverityFilter(activeSeverityFilter === 'warning' ? null : 'warning')"
        >
          <div class="text-3xl font-bold text-amber-400">{{ warningNotifications.length }}</div>
          <div class="mt-1 text-xs text-slate-400">Uyari</div>
        </button>
        <button
          class="glass-card rounded-xl p-5 text-center border transition-all"
          :class="activeSeverityFilter === 'info' ? 'border-cyan-500/30 ring-1 ring-cyan-500/20' : 'border-cyan-500/10 hover:border-cyan-500/20'"
          @click="setSeverityFilter(activeSeverityFilter === 'info' ? null : 'info')"
        >
          <div class="text-3xl font-bold text-cyan-400">{{ infoNotifications.length }}</div>
          <div class="mt-1 text-xs text-slate-400">Bilgi</div>
        </button>
      </div>

      <!-- Empty State -->
      <div
        v-if="filteredNotifications.length === 0"
        class="glass-card rounded-xl p-16 text-center"
      >
        <Shield class="mx-auto h-16 w-16 text-emerald-400/60" />
        <h2 class="mt-6 text-xl font-semibold text-white">Her Sey Yolunda!</h2>
        <p class="mx-auto mt-3 max-w-sm text-sm leading-relaxed text-slate-400">
          Arkaniz kollanıyor. Su an icin bildirimi gerektiren bir durum yok.
          Rahatca kahvenizi yudumlayin.
        </p>
      </div>

      <!-- Notification List -->
      <div v-else class="space-y-3">
        <TransitionGroup name="list">
          <NotificationCard
            v-for="notification in filteredNotifications"
            :key="notification.id"
            :notification="notification"
            @action="(type: string) => handleAction(notification.id, type)"
            @dismiss="handleDismiss(notification.id)"
          />
        </TransitionGroup>
      </div>
    </template>
  </div>
</template>

<style scoped>
.list-enter-active,
.list-leave-active {
  transition: all 0.3s ease;
}
.list-enter-from {
  opacity: 0;
  transform: translateX(-20px);
}
.list-leave-to {
  opacity: 0;
  transform: translateX(20px);
}
.list-move {
  transition: transform 0.3s ease;
}
</style>
