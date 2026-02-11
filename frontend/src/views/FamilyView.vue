<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import {
  Shield,
  Plus,
  RefreshCw,
  Loader2,
  AlertTriangle,
  X,
  Clock,
  Wifi,
} from 'lucide-vue-next'
import { useFamilyStore } from '@/stores/family'
import { useSubscriptionStore } from '@/stores/subscription'
import DeviceCard from '@/components/family/DeviceCard.vue'
import SafetyRing from '@/components/family/SafetyRing.vue'
import StatCard from '@/components/dashboard/StatCard.vue'

const family = useFamilyStore()
const subscription = useSubscriptionStore()

const showAddModal = ref(false)
const newDeviceName = ref('')
const newDeviceType = ref('other')
const newDeviceOwner = ref('')

const deviceTypeOptions = [
  { value: 'phone', label: 'Telefon', icon: '\uD83D\uDCF1' },
  { value: 'laptop', label: 'Dizustu', icon: '\uD83D\uDCBB' },
  { value: 'tablet', label: 'Tablet', icon: '\uD83D\uDCDF' },
  { value: 'desktop', label: 'Masaustu', icon: '\uD83D\uDDA5\uFE0F' },
  { value: 'other', label: 'Diger', icon: '\uD83D\uDCE1' },
]

async function initialize() {
  // Ensure subscription is loaded
  if (!subscription.currentSubscription) {
    await subscription.fetchCurrentSubscription()
  }

  // For MVP, use the subscription ID if available
  if (subscription.currentSubscription) {
    // The subscription response includes device_id; we need the subscription record's id
    // We'll use a query param approach - for MVP use a static approach
    const currentSub = subscription.currentSubscription
    if (currentSub.plan_id === 'family') {
      // Try to extract subscription id from the currentSubscription
      const subRecord = currentSub as unknown as { id?: string; device_id: string }
      const id = subRecord.id || subRecord.device_id || 'local-device-001'
      await family.setSubscriptionId(id)
      await family.loadAll()
    }
  }
}

async function handleAddDevice() {
  if (!newDeviceName.value.trim()) return

  await family.addDevice({
    device_name: newDeviceName.value.trim(),
    device_type: newDeviceType.value,
    owner_name: newDeviceOwner.value.trim() || undefined,
  })

  if (!family.error) {
    showAddModal.value = false
    newDeviceName.value = ''
    newDeviceType.value = 'other'
    newDeviceOwner.value = ''
  }
}

async function handleRemoveDevice(deviceId: string) {
  await family.removeDevice(deviceId)
}

function handleRefresh() {
  family.loadAll()
}

onMounted(() => {
  initialize()
})

// Re-initialize when subscription changes
watch(
  () => subscription.currentSubscription?.plan_id,
  () => initialize(),
)

// Severity color helper for alerts
function alertSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'text-red-400'
    case 'high': return 'text-orange-400'
    case 'medium': return 'text-amber-400'
    case 'low': return 'text-slate-400'
    default: return 'text-cyan-400'
  }
}

function alertSeverityBg(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500/10 border-red-500/20'
    case 'high': return 'bg-orange-500/10 border-orange-500/20'
    case 'medium': return 'bg-amber-500/10 border-amber-500/20'
    default: return 'bg-cyan-500/10 border-cyan-500/20'
  }
}
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/15">
          <Shield class="h-6 w-6 text-emerald-400" />
        </div>
        <div>
          <h1 class="text-2xl font-bold text-white">Aile Kalkani</h1>
          <p class="mt-0.5 text-sm text-slate-400">
            {{ family.safetyMessage }}
          </p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <!-- Device count indicator -->
        <div class="rounded-lg bg-white/5 px-3 py-1.5 text-xs text-slate-400">
          <span class="font-medium text-emerald-400">{{ family.deviceCount }}</span>
          / {{ family.maxDevices }} cihaz
        </div>
        <button
          class="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-2 text-xs text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
          :disabled="family.isLoading"
          @click="handleRefresh"
        >
          <RefreshCw class="h-3.5 w-3.5" :class="{ 'animate-spin': family.isLoading }" />
          Yenile
        </button>
      </div>
    </div>

    <!-- Plan mismatch warning -->
    <div
      v-if="subscription.currentPlanId !== 'family'"
      class="glass-card rounded-xl border border-amber-500/20 bg-amber-500/5 p-6 text-center"
    >
      <AlertTriangle class="mx-auto h-10 w-10 text-amber-400" />
      <h2 class="mt-3 text-lg font-semibold text-white">Aile Kalkani Aktif Degil</h2>
      <p class="mt-2 text-sm text-slate-400">
        Aile Kalkani ozelliklerini kullanmak icin Family Shield planina gecin.
      </p>
      <RouterLink
        to="/pricing"
        class="mt-4 inline-flex items-center gap-2 rounded-lg bg-emerald-500/20 px-4 py-2 text-sm font-medium text-emerald-400 transition-colors hover:bg-emerald-500/30"
      >
        Planlari Incele
      </RouterLink>
    </div>

    <!-- Loading State -->
    <div
      v-else-if="family.isLoading && !family.overview"
      class="flex flex-col items-center justify-center py-20"
    >
      <Loader2 class="h-8 w-8 animate-spin text-emerald-400" />
      <p class="mt-3 text-sm text-slate-400">Aile paneli yukleniyor...</p>
    </div>

    <!-- Error State -->
    <div
      v-else-if="family.error && !family.overview"
      class="glass-card mx-auto max-w-md rounded-xl p-8 text-center"
    >
      <AlertTriangle class="mx-auto h-10 w-10 text-amber-400" />
      <h2 class="mt-3 text-lg font-semibold text-white">Veri Yuklenemedi</h2>
      <p class="mt-2 text-sm text-slate-400">{{ family.error }}</p>
      <button
        class="mt-4 rounded-lg bg-emerald-500/20 px-4 py-2 text-sm font-medium text-emerald-400 transition-colors hover:bg-emerald-500/30"
        @click="handleRefresh"
      >
        Tekrar Dene
      </button>
    </div>

    <!-- Dashboard Content -->
    <template v-else-if="subscription.currentPlanId === 'family'">
      <!-- Top Stats Row -->
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <!-- Overall Safety -->
        <div class="glass-card flex items-center gap-4 rounded-xl p-5">
          <SafetyRing :score="family.avgSafetyScore" :size="72" :stroke-width="5" />
          <div>
            <p class="text-xs font-medium uppercase tracking-wider text-slate-400">Genel Guvenlik</p>
            <p class="mt-1 text-sm font-medium" :class="{
              'text-emerald-400': family.safetyLevel === 'safe',
              'text-amber-400': family.safetyLevel === 'warning',
              'text-red-400': family.safetyLevel === 'danger',
            }">
              {{ family.safetyMessage }}
            </p>
          </div>
        </div>

        <StatCard
          label="Cevrimici Cihaz"
          :value="`${family.devicesOnline} / ${family.deviceCount}`"
          :icon="Wifi"
          color="#10b981"
        />
        <StatCard
          label="Toplam Tehdit"
          :value="family.totalThreats"
          :icon="AlertTriangle"
          :color="family.totalThreats > 0 ? '#f59e0b' : '#10b981'"
        />
        <StatCard
          label="Son Tarama"
          :value="family.overview?.last_scan ? family.overview.last_scan.slice(0, 10) : 'Henuz yok'"
          :icon="Clock"
          color="#06b6d4"
        />
      </div>

      <!-- Device Grid -->
      <div>
        <div class="mb-3 flex items-center justify-between">
          <h2 class="text-sm font-medium uppercase tracking-wider text-slate-400">
            Aile Cihazlari
          </h2>
          <button
            v-if="family.canAddDevice"
            class="flex items-center gap-1.5 rounded-lg bg-emerald-500/15 px-3 py-1.5 text-xs font-medium text-emerald-400 transition-colors hover:bg-emerald-500/25"
            @click="showAddModal = true"
          >
            <Plus class="h-3.5 w-3.5" />
            Cihaz Ekle
          </button>
          <span v-else class="text-xs text-slate-500">
            Cihaz limiti doldu
          </span>
        </div>

        <!-- Empty state -->
        <div
          v-if="family.deviceCount === 0"
          class="glass-card flex flex-col items-center justify-center rounded-xl p-12 text-center"
        >
          <div class="text-4xl">&#x1F6E1;&#xFE0F;</div>
          <h3 class="mt-4 text-lg font-semibold text-white">Aile Kalkanini Kur</h3>
          <p class="mt-2 max-w-sm text-sm text-slate-400">
            Aile Kalkanini kurmak icin ilk cihazini ekle. Tum ailenin guvenligini tek panelden takip et.
          </p>
          <button
            class="mt-6 flex items-center gap-2 rounded-lg bg-emerald-500/20 px-5 py-2.5 text-sm font-medium text-emerald-400 transition-colors hover:bg-emerald-500/30"
            @click="showAddModal = true"
          >
            <Plus class="h-4 w-4" />
            Ilk Cihazi Ekle
          </button>
        </div>

        <!-- Device cards grid -->
        <div
          v-else
          class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3"
        >
          <DeviceCard
            v-for="device in family.devices"
            :key="device.id"
            :device="device"
            @remove="handleRemoveDevice"
          />
        </div>
      </div>

      <!-- Alerts & Timeline -->
      <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <!-- Recent Alerts -->
        <div class="glass-panel rounded-xl p-5">
          <div class="mb-4 flex items-center justify-between">
            <h3 class="text-sm font-medium text-slate-300">Son Uyarilar</h3>
            <span v-if="family.unreadAlerts.length > 0" class="rounded-full bg-amber-500/20 px-2 py-0.5 text-[10px] font-medium text-amber-400">
              {{ family.unreadAlerts.length }} yeni
            </span>
          </div>
          <div v-if="family.alerts.length === 0" class="py-6 text-center text-sm text-slate-500">
            Henuz uyari yok. Endiselenme, her sey yolunda.
          </div>
          <div v-else class="space-y-2">
            <div
              v-for="alert in family.alerts.slice(0, 10)"
              :key="alert.id"
              class="rounded-lg border p-3"
              :class="alertSeverityBg(alert.severity)"
            >
              <div class="flex items-start justify-between gap-2">
                <div class="min-w-0 flex-1">
                  <div class="flex items-center gap-2">
                    <span class="text-xs font-medium" :class="alertSeverityColor(alert.severity)">
                      {{ alert.severity.toUpperCase() }}
                    </span>
                    <span class="text-xs text-slate-400">{{ alert.device_name }}</span>
                  </div>
                  <p class="mt-1 text-sm text-slate-300">{{ alert.message }}</p>
                </div>
                <span class="shrink-0 text-[10px] text-slate-500">
                  {{ alert.timestamp.slice(0, 10) }}
                </span>
              </div>
            </div>
          </div>
        </div>

        <!-- Activity Timeline -->
        <div class="glass-panel rounded-xl p-5">
          <h3 class="mb-4 text-sm font-medium text-slate-300">Aktivite Gecmisi</h3>
          <div v-if="family.timeline.length === 0" class="py-6 text-center text-sm text-slate-500">
            Henuz aktivite kaydedilmedi.
          </div>
          <div v-else class="space-y-3">
            <div
              v-for="entry in family.timeline.slice(0, 15)"
              :key="entry.id"
              class="flex items-start gap-3"
            >
              <div class="mt-0.5 text-lg leading-none">{{ entry.device_icon }}</div>
              <div class="min-w-0 flex-1">
                <p class="text-sm text-slate-300">{{ entry.message }}</p>
                <div class="mt-0.5 flex items-center gap-2 text-[10px] text-slate-500">
                  <span>{{ entry.device_name }}</span>
                  <span>{{ entry.timestamp.slice(0, 19).replace('T', ' ') }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </template>

    <!-- Add Device Modal -->
    <Teleport to="body">
      <Transition name="modal">
        <div
          v-if="showAddModal"
          class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          @click.self="showAddModal = false"
        >
          <div class="glass-card w-full max-w-md rounded-2xl border border-emerald-500/20 p-6">
            <div class="mb-5 flex items-center justify-between">
              <h2 class="text-lg font-semibold text-white">Cihaz Ekle</h2>
              <button
                class="rounded-lg p-1 text-slate-500 hover:bg-white/5 hover:text-slate-300"
                @click="showAddModal = false"
              >
                <X class="h-5 w-5" />
              </button>
            </div>

            <form @submit.prevent="handleAddDevice" class="space-y-4">
              <!-- Device name -->
              <div>
                <label class="mb-1.5 block text-xs font-medium text-slate-400">Cihaz Adi</label>
                <input
                  v-model="newDeviceName"
                  type="text"
                  placeholder="ornegin: Okan'in iPhone"
                  class="w-full rounded-lg border border-slate-700 bg-slate-800/50 px-3 py-2.5 text-sm text-white placeholder-slate-500 focus:border-emerald-500/50 focus:outline-none focus:ring-1 focus:ring-emerald-500/50"
                  required
                />
              </div>

              <!-- Device type -->
              <div>
                <label class="mb-1.5 block text-xs font-medium text-slate-400">Cihaz Tipi</label>
                <div class="grid grid-cols-5 gap-2">
                  <button
                    v-for="option in deviceTypeOptions"
                    :key="option.value"
                    type="button"
                    class="flex flex-col items-center gap-1 rounded-lg border px-2 py-2.5 text-center transition-all"
                    :class="newDeviceType === option.value
                      ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-400'
                      : 'border-slate-700 bg-slate-800/30 text-slate-400 hover:border-slate-600'"
                    @click="newDeviceType = option.value"
                  >
                    <span class="text-lg">{{ option.icon }}</span>
                    <span class="text-[10px]">{{ option.label }}</span>
                  </button>
                </div>
              </div>

              <!-- Owner name -->
              <div>
                <label class="mb-1.5 block text-xs font-medium text-slate-400">Sahip (istege bagli)</label>
                <input
                  v-model="newDeviceOwner"
                  type="text"
                  placeholder="ornegin: Okan"
                  class="w-full rounded-lg border border-slate-700 bg-slate-800/50 px-3 py-2.5 text-sm text-white placeholder-slate-500 focus:border-emerald-500/50 focus:outline-none focus:ring-1 focus:ring-emerald-500/50"
                />
              </div>

              <!-- Error message -->
              <div v-if="family.error" class="rounded-lg bg-red-500/10 px-3 py-2 text-xs text-red-400">
                {{ family.error }}
              </div>

              <!-- Submit -->
              <button
                type="submit"
                class="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-500/20 py-2.5 text-sm font-medium text-emerald-400 transition-colors hover:bg-emerald-500/30 disabled:opacity-50"
                :disabled="family.isAddingDevice || !newDeviceName.trim()"
              >
                <Loader2 v-if="family.isAddingDevice" class="h-4 w-4 animate-spin" />
                <Plus v-else class="h-4 w-4" />
                Cihaz Ekle
              </button>
            </form>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<style scoped>
.modal-enter-active,
.modal-leave-active {
  transition: all 0.25s ease;
}
.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}
.modal-enter-from .glass-card,
.modal-leave-to .glass-card {
  transform: scale(0.95);
}
</style>
