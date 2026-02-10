<script setup lang="ts">
import { ref, onMounted } from 'vue'
import {
  RefreshCw,
  Loader2,
  AlertTriangle,
  Shield,
  ShieldOff,
  Plus,
  Trash2,
  ToggleLeft,
  ToggleRight,
  Zap,
  Globe,
  Server,
  Ban,
  CheckCircle,
  XCircle,
  Download,
} from 'lucide-vue-next'
import { useFirewall } from '@/composables/useFirewall'
import type { FirewallRule } from '@/types/api'

const {
  status,
  rules,
  events,
  config,
  dailyStats,
  loading,
  error,
  activeRules,
  blockRules,
  fetchRules,
  addRule,
  removeRule,
  toggleRule,
  syncThreats,
  syncPorts,
  fetchEvents,
  updateConfig,
  installAdapter,
  refreshAll,
} = useFirewall()

const activeTab = ref<'rules' | 'events' | 'settings'>('rules')
const showAddForm = ref(false)
const syncing = ref(false)

// New rule form
const newRule = ref({
  rule_type: 'block_ip',
  target: '',
  direction: 'both',
  protocol: 'any',
  reason_tr: '',
})

const ruleTypeOptions = [
  { value: 'block_ip', label: 'IP Engelle' },
  { value: 'block_port', label: 'Port Engelle' },
  { value: 'block_domain', label: 'Domain Engelle' },
  { value: 'allow_ip', label: 'IP Izin Ver' },
  { value: 'allow_domain', label: 'Domain Izin Ver' },
]

const protectionLevels = [
  { value: 'minimal', label: 'Minimal', desc: 'Sadece bilinen tehditler engellenir' },
  { value: 'balanced', label: 'Dengeli', desc: 'Tehditler + yuksek riskli portlar engellenir' },
  { value: 'strict', label: 'Siki', desc: 'Tum supheli baglantilar engellenir' },
]

const severityColors: Record<string, string> = {
  threat_intel: 'bg-red-500/20 text-red-400 border-red-500/30',
  remediation: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  user: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  collective: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
}

function ruleTypeLabel(type: string): string {
  const labels: Record<string, string> = {
    block_ip: 'IP Engelle',
    block_port: 'Port Engelle',
    block_domain: 'Domain Engelle',
    allow_ip: 'IP Izin',
    allow_domain: 'Domain Izin',
  }
  return labels[type] || type
}

function isBlockRule(type: string): boolean {
  return type.startsWith('block_')
}

async function handleAddRule() {
  if (!newRule.value.target) return
  await addRule({
    id: '',
    rule_type: newRule.value.rule_type,
    target: newRule.value.target,
    direction: newRule.value.direction,
    protocol: newRule.value.protocol,
    source: 'user',
    reason: newRule.value.reason_tr,
    reason_tr: newRule.value.reason_tr,
    is_active: true,
    created_at: '',
    expires_at: null,
    hit_count: 0,
  })
  newRule.value.target = ''
  newRule.value.reason_tr = ''
  showAddForm.value = false
}

async function handleSyncAll() {
  syncing.value = true
  await syncThreats()
  await syncPorts()
  syncing.value = false
}

async function handleProtectionChange(level: string) {
  if (!config.value) return
  await updateConfig({ ...config.value, protection_level: level })
}

onMounted(() => {
  refreshAll()
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white">Guvenlik Duvari</h1>
        <p class="mt-1 text-sm text-slate-400">
          Agin dijital korumasi. Baglantilari izle, tehditleri engelle.
        </p>
      </div>
      <div class="flex items-center gap-3">
        <button
          class="flex items-center gap-2 rounded-lg bg-cyan-500/20 px-4 py-2 text-sm font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
          :disabled="syncing"
          @click="handleSyncAll"
        >
          <Download class="h-4 w-4" :class="{ 'animate-pulse': syncing }" />
          Kurallari Senkronize Et
        </button>
        <button
          class="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-2 text-xs text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
          :disabled="loading"
          @click="refreshAll"
        >
          <RefreshCw class="h-3.5 w-3.5" :class="{ 'animate-spin': loading }" />
          Yenile
        </button>
      </div>
    </div>

    <!-- Loading State -->
    <div
      v-if="loading && !status"
      class="flex flex-col items-center justify-center py-20"
    >
      <Loader2 class="h-8 w-8 animate-spin text-cyan-400" />
      <p class="mt-3 text-sm text-slate-400">Guvenlik duvari durumu yukleniyor...</p>
    </div>

    <!-- Content -->
    <template v-else>
      <!-- Status Banner -->
      <div
        class="glass-card rounded-xl border p-5"
        :class="status?.is_enabled ? 'border-emerald-500/20' : 'border-red-500/20 bg-red-500/5'"
      >
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-4">
            <div
              class="flex h-12 w-12 items-center justify-center rounded-xl"
              :class="status?.is_enabled ? 'bg-emerald-500/10' : 'bg-red-500/10'"
            >
              <Shield v-if="status?.is_enabled" class="h-6 w-6 text-emerald-400" />
              <ShieldOff v-else class="h-6 w-6 text-red-400" />
            </div>
            <div>
              <h2 class="text-lg font-semibold text-white">
                {{ status?.is_enabled ? 'Guvenlik Duvari Aktif' : 'Guvenlik Duvari Devre Disi' }}
              </h2>
              <p class="text-xs text-slate-400">
                Platform: {{ status?.platform || '-' }} |
                Motor: {{ status?.engine || '-' }} |
                Koruma: {{ status?.protection_level || '-' }}
              </p>
            </div>
          </div>
        </div>
      </div>

      <!-- Stats Cards -->
      <div class="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <div class="glass-card rounded-xl p-5 text-center border border-white/5">
          <div class="text-3xl font-bold text-white">{{ status?.active_rules || 0 }}</div>
          <div class="mt-1 text-xs text-slate-400">Aktif Kural</div>
        </div>
        <div class="glass-card rounded-xl p-5 text-center border border-red-500/20">
          <div class="text-3xl font-bold text-red-400">{{ dailyStats?.blocked || 0 }}</div>
          <div class="mt-1 text-xs text-slate-400">Bugunku Engelleme</div>
        </div>
        <div class="glass-card rounded-xl p-5 text-center border border-emerald-500/20">
          <div class="text-3xl font-bold text-emerald-400">{{ dailyStats?.allowed || 0 }}</div>
          <div class="mt-1 text-xs text-slate-400">Bugunku Izin</div>
        </div>
        <div class="glass-card rounded-xl p-5 text-center border border-amber-500/20">
          <div class="text-3xl font-bold text-amber-400">{{ dailyStats?.block_rate || 0 }}%</div>
          <div class="mt-1 text-xs text-slate-400">Engelleme Orani</div>
        </div>
      </div>

      <!-- Tabs -->
      <div class="flex gap-1 rounded-lg bg-white/5 p-1">
        <button
          class="flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors"
          :class="activeTab === 'rules' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-400 hover:text-slate-200'"
          @click="activeTab = 'rules'"
        >
          <Shield class="h-4 w-4" />
          Kurallar ({{ rules.length }})
        </button>
        <button
          class="flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors"
          :class="activeTab === 'events' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-400 hover:text-slate-200'"
          @click="activeTab = 'events'; fetchEvents()"
        >
          <Globe class="h-4 w-4" />
          Olaylar
        </button>
        <button
          class="flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors"
          :class="activeTab === 'settings' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-400 hover:text-slate-200'"
          @click="activeTab = 'settings'"
        >
          <Server class="h-4 w-4" />
          Ayarlar
        </button>
      </div>

      <!-- Rules Tab -->
      <div v-if="activeTab === 'rules'" class="space-y-4">
        <!-- Add Rule Button -->
        <div class="flex justify-end">
          <button
            class="flex items-center gap-2 rounded-lg bg-cyan-500/20 px-3 py-2 text-xs font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
            @click="showAddForm = !showAddForm"
          >
            <Plus class="h-3.5 w-3.5" />
            Kural Ekle
          </button>
        </div>

        <!-- Add Rule Form -->
        <div
          v-if="showAddForm"
          class="glass-card rounded-xl border border-cyan-500/20 p-5 space-y-4"
        >
          <h3 class="text-sm font-semibold text-white">Yeni Kural Ekle</h3>
          <div class="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div>
              <label class="mb-1 block text-xs text-slate-400">Kural Tipi</label>
              <select
                v-model="newRule.rule_type"
                class="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white focus:border-cyan-500 focus:outline-none"
              >
                <option v-for="opt in ruleTypeOptions" :key="opt.value" :value="opt.value">
                  {{ opt.label }}
                </option>
              </select>
            </div>
            <div>
              <label class="mb-1 block text-xs text-slate-400">Hedef (IP / Port / Domain)</label>
              <input
                v-model="newRule.target"
                type="text"
                placeholder="ornek: 192.168.1.1"
                class="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
              />
            </div>
            <div>
              <label class="mb-1 block text-xs text-slate-400">Aciklama (TR)</label>
              <input
                v-model="newRule.reason_tr"
                type="text"
                placeholder="Neden engelleniyor?"
                class="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
              />
            </div>
          </div>
          <div class="flex justify-end gap-2">
            <button
              class="rounded-lg bg-white/5 px-3 py-1.5 text-xs text-slate-400 hover:bg-white/10"
              @click="showAddForm = false"
            >
              Iptal
            </button>
            <button
              class="rounded-lg bg-cyan-500/20 px-4 py-1.5 text-xs font-medium text-cyan-400 hover:bg-cyan-500/30"
              :disabled="!newRule.target"
              @click="handleAddRule"
            >
              Ekle
            </button>
          </div>
        </div>

        <!-- Rules List -->
        <div
          v-if="rules.length === 0"
          class="glass-card rounded-xl p-12 text-center"
        >
          <Shield class="mx-auto h-12 w-12 text-slate-600" />
          <h2 class="mt-4 text-lg font-semibold text-white">Kural Bulunamadi</h2>
          <p class="mt-2 text-sm text-slate-400">
            Henuz firewall kurali eklenmemis. "Kurallari Senkronize Et" ile otomatik kurallar olusturun.
          </p>
        </div>

        <div v-else class="glass-card overflow-hidden rounded-xl border border-white/5">
          <table class="w-full">
            <thead>
              <tr class="border-b border-white/5 text-left">
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Tip</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Hedef</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Kaynak</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Aciklama</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Durum</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Islemler</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/5">
              <tr
                v-for="rule in rules"
                :key="rule.id"
                class="transition-colors hover:bg-white/[0.02]"
              >
                <td class="px-4 py-3">
                  <span
                    class="inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-medium"
                    :class="isBlockRule(rule.rule_type) ? 'bg-red-500/10 text-red-400 border-red-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'"
                  >
                    <Ban v-if="isBlockRule(rule.rule_type)" class="h-2.5 w-2.5" />
                    <CheckCircle v-else class="h-2.5 w-2.5" />
                    {{ ruleTypeLabel(rule.rule_type) }}
                  </span>
                </td>
                <td class="px-4 py-3">
                  <span class="font-mono text-sm text-white">{{ rule.target }}</span>
                </td>
                <td class="px-4 py-3">
                  <span
                    class="inline-flex rounded-md border px-1.5 py-0.5 text-[10px] font-medium"
                    :class="severityColors[rule.source] || 'bg-white/5 text-slate-400 border-white/10'"
                  >
                    {{ rule.source }}
                  </span>
                </td>
                <td class="px-4 py-3 text-xs text-slate-400">
                  {{ rule.reason_tr || rule.reason || '-' }}
                </td>
                <td class="px-4 py-3">
                  <span
                    class="inline-flex items-center gap-1 text-xs font-medium"
                    :class="rule.is_active ? 'text-emerald-400' : 'text-slate-500'"
                  >
                    <span
                      class="h-1.5 w-1.5 rounded-full"
                      :class="rule.is_active ? 'bg-emerald-400' : 'bg-slate-500'"
                    />
                    {{ rule.is_active ? 'Aktif' : 'Pasif' }}
                  </span>
                </td>
                <td class="px-4 py-3">
                  <div class="flex items-center gap-2">
                    <button
                      class="rounded p-1 text-slate-500 transition-colors hover:bg-white/5 hover:text-white"
                      :title="rule.is_active ? 'Devre Disi Birak' : 'Aktif Et'"
                      @click="toggleRule(rule.id)"
                    >
                      <ToggleRight v-if="rule.is_active" class="h-4 w-4 text-emerald-400" />
                      <ToggleLeft v-else class="h-4 w-4" />
                    </button>
                    <button
                      class="rounded p-1 text-slate-500 transition-colors hover:bg-red-500/10 hover:text-red-400"
                      title="Sil"
                      @click="removeRule(rule.id)"
                    >
                      <Trash2 class="h-4 w-4" />
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Events Tab -->
      <div v-if="activeTab === 'events'" class="space-y-4">
        <div
          v-if="events.length === 0"
          class="glass-card rounded-xl p-12 text-center"
        >
          <Globe class="mx-auto h-12 w-12 text-slate-600" />
          <h2 class="mt-4 text-lg font-semibold text-white">Olay Bulunamadi</h2>
          <p class="mt-2 text-sm text-slate-400">
            Henuz firewall olayi kaydedilmemis.
          </p>
        </div>

        <div v-else class="glass-card overflow-hidden rounded-xl border border-white/5">
          <table class="w-full">
            <thead>
              <tr class="border-b border-white/5 text-left">
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Zaman</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Aksiyon</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Kaynak IP</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Hedef IP</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Port</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Protokol</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Uygulama</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/5">
              <tr
                v-for="event in events"
                :key="event.id"
                class="transition-colors hover:bg-white/[0.02]"
              >
                <td class="px-4 py-3 text-xs text-slate-400">
                  {{ event.timestamp?.substring(0, 19).replace('T', ' ') }}
                </td>
                <td class="px-4 py-3">
                  <span
                    class="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[10px] font-medium"
                    :class="event.action === 'blocked' ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'"
                  >
                    <XCircle v-if="event.action === 'blocked'" class="h-2.5 w-2.5" />
                    <CheckCircle v-else class="h-2.5 w-2.5" />
                    {{ event.action === 'blocked' ? 'Engellendi' : 'Izin Verildi' }}
                  </span>
                </td>
                <td class="px-4 py-3 font-mono text-xs text-white">{{ event.source_ip }}</td>
                <td class="px-4 py-3 font-mono text-xs text-cyan-400">{{ event.dest_ip }}</td>
                <td class="px-4 py-3 font-mono text-xs text-white">{{ event.dest_port }}</td>
                <td class="px-4 py-3 text-xs text-slate-400">{{ event.protocol.toUpperCase() }}</td>
                <td class="px-4 py-3 text-xs text-slate-400">{{ event.process_name || '-' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Settings Tab -->
      <div v-if="activeTab === 'settings'" class="space-y-6">
        <!-- Protection Level -->
        <div class="glass-card rounded-xl border border-white/5 p-5">
          <h3 class="text-sm font-semibold text-white">Koruma Seviyesi</h3>
          <p class="mt-1 text-xs text-slate-400">Agin icin uygun koruma seviyesini sec.</p>
          <div class="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
            <button
              v-for="level in protectionLevels"
              :key="level.value"
              class="rounded-xl border p-4 text-left transition-colors"
              :class="config?.protection_level === level.value
                ? 'border-cyan-500/30 bg-cyan-500/10'
                : 'border-white/10 bg-white/5 hover:bg-white/10'"
              @click="handleProtectionChange(level.value)"
            >
              <div class="text-sm font-medium" :class="config?.protection_level === level.value ? 'text-cyan-400' : 'text-white'">
                {{ level.label }}
              </div>
              <div class="mt-1 text-xs text-slate-400">{{ level.desc }}</div>
            </button>
          </div>
        </div>

        <!-- Platform Adapter -->
        <div class="glass-card rounded-xl border border-white/5 p-5">
          <div class="flex items-center justify-between">
            <div>
              <h3 class="text-sm font-semibold text-white">Platform Adaptoru</h3>
              <p class="mt-1 text-xs text-slate-400">
                macOS NEFilterDataProvider entegrasyonu. Apple Developer entitlement gerektirir.
              </p>
            </div>
            <button
              class="flex items-center gap-2 rounded-lg bg-cyan-500/20 px-3 py-2 text-xs font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
              @click="installAdapter"
            >
              <Zap class="h-3.5 w-3.5" />
              Adaptoru Yukle
            </button>
          </div>
          <div class="mt-3 rounded-lg bg-white/5 p-3">
            <div class="text-xs text-slate-400">
              <span class="text-slate-300">Motor:</span> {{ status?.engine || 'Bilinmiyor' }} |
              <span class="text-slate-300">Platform:</span> {{ status?.platform || 'Bilinmiyor' }}
            </div>
          </div>
        </div>

        <!-- Error Display -->
        <div
          v-if="error"
          class="glass-card rounded-xl border border-red-500/20 bg-red-500/5 p-4"
        >
          <div class="flex items-center gap-2">
            <AlertTriangle class="h-4 w-4 text-red-400" />
            <span class="text-sm text-red-400">{{ error }}</span>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>
