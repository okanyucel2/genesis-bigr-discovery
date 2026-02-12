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
  CheckCircle,
  XCircle,
  Globe,
  Ban,
  Download,
  List,
  Activity,
} from 'lucide-vue-next'
import { useGuardian } from '@/composables/useGuardian'

const {
  status,
  stats,
  rules,
  blocklists,
  health,
  loading,
  error,
  activeBlocklists,
  addRule,
  deleteRule,
  updateBlocklists,
  refreshAll,
} = useGuardian()

const activeTab = ref<'overview' | 'rules' | 'blocklists' | 'health'>('overview')
const showAddForm = ref(false)
const updatingLists = ref(false)

// New rule form
const newRule = ref({
  action: 'block',
  domain: '',
  category: 'custom',
  reason: '',
})

const actionOptions = [
  { value: 'block', label: 'Engelle' },
  { value: 'allow', label: 'Izin Ver' },
]

function blockRate(): string {
  if (!status.value?.stats.total_queries) return '0'
  return ((status.value.stats.blocked_queries / status.value.stats.total_queries) * 100).toFixed(1)
}

async function handleAddRule() {
  if (!newRule.value.domain) return
  await addRule(
    newRule.value.action,
    newRule.value.domain,
    newRule.value.category,
    newRule.value.reason,
  )
  newRule.value.domain = ''
  newRule.value.reason = ''
  showAddForm.value = false
}

async function handleUpdateBlocklists() {
  updatingLists.value = true
  await updateBlocklists()
  updatingLists.value = false
}

function healthStatusColor(s: string): string {
  if (s === 'healthy') return 'text-emerald-400'
  if (s === 'degraded') return 'text-amber-400'
  return 'text-red-400'
}

function healthStatusLabel(s: string): string {
  if (s === 'healthy') return 'Saglikli'
  if (s === 'degraded') return 'Dusuk Performans'
  return 'Cevrimdisi'
}

function formatDate(iso: string | null): string {
  if (!iso) return '-'
  return iso.substring(0, 16).replace('T', ' ')
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
        <h1 class="text-2xl font-bold text-white">Guardian DNS Filtreleme</h1>
        <p class="mt-1 text-sm text-slate-400">
          DNS katmaninda koruma. Zararli domainleri engelle, ag trafiğini filtrele.
        </p>
      </div>
      <button
        class="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-2 text-xs text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
        :disabled="loading"
        @click="refreshAll"
      >
        <RefreshCw class="h-3.5 w-3.5" :class="{ 'animate-spin': loading }" />
        Yenile
      </button>
    </div>

    <!-- Loading State -->
    <div
      v-if="loading && !status"
      class="flex flex-col items-center justify-center py-20"
    >
      <Loader2 class="h-8 w-8 animate-spin text-cyan-400" />
      <p class="mt-3 text-sm text-slate-400">Guardian durumu yukleniyor...</p>
    </div>

    <!-- Content -->
    <template v-else>
      <!-- Status Banner -->
      <div
        class="glass-card rounded-xl border p-5"
        :class="status?.guardian_active ? 'border-emerald-500/20' : 'border-amber-500/20 bg-amber-500/5'"
      >
        <div class="flex items-center gap-4">
          <div
            class="flex h-12 w-12 items-center justify-center rounded-xl"
            :class="status?.guardian_active ? 'bg-emerald-500/10' : 'bg-amber-500/10'"
          >
            <Shield v-if="status?.guardian_active" class="h-6 w-6 text-emerald-400" />
            <ShieldOff v-else class="h-6 w-6 text-amber-400" />
          </div>
          <div>
            <h2 class="text-lg font-semibold text-white">
              {{ status?.guardian_active ? 'Guardian Aktif' : 'Guardian Cevrimdisi' }}
            </h2>
            <p class="text-xs text-slate-400">
              DNS Filtreleme: {{ status?.dns_filtering ? 'Acik' : 'Kapali' }} |
              Engel Listesi: {{ status?.blocked_domains_count?.toLocaleString() || 0 }} domain
            </p>
          </div>
        </div>
      </div>

      <!-- Stats Cards -->
      <div class="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <div class="glass-card rounded-xl p-5 text-center border border-white/5">
          <div class="text-3xl font-bold text-white">{{ status?.stats.total_queries?.toLocaleString() || 0 }}</div>
          <div class="mt-1 text-xs text-slate-400">Toplam Sorgu</div>
        </div>
        <div class="glass-card rounded-xl p-5 text-center border border-red-500/20">
          <div class="text-3xl font-bold text-red-400">{{ status?.stats.blocked_queries || 0 }} ({{ blockRate() }}%)</div>
          <div class="mt-1 text-xs text-slate-400">Engellenen</div>
        </div>
        <div class="glass-card rounded-xl p-5 text-center border border-emerald-500/20">
          <div class="text-3xl font-bold text-emerald-400">{{ ((status?.stats.cache_hit_rate || 0) * 100).toFixed(0) }}%</div>
          <div class="mt-1 text-xs text-slate-400">Onbellek Isabet</div>
        </div>
        <div class="glass-card rounded-xl p-5 text-center border border-cyan-500/20">
          <div class="text-3xl font-bold text-cyan-400">{{ activeBlocklists.length }}</div>
          <div class="mt-1 text-xs text-slate-400">Aktif Liste</div>
        </div>
      </div>

      <!-- Tabs -->
      <div class="flex gap-1 rounded-lg bg-white/5 p-1">
        <button
          class="flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors"
          :class="activeTab === 'overview' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-400 hover:text-slate-200'"
          @click="activeTab = 'overview'"
        >
          <Globe class="h-4 w-4" />
          Genel Bakis
        </button>
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
          :class="activeTab === 'blocklists' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-400 hover:text-slate-200'"
          @click="activeTab = 'blocklists'"
        >
          <List class="h-4 w-4" />
          Engel Listeleri
        </button>
        <button
          class="flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors"
          :class="activeTab === 'health' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-400 hover:text-slate-200'"
          @click="activeTab = 'health'"
        >
          <Activity class="h-4 w-4" />
          Saglik
        </button>
      </div>

      <!-- Overview Tab -->
      <div v-if="activeTab === 'overview'" class="space-y-4">
        <!-- Top Blocked Domains -->
        <div v-if="stats?.top_blocked?.length" class="glass-card overflow-hidden rounded-xl border border-white/5">
          <div class="border-b border-white/5 px-4 py-3">
            <h3 class="text-sm font-semibold text-white">En Cok Engellenen Domainler</h3>
          </div>
          <table class="w-full">
            <thead>
              <tr class="border-b border-white/5 text-left">
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Domain</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Kategori</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Isabet</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/5">
              <tr
                v-for="item in stats.top_blocked"
                :key="item.domain"
                class="transition-colors hover:bg-white/[0.02]"
              >
                <td class="px-4 py-3 font-mono text-sm text-white">{{ item.domain }}</td>
                <td class="px-4 py-3">
                  <span class="inline-flex rounded-md border border-red-500/20 bg-red-500/10 px-2 py-0.5 text-[10px] font-medium text-red-400">
                    {{ item.category }}
                  </span>
                </td>
                <td class="px-4 py-3 font-mono text-sm text-slate-300">{{ item.count }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Lifetime Stats -->
        <div v-if="stats?.lifetime" class="glass-card rounded-xl border border-white/5 p-5">
          <h3 class="text-sm font-semibold text-white">Toplam Istatistik</h3>
          <div class="mt-3 grid grid-cols-3 gap-4">
            <div class="text-center">
              <div class="text-xl font-bold text-white">{{ stats.lifetime.total_queries.toLocaleString() }}</div>
              <div class="mt-0.5 text-xs text-slate-400">Toplam Sorgu</div>
            </div>
            <div class="text-center">
              <div class="text-xl font-bold text-red-400">{{ stats.lifetime.blocked_queries.toLocaleString() }}</div>
              <div class="mt-0.5 text-xs text-slate-400">Engellenen</div>
            </div>
            <div class="text-center">
              <div class="text-xl font-bold text-emerald-400">{{ stats.lifetime.allowed_queries.toLocaleString() }}</div>
              <div class="mt-0.5 text-xs text-slate-400">Izin Verilen</div>
            </div>
          </div>
        </div>
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
          <div class="grid grid-cols-1 gap-4 sm:grid-cols-4">
            <div>
              <label class="mb-1 block text-xs text-slate-400">Aksiyon</label>
              <select
                v-model="newRule.action"
                class="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white focus:border-cyan-500 focus:outline-none"
              >
                <option v-for="opt in actionOptions" :key="opt.value" :value="opt.value">
                  {{ opt.label }}
                </option>
              </select>
            </div>
            <div>
              <label class="mb-1 block text-xs text-slate-400">Domain</label>
              <input
                v-model="newRule.domain"
                type="text"
                placeholder="ornek: tracking.example.com"
                class="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
              />
            </div>
            <div>
              <label class="mb-1 block text-xs text-slate-400">Kategori</label>
              <input
                v-model="newRule.category"
                type="text"
                placeholder="custom"
                class="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
              />
            </div>
            <div>
              <label class="mb-1 block text-xs text-slate-400">Aciklama</label>
              <input
                v-model="newRule.reason"
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
              :disabled="!newRule.domain"
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
          <h2 class="mt-4 text-lg font-semibold text-white">Henuz kural eklenmemis</h2>
          <p class="mt-2 text-sm text-slate-400">
            "Kural Ekle" ile DNS filtreleme kurallarinizi olusturun.
          </p>
        </div>

        <div v-else class="glass-card overflow-hidden rounded-xl border border-white/5">
          <table class="w-full">
            <thead>
              <tr class="border-b border-white/5 text-left">
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Aksiyon</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Domain</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Kategori</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Aciklama</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Isabet</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Tarih</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Islem</th>
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
                    :class="rule.action === 'block' ? 'bg-red-500/10 text-red-400 border-red-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'"
                  >
                    <Ban v-if="rule.action === 'block'" class="h-2.5 w-2.5" />
                    <CheckCircle v-else class="h-2.5 w-2.5" />
                    {{ rule.action === 'block' ? 'Engelle' : 'Izin' }}
                  </span>
                </td>
                <td class="px-4 py-3">
                  <span class="font-mono text-sm text-white">{{ rule.domain }}</span>
                </td>
                <td class="px-4 py-3">
                  <span class="inline-flex rounded-md border border-white/10 bg-white/5 px-1.5 py-0.5 text-[10px] font-medium text-slate-400">
                    {{ rule.category }}
                  </span>
                </td>
                <td class="px-4 py-3 text-xs text-slate-400">{{ rule.reason || '-' }}</td>
                <td class="px-4 py-3 font-mono text-xs text-slate-300">{{ rule.hit_count }}</td>
                <td class="px-4 py-3 text-xs text-slate-400">{{ formatDate(rule.created_at) }}</td>
                <td class="px-4 py-3">
                  <button
                    class="rounded p-1 text-slate-500 transition-colors hover:bg-red-500/10 hover:text-red-400"
                    title="Sil"
                    @click="deleteRule(rule.id)"
                  >
                    <Trash2 class="h-4 w-4" />
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Blocklists Tab -->
      <div v-if="activeTab === 'blocklists'" class="space-y-4">
        <div class="flex justify-end">
          <button
            class="flex items-center gap-2 rounded-lg bg-cyan-500/20 px-3 py-2 text-xs font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
            :disabled="updatingLists"
            @click="handleUpdateBlocklists"
          >
            <Download class="h-3.5 w-3.5" :class="{ 'animate-pulse': updatingLists }" />
            Listeleri Guncelle
          </button>
        </div>

        <div v-if="blocklists.length === 0" class="glass-card rounded-xl p-12 text-center">
          <List class="mx-auto h-12 w-12 text-slate-600" />
          <h2 class="mt-4 text-lg font-semibold text-white">Engel listesi bulunamadi</h2>
        </div>

        <div v-else class="glass-card overflow-hidden rounded-xl border border-white/5">
          <table class="w-full">
            <thead>
              <tr class="border-b border-white/5 text-left">
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Isim</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Kategori</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Domain Sayisi</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Son Guncelleme</th>
                <th class="px-4 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-500">Durum</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/5">
              <tr
                v-for="bl in blocklists"
                :key="bl.id"
                class="transition-colors hover:bg-white/[0.02]"
              >
                <td class="px-4 py-3 text-sm text-white">{{ bl.name }}</td>
                <td class="px-4 py-3">
                  <span class="inline-flex rounded-md border border-white/10 bg-white/5 px-1.5 py-0.5 text-[10px] font-medium text-slate-400">
                    {{ bl.category }}
                  </span>
                </td>
                <td class="px-4 py-3 font-mono text-sm text-slate-300">{{ bl.domain_count.toLocaleString() }}</td>
                <td class="px-4 py-3 text-xs text-slate-400">{{ formatDate(bl.last_updated) }}</td>
                <td class="px-4 py-3">
                  <span
                    class="inline-flex items-center gap-1 text-xs font-medium"
                    :class="bl.is_enabled ? 'text-emerald-400' : 'text-slate-500'"
                  >
                    <span
                      class="h-1.5 w-1.5 rounded-full"
                      :class="bl.is_enabled ? 'bg-emerald-400' : 'bg-slate-500'"
                    />
                    {{ bl.is_enabled ? 'Aktif' : 'Pasif' }}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Health Tab -->
      <div v-if="activeTab === 'health'" class="space-y-4">
        <!-- Overall Status -->
        <div
          v-if="health"
          class="glass-card rounded-xl border p-5"
          :class="{
            'border-emerald-500/20': health.status === 'healthy',
            'border-amber-500/20': health.status === 'degraded',
            'border-red-500/20': health.status === 'offline',
          }"
        >
          <div class="flex items-center gap-3">
            <CheckCircle v-if="health.status === 'healthy'" class="h-6 w-6 text-emerald-400" />
            <AlertTriangle v-else-if="health.status === 'degraded'" class="h-6 w-6 text-amber-400" />
            <XCircle v-else class="h-6 w-6 text-red-400" />
            <div>
              <h3 class="text-lg font-semibold" :class="healthStatusColor(health.status)">
                {{ healthStatusLabel(health.status) }}
              </h3>
              <p v-if="health.message" class="text-xs text-slate-400">{{ health.message }}</p>
            </div>
          </div>
        </div>

        <!-- Individual Checks -->
        <div v-if="health?.checks" class="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div
            v-for="(check, name) in health.checks"
            :key="name"
            class="glass-card rounded-xl border p-4"
            :class="check.ok ? 'border-emerald-500/20' : 'border-red-500/20'"
          >
            <div class="flex items-center gap-3">
              <CheckCircle v-if="check.ok" class="h-5 w-5 text-emerald-400" />
              <XCircle v-else class="h-5 w-5 text-red-400" />
              <div>
                <h4 class="text-sm font-medium text-white">{{ name }}</h4>
                <p v-if="check.detail" class="mt-0.5 text-xs text-slate-400">{{ check.detail }}</p>
              </div>
            </div>
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
    </template>
  </div>
</template>
