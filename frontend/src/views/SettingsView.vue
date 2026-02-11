<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import {
  Settings,
  Globe,
  CheckCircle,
  XCircle,
  Radar,
  Info,
  Shield,
  Eye,
  EyeOff,
  Loader2,
  Trash2,
} from 'lucide-vue-next'
import { useHealth } from '@/composables/useHealth'
import { bigrApi } from '@/lib/api'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'

const { status, dataFile, dataExists } = useHealth()

// AbuseIPDB settings state
const abuseSettings = ref<{
  api_key_set: boolean
  api_key_masked: string
  daily_limit: number
  remaining_calls: number
  cache_size: number
  source: string
} | null>(null)
const abuseApiKey = ref('')
const abuseDailyLimit = ref(1000)
const abuseShowKey = ref(false)
const abuseSaving = ref(false)
const abuseTesting = ref(false)
const abuseClearing = ref(false)
const abuseMessage = ref<{ type: 'success' | 'error'; text: string } | null>(null)

async function loadAbuseSettings() {
  try {
    const res = await bigrApi.getAbuseIPDBSettings()
    abuseSettings.value = res.data
    abuseDailyLimit.value = res.data.daily_limit
  } catch {
    // Silently fail
  }
}

async function saveAbuseSettings() {
  abuseSaving.value = true
  abuseMessage.value = null
  try {
    const res = await bigrApi.updateAbuseIPDBSettings({
      api_key: abuseApiKey.value,
      daily_limit: abuseDailyLimit.value,
    })
    abuseMessage.value = { type: 'success', text: res.data.message }
    abuseApiKey.value = ''
    abuseShowKey.value = false
    await loadAbuseSettings()
  } catch (e: unknown) {
    abuseMessage.value = {
      type: 'error',
      text: e instanceof Error ? e.message : 'Kaydetme basarisiz',
    }
  } finally {
    abuseSaving.value = false
  }
}

async function testAbuseConnection() {
  abuseTesting.value = true
  abuseMessage.value = null
  try {
    const res = await bigrApi.testAbuseIPDBConnection()
    abuseMessage.value = {
      type: res.data.valid ? 'success' : 'error',
      text: res.data.message,
    }
  } catch (e: unknown) {
    abuseMessage.value = {
      type: 'error',
      text: e instanceof Error ? e.message : 'Test basarisiz',
    }
  } finally {
    abuseTesting.value = false
  }
}

async function clearAbuseSettings() {
  abuseClearing.value = true
  abuseMessage.value = null
  try {
    const res = await bigrApi.clearAbuseIPDBSettings()
    abuseMessage.value = { type: 'success', text: res.data.message }
    abuseApiKey.value = ''
    await loadAbuseSettings()
  } catch (e: unknown) {
    abuseMessage.value = {
      type: 'error',
      text: e instanceof Error ? e.message : 'Temizleme basarisiz',
    }
  } finally {
    abuseClearing.value = false
  }
}

onMounted(() => {
  loadAbuseSettings()
})

const apiUrl = computed(() => {
  const envUrl = import.meta.env.VITE_API_URL
  return envUrl || `${window.location.origin}`
})

const statusColor = computed(() => {
  switch (status.value) {
    case 'ok':
      return 'text-emerald-400'
    case 'error':
      return 'text-rose-400'
    default:
      return 'text-amber-400'
  }
})

const statusLabel = computed(() => {
  switch (status.value) {
    case 'ok':
      return 'Bağlı'
    case 'error':
      return 'Bağlantı Yok'
    default:
      return 'Kontrol Ediliyor...'
  }
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div>
      <h1 class="text-2xl font-bold text-white">Ayarlar</h1>
      <p class="mt-1 text-sm text-slate-400">
        Yapılandırma ve sistem bilgisi
      </p>
    </div>

    <!-- Tabs -->
    <Tabs default-value="general">
      <TabsList>
        <TabsTrigger value="general">Genel</TabsTrigger>
        <TabsTrigger value="integrations">Entegrasyonlar</TabsTrigger>
        <TabsTrigger value="scanner">Tarayıcı</TabsTrigger>
        <TabsTrigger value="about">Hakkında</TabsTrigger>
      </TabsList>

      <!-- General Tab -->
      <TabsContent value="general">
        <div class="space-y-4">
          <!-- API Connection -->
          <Card>
            <CardHeader>
              <CardTitle class="flex items-center gap-2 text-sm">
                <Globe :size="16" class="text-cyan-400" />
                API Bağlantısı
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div class="space-y-4">
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Uç Nokta URL</span>
                  <span class="font-mono text-sm text-slate-300">{{ apiUrl }}</span>
                </div>
                <Separator />
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Durum</span>
                  <div class="flex items-center gap-2">
                    <component
                      :is="status === 'ok' ? CheckCircle : status === 'error' ? XCircle : Settings"
                      :size="14"
                      :class="statusColor"
                    />
                    <span class="text-sm font-medium" :class="statusColor">
                      {{ statusLabel }}
                    </span>
                  </div>
                </div>
                <Separator />
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Veri Dosyası</span>
                  <span class="font-mono text-xs text-slate-400">
                    {{ dataFile ?? 'N/A' }}
                  </span>
                </div>
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Veri Mevcut</span>
                  <div class="flex items-center gap-2">
                    <component
                      :is="dataExists ? CheckCircle : XCircle"
                      :size="14"
                      :class="dataExists ? 'text-emerald-400' : 'text-rose-400'"
                    />
                    <span
                      class="text-sm"
                      :class="dataExists ? 'text-emerald-400' : 'text-rose-400'"
                    >
                      {{ dataExists ? 'Evet' : 'Hayır' }}
                    </span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </TabsContent>

      <!-- Integrations Tab -->
      <TabsContent value="integrations">
        <div class="space-y-4">
          <!-- AbuseIPDB Settings -->
          <Card>
            <CardHeader>
              <CardTitle class="flex items-center gap-2 text-sm">
                <Shield :size="16" class="text-orange-400" />
                AbuseIPDB Tehdit İstihbaratı
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div class="space-y-4">
                <!-- Current Status -->
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Durum</span>
                  <div class="flex items-center gap-2">
                    <component
                      :is="abuseSettings?.api_key_set ? CheckCircle : XCircle"
                      :size="14"
                      :class="abuseSettings?.api_key_set ? 'text-emerald-400' : 'text-rose-400'"
                    />
                    <span
                      class="text-sm font-medium"
                      :class="abuseSettings?.api_key_set ? 'text-emerald-400' : 'text-rose-400'"
                    >
                      {{ abuseSettings?.api_key_set ? 'Aktif' : 'Yapılandırılmamış' }}
                    </span>
                  </div>
                </div>

                <template v-if="abuseSettings?.api_key_set">
                  <Separator />
                  <div class="flex items-center justify-between">
                    <span class="text-sm text-slate-400">API Anahtarı</span>
                    <span class="font-mono text-sm text-slate-300">{{ abuseSettings.api_key_masked }}</span>
                  </div>
                  <div class="flex items-center justify-between">
                    <span class="text-sm text-slate-400">Kaynak</span>
                    <span class="rounded-full bg-white/5 px-2 py-0.5 text-xs text-slate-300">
                      {{ abuseSettings.source === 'env' ? 'Ortam Değişkeni' : abuseSettings.source === 'file' ? 'Dosya' : '-' }}
                    </span>
                  </div>
                  <div class="flex items-center justify-between">
                    <span class="text-sm text-slate-400">Kalan İstek</span>
                    <span class="text-sm text-slate-300">
                      {{ abuseSettings.remaining_calls }} / {{ abuseSettings.daily_limit }}
                    </span>
                  </div>
                  <!-- Usage bar -->
                  <div class="h-1.5 w-full overflow-hidden rounded-full bg-white/5">
                    <div
                      class="h-full rounded-full transition-all"
                      :class="
                        abuseSettings.remaining_calls / abuseSettings.daily_limit > 0.5
                          ? 'bg-emerald-500'
                          : abuseSettings.remaining_calls / abuseSettings.daily_limit > 0.2
                            ? 'bg-amber-500'
                            : 'bg-rose-500'
                      "
                      :style="{ width: `${(abuseSettings.remaining_calls / abuseSettings.daily_limit) * 100}%` }"
                    />
                  </div>
                </template>

                <Separator />

                <!-- API Key Input -->
                <div>
                  <label class="mb-1.5 block text-sm text-slate-400">
                    {{ abuseSettings?.api_key_set ? 'Yeni API Anahtarı' : 'API Anahtarı' }}
                  </label>
                  <div class="flex gap-2">
                    <div class="relative flex-1">
                      <input
                        v-model="abuseApiKey"
                        :type="abuseShowKey ? 'text' : 'password'"
                        placeholder="AbuseIPDB API anahtarınızı girin..."
                        class="w-full rounded-md border border-white/10 bg-white/5 px-3 py-2 pr-10 font-mono text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20"
                      />
                      <button
                        type="button"
                        class="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                        @click="abuseShowKey = !abuseShowKey"
                      >
                        <component :is="abuseShowKey ? EyeOff : Eye" :size="16" />
                      </button>
                    </div>
                  </div>
                </div>

                <!-- Daily Limit -->
                <div>
                  <label class="mb-1.5 block text-sm text-slate-400">Günlük İstek Limiti</label>
                  <div class="flex gap-2">
                    <button
                      v-for="preset in [1000, 10000, 50000]"
                      :key="preset"
                      class="rounded-md px-3 py-1.5 text-xs font-medium transition-colors"
                      :class="
                        abuseDailyLimit === preset
                          ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                          : 'bg-white/5 text-slate-400 border border-white/10 hover:bg-white/10'
                      "
                      @click="abuseDailyLimit = preset"
                    >
                      {{ preset.toLocaleString() }}
                    </button>
                  </div>
                  <p class="mt-1 text-xs text-slate-500">
                    Free: 1.000 / Basic: 10.000 / Premium: 50.000
                  </p>
                </div>

                <!-- Message -->
                <div
                  v-if="abuseMessage"
                  class="rounded-md px-3 py-2 text-sm"
                  :class="
                    abuseMessage.type === 'success'
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                  "
                >
                  {{ abuseMessage.text }}
                </div>

                <!-- Actions -->
                <div class="flex gap-2">
                  <button
                    :disabled="!abuseApiKey || abuseSaving"
                    class="inline-flex items-center gap-1.5 rounded-md bg-cyan-600 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
                    @click="saveAbuseSettings"
                  >
                    <Loader2 v-if="abuseSaving" :size="14" class="animate-spin" />
                    Kaydet
                  </button>
                  <button
                    :disabled="!abuseSettings?.api_key_set || abuseTesting"
                    class="inline-flex items-center gap-1.5 rounded-md bg-white/5 px-3 py-1.5 text-sm font-medium text-slate-300 transition-colors hover:bg-white/10 disabled:cursor-not-allowed disabled:opacity-50"
                    @click="testAbuseConnection"
                  >
                    <Loader2 v-if="abuseTesting" :size="14" class="animate-spin" />
                    Test Et
                  </button>
                  <button
                    v-if="abuseSettings?.api_key_set && abuseSettings?.source !== 'env'"
                    :disabled="abuseClearing"
                    class="inline-flex items-center gap-1.5 rounded-md bg-rose-500/10 px-3 py-1.5 text-sm font-medium text-rose-400 transition-colors hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                    @click="clearAbuseSettings"
                  >
                    <Trash2 :size="14" />
                    Temizle
                  </button>
                </div>

                <p class="text-xs leading-relaxed text-slate-500">
                  API anahtarınızı
                  <a href="https://www.abuseipdb.com/account/api" target="_blank" rel="noopener" class="text-cyan-500 hover:underline">abuseipdb.com</a>
                  adresinden alabilirsiniz. Ortam değişkeni (<code class="text-slate-400">ABUSEIPDB_API_KEY</code>)
                  ayarlanmışsa öncelikli olarak kullanılır.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </TabsContent>

      <!-- Scanner Tab -->
      <TabsContent value="scanner">
        <div class="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle class="flex items-center gap-2 text-sm">
                <Radar :size="16" class="text-cyan-400" />
                Tarayıcı Bilgisi
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div class="space-y-4">
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Tarayıcı Türü</span>
                  <span class="text-sm text-slate-300">Nmap + ARP Taraması</span>
                </div>
                <Separator />
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Hedef Alt Ağ</span>
                  <span class="font-mono text-sm text-slate-300">CLI ile yapılandırılmış</span>
                </div>
                <Separator />
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Tarama Yöntemleri</span>
                  <span class="text-sm text-slate-300">nmap, arp, pasif</span>
                </div>
                <Separator />
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Sınıflandırma</span>
                  <span class="text-sm text-slate-300">BİGR 4-Kategori Sistemi</span>
                </div>
                <Separator />
                <div>
                  <p class="text-sm text-slate-400">Kategoriler</p>
                  <div class="mt-2 grid grid-cols-2 gap-2">
                    <div class="rounded-lg bg-blue-500/10 px-3 py-2 text-xs text-blue-400">
                      Ağ ve Sistemler
                    </div>
                    <div class="rounded-lg bg-purple-500/10 px-3 py-2 text-xs text-purple-400">
                      Uygulamalar
                    </div>
                    <div class="rounded-lg bg-emerald-500/10 px-3 py-2 text-xs text-emerald-400">
                      IoT Cihazları
                    </div>
                    <div class="rounded-lg bg-amber-500/10 px-3 py-2 text-xs text-amber-400">
                      Taşınabilir Cihazlar
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </TabsContent>

      <!-- About Tab -->
      <TabsContent value="about">
        <div class="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle class="flex items-center gap-2 text-sm">
                <Info :size="16" class="text-cyan-400" />
                BİGR Discovery Hakkında
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div class="space-y-4">
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Sürüm</span>
                  <span class="font-mono text-sm text-slate-300">0.1.0</span>
                </div>
                <Separator />
                <div class="flex items-center justify-between">
                  <span class="text-sm text-slate-400">Proje</span>
                  <span class="text-sm text-slate-300">GENESIS v3 - BIGR Discovery</span>
                </div>
                <Separator />
                <div>
                  <p class="text-sm text-slate-400">Açıklama</p>
                  <p class="mt-1 text-sm leading-relaxed text-slate-300">
                    BİGR Discovery, otonom ağ cihaz keşfi ve sınıflandırma ajanıdır.
                    Ağ alt ağlarını tarar, cihazları tanımlar, BİGR 4-kategori sistemine göre
                    sınıflandırır ve zamanla değişiklikleri takip eder.
                  </p>
                </div>
                <Separator />
                <div>
                  <p class="text-sm text-slate-400">Teknoloji Yığını</p>
                  <div class="mt-2 flex flex-wrap gap-2">
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">Python 3.12+</span>
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">FastAPI</span>
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">Vue 3</span>
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">TypeScript</span>
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">Tailwind CSS</span>
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">Chart.js</span>
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">Nmap</span>
                    <span class="rounded-full bg-white/5 px-2.5 py-1 text-xs text-slate-300">Scapy</span>
                  </div>
                </div>
                <Separator />
                <div>
                  <p class="text-sm text-slate-400">Katkıda Bulunanlar</p>
                  <p class="mt-1 text-sm text-slate-300">
                    GENESIS otonom kod kalitesi platformunun bir parçası olarak geliştirilmiştir.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </TabsContent>
    </Tabs>
  </div>
</template>
