<script setup lang="ts">
import { ref, computed, onMounted, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { useOnboardingStore } from '@/stores/onboarding'
import { guessDeviceFromVendor } from '@/lib/device-icons'
import ChatBubble from './ChatBubble.vue'
import DeviceDiscoveryAnimation from './DeviceDiscoveryAnimation.vue'

interface ChatMessage {
  id: string
  sender: 'bigr' | 'user'
  text: string
  options?: { label: string; value: string }[]
}

const router = useRouter()
const store = useOnboardingStore()

const chatPhase = ref<'scanning' | 'identifying' | 'complete'>('scanning')
const messages = ref<ChatMessage[]>([])
const chatContainer = ref<HTMLElement | null>(null)

interface DiscoveredDevice { type: string; name: string; vendor: string | null; model: string | null }

const MAX_ASK_DEVICES = 3

const allDevices = ref<DiscoveredDevice[]>([])
const notableDevices = ref<DiscoveredDevice[]>([])
const currentDeviceIdx = ref(0)
const identifiedCount = ref(0)

const currentDevice = computed(() => notableDevices.value[currentDeviceIdx.value] ?? null)
const remainingCount = computed(() => Math.max(0, allDevices.value.length - notableDevices.value.length))
const animDevices = computed(() =>
  allDevices.value.map((d) => ({ type: d.type, name: d.name })),
)

function addMessage(msg: Omit<ChatMessage, 'id'>) {
  messages.value.push({ ...msg, id: `msg_${Date.now()}_${Math.random()}` })
  nextTick(() => {
    chatContainer.value?.scrollTo({ top: chatContainer.value.scrollHeight, behavior: 'smooth' })
  })
}

async function startScanning() {
  addMessage({ sender: 'bigr', text: 'Merhaba! Evinizi taniyorum... 🏠' })

  // Start the actual scan
  await store.startScan()

  // Simulate discovered devices with human-friendly names (each unique)
  const mockDeviceProfiles: { vendor: string | null; hostname: string | null; model: string | null }[] = [
    { vendor: 'Apple', hostname: 'Okan\'in iPhone\'u', model: 'iPhone 15 Pro' },
    { vendor: 'Samsung', hostname: null, model: 'Galaxy Smart TV 55"' },
    { vendor: 'Apple', hostname: 'MacBook Pro', model: 'MacBook Pro M3' },
    { vendor: 'TP-Link', hostname: null, model: 'Archer AX73' },
    { vendor: 'Apple', hostname: 'iPad', model: 'iPad Air' },
    { vendor: 'Samsung', hostname: null, model: 'Galaxy S24' },
    { vendor: 'LG', hostname: null, model: 'Yatak Odasi TV' },
    { vendor: null, hostname: null, model: null },
  ]

  const deviceCount = store.networkInfo ? Math.max(store.networkInfo.device_count, 4) : 4
  // Build unique device list — never cycle/repeat profiles
  const devices: DiscoveredDevice[] = Array.from({ length: deviceCount }, (_, i) => {
    const profile = i < mockDeviceProfiles.length
      ? mockDeviceProfiles[i]!
      : { vendor: null, hostname: null, model: null }
    const guess = guessDeviceFromVendor(profile.vendor)
    const displayName = profile.hostname ?? profile.model ?? guess.label
    return { type: guess.type, name: displayName, vendor: profile.vendor, model: profile.model }
  })

  allDevices.value = devices

  // Pick notable devices to ask about: ones with a known vendor/hostname (max MAX_ASK_DEVICES)
  const notable = devices.filter((d) => d.vendor !== null).slice(0, MAX_ASK_DEVICES)
  notableDevices.value = notable

  setTimeout(() => {
    const count = devices.length
    addMessage({
      sender: 'bigr',
      text: `${count} cihaz buldum! En onemli ${notable.length} tanesini sana soracagim.`,
    })

    chatPhase.value = 'identifying'
    askAboutNextDevice()
  }, 2000)
}

function askAboutNextDevice() {
  const device = currentDevice.value
  if (!device) {
    finishIdentification()
    return
  }

  addMessage({
    sender: 'bigr',
    text: `Agda bir ${device.vendor ?? ''} cihaz goruyorum: "${device.name}". Bu kimin?`,
    options: [
      { label: 'Benim', value: 'mine' },
      { label: 'Ailemin', value: 'known' },
      { label: 'Tanimiyorum', value: 'unknown' },
    ],
  })
}

function handleDeviceResponse(value: string) {
  const device = currentDevice.value
  if (!device) return

  switch (value) {
    case 'known':
      addMessage({ sender: 'user', text: `Ailemin cihazi` })
      addMessage({ sender: 'bigr', text: `Tamam, "${device.name}" aile cihazi olarak kaydedildi. ✅` })
      identifiedCount.value++
      break
    case 'mine':
      addMessage({ sender: 'user', text: 'Benim cihazim' })
      addMessage({ sender: 'bigr', text: `Harika, "${device.name}" senin cihazin olarak kaydedildi. ✅` })
      identifiedCount.value++
      break
    case 'unknown':
      addMessage({ sender: 'user', text: 'Tanimiyorum' })
      addMessage({ sender: 'bigr', text: 'Sorun degil, bu cihazi yakindan izleyecegim. 👀' })
      break
  }

  currentDeviceIdx.value++
  setTimeout(() => askAboutNextDevice(), 500)
}

function finishIdentification() {
  chatPhase.value = 'complete'
  const total = allDevices.value.length
  const score = Math.round(store.safetyScore * 100)

  addMessage({
    sender: 'bigr',
    text: `Harika! ${identifiedCount.value} cihaz tanimlandi. Guvenlik skorunuz: ${score}. Aileniz koruma altinda! 🛡️`,
  })

  if (remainingCount.value > 0) {
    addMessage({
      sender: 'bigr',
      text: `Geri kalan ${remainingCount.value} cihazi dashboard'dan toplu tanimlayabilirsin. Simdilik hepsini izliyorum. 👀`,
    })
  }

  addMessage({
    sender: 'bigr',
    text: 'Dashboard\'a gitmek ister misin?',
    options: [
      { label: 'Basla!', value: 'dashboard' },
    ],
  })
}

function handleComplete(value: string) {
  if (value === 'dashboard') {
    store.completeOnboarding()
    router.push('/')
  }
}

function handleOptionClick(msg: ChatMessage, value: string) {
  if (chatPhase.value === 'identifying') {
    handleDeviceResponse(value)
  } else if (chatPhase.value === 'complete') {
    handleComplete(value)
  }
  // Remove options from this message after selection
  const found = messages.value.find((m) => m.id === msg.id)
  if (found) found.options = undefined
}

onMounted(() => {
  startScanning()
})
</script>

<template>
  <div class="chat-onboarding flex flex-col items-center min-h-[70vh] px-4 py-6 max-w-lg mx-auto">
    <!-- Discovery animation (scanning phase) -->
    <DeviceDiscoveryAnimation
      v-if="chatPhase === 'scanning'"
      :devices="animDevices"
    />

    <!-- Chat messages -->
    <div
      ref="chatContainer"
      class="chat-messages w-full flex-1 space-y-3 overflow-y-auto pr-1"
      :class="chatPhase !== 'scanning' ? 'mt-4' : ''"
    >
      <template v-for="msg in messages" :key="msg.id">
        <ChatBubble :sender="msg.sender" :message="msg.text" :animated="true" />

        <!-- Quick reply buttons -->
        <div v-if="msg.options" class="flex flex-wrap gap-2" :class="msg.sender === 'bigr' ? 'ml-2' : 'mr-2 justify-end'">
          <button
            v-for="opt in msg.options"
            :key="opt.value"
            class="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-4 py-1.5 text-xs font-medium text-cyan-300 transition-all hover:bg-cyan-500/20"
            @click="handleOptionClick(msg, opt.value)"
          >
            {{ opt.label }}
          </button>
        </div>
      </template>
    </div>

    <!-- Phase indicator -->
    <div class="mt-4 flex items-center gap-3 text-[10px] text-slate-500">
      <span
        class="h-1.5 w-1.5 rounded-full"
        :class="chatPhase === 'scanning' ? 'bg-cyan-400 animate-pulse' : 'bg-emerald-400'"
      />
      <span>{{ chatPhase === 'scanning' ? 'Taraniyor...' : chatPhase === 'identifying' ? 'Cihazlar tanimlaniyor' : 'Tamamlandi!' }}</span>
    </div>
  </div>
</template>
