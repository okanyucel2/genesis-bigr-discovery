<script setup lang="ts">
import { computed } from 'vue'
import { relativeTime } from '@/lib/time-utils'
import type { TimelineItem, TimelineRichDetail, TimelineDetailAction } from '@/types/home-dashboard'
import { isRichDetail } from '@/types/home-dashboard'

const props = defineProps<{
  item: TimelineItem
  expanded: boolean
}>()

const emit = defineEmits<{
  toggle: []
  blockIp: [ip: string]
  viewRule: [ruleId: string]
  shieldBlock: [ip: string, method?: string]
  setupShield: []
}>()

const severityClass = computed(() => {
  switch (props.item.severity) {
    case 'critical':
      return 'border-l-rose-500 bg-rose-500/5'
    case 'high':
      return 'border-l-amber-500 bg-amber-500/5'
    case 'medium':
      return 'border-l-yellow-500 bg-yellow-500/5'
    case 'low':
      return 'border-l-blue-500 bg-blue-500/5'
    default:
      return 'border-l-slate-600 bg-white/[0.02]'
  }
})

const timeText = computed(() => relativeTime(props.item.timestamp))

const richDetail = computed<TimelineRichDetail | null>(() => {
  return isRichDetail(props.item.detail) ? props.item.detail : null
})

const stringDetail = computed<string | null>(() => {
  return typeof props.item.detail === 'string' ? props.item.detail : null
})

function handleAction(action: TimelineDetailAction) {
  if (action.handler === 'block-permanent' && action.metadata?.ip) {
    emit('blockIp', action.metadata.ip)
  } else if (action.handler === 'view-rule' && action.metadata?.ruleId) {
    emit('viewRule', action.metadata.ruleId)
  } else if (action.handler === 'shield-block' && action.metadata?.ip) {
    emit('shieldBlock', action.metadata.ip, action.metadata.method)
  } else if (action.handler === 'setup-shield') {
    emit('setupShield')
  }
}

const actionVariantClass: Record<string, string> = {
  danger: 'bg-rose-500/20 text-rose-300 hover:bg-rose-500/30',
  secondary: 'bg-slate-500/20 text-slate-300 hover:bg-slate-500/30',
  primary: 'bg-cyan-500/20 text-cyan-300 hover:bg-cyan-500/30',
}

const ruleBannerVariantClass: Record<string, string> = {
  red: 'bg-rose-500/15 border-rose-500/30 text-rose-300',
  purple: 'bg-purple-500/15 border-purple-500/30 text-purple-300',
  blue: 'bg-blue-500/15 border-blue-500/30 text-blue-300',
  orange: 'bg-amber-500/15 border-amber-500/30 text-amber-300',
}

const directActions = computed(() =>
  richDetail.value?.actions.filter((a) => !a.suggested) ?? [],
)

const suggestedActions = computed(() =>
  richDetail.value?.actions.filter((a) => a.suggested) ?? [],
)

const suggestedVariantClass: Record<string, string> = {
  danger: 'border-rose-500/30 text-rose-400/70 hover:bg-rose-500/10',
  secondary: 'border-slate-500/30 text-slate-400/70 hover:bg-slate-500/10',
  primary: 'border-cyan-500/30 text-cyan-400/70 hover:bg-cyan-500/10',
}

const showRuleBanner = computed(() => {
  if (!richDetail.value?.ruleContext) return false
  // Don't show rule banner if threat banner is already shown (threat takes priority)
  if (richDetail.value.threatContext?.isKnownMalicious) return false
  if (richDetail.value.threatContext?.reputation === 'suspicious') return false
  return true
})
</script>

<template>
  <div
    class="timeline-item cursor-pointer rounded-lg border-l-2 px-4 py-3 transition-all duration-200 hover:bg-white/5"
    :class="severityClass"
    @click="$emit('toggle')"
  >
    <div class="flex items-start gap-3">
      <span class="mt-0.5 text-base leading-none">{{ item.icon }}</span>
      <div class="min-w-0 flex-1">
        <p class="text-sm text-slate-200">{{ item.message }}</p>
        <p class="mt-1 text-[10px] text-slate-500">{{ timeText }}</p>
      </div>
      <button
        v-if="item.detail"
        class="shrink-0 text-[10px] text-cyan-400 transition-colors hover:text-cyan-300"
        @click.stop="$emit('toggle')"
      >
        {{ expanded ? 'Gizle' : 'Detay' }}
      </button>
    </div>

    <!-- Expanded detail -->
    <Transition name="expand">
      <div v-if="expanded && item.detail" class="mt-2">
        <!-- Rich detail (firewall) -->
        <div v-if="richDetail" class="space-y-2">
          <!-- Threat banner -->
          <div
            v-if="richDetail.threatContext?.isKnownMalicious"
            class="threat-banner flex items-center gap-2 rounded-md bg-rose-500/15 border border-rose-500/30 px-3 py-1.5"
          >
            <span class="text-sm">⚠️</span>
            <span class="text-xs font-medium text-rose-300">
              Bilinen Tehdit — {{ richDetail.threatContext.threatType }}
            </span>
          </div>

          <!-- Suspicious banner -->
          <div
            v-else-if="richDetail.threatContext?.reputation === 'suspicious'"
            class="threat-banner flex items-center gap-2 rounded-md bg-amber-500/15 border border-amber-500/30 px-3 py-1.5"
          >
            <span class="text-sm">⚠️</span>
            <span class="text-xs font-medium text-amber-300">
              Suphelendi — {{ richDetail.threatContext.threatType }}
            </span>
          </div>

          <!-- Rule context banner (when no threat banner) -->
          <div
            v-else-if="showRuleBanner && richDetail.ruleContext"
            class="rule-banner flex items-center gap-2 rounded-md border px-3 py-1.5"
            :class="ruleBannerVariantClass[richDetail.ruleContext.bannerVariant]"
          >
            <span class="text-sm">{{ richDetail.ruleContext.category === 'ad' ? '🛑' : 'ℹ️' }}</span>
            <div class="min-w-0">
              <span class="text-xs font-medium">{{ richDetail.ruleContext.label }}</span>
              <span class="text-xs opacity-75"> — {{ richDetail.ruleContext.reason }}</span>
            </div>
          </div>

          <!-- Summary -->
          <div class="rich-summary rounded-md bg-black/20 px-3 py-2">
            <p class="text-xs text-slate-300">{{ richDetail.summary }}</p>
          </div>

          <!-- Fields grid -->
          <div class="detail-fields grid grid-cols-2 gap-2">
            <div
              v-for="field in richDetail.fields"
              :key="field.label"
              class="rounded-md bg-black/15 px-3 py-1.5"
            >
              <div class="flex items-center gap-1.5">
                <span class="text-xs">{{ field.icon }}</span>
                <span class="text-[10px] text-slate-500">{{ field.label }}</span>
              </div>
              <p class="mt-0.5 text-xs font-medium text-slate-300">{{ field.value }}</p>
            </div>
          </div>

          <!-- Direct actions -->
          <div v-if="directActions.length > 0" class="detail-actions flex flex-wrap gap-2">
            <button
              v-for="action in directActions"
              :key="action.label"
              class="inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors"
              :class="actionVariantClass[action.variant]"
              @click.stop="handleAction(action)"
            >
              <span v-if="action.icon" class="text-xs">{{ action.icon }}</span>
              {{ action.label }}
            </button>
          </div>

          <!-- Suggested actions -->
          <div v-if="suggestedActions.length > 0" class="suggested-actions space-y-1.5">
            <p class="text-[10px] font-medium uppercase tracking-wider text-slate-500">Onerilen</p>
            <div class="flex flex-wrap gap-2">
              <button
                v-for="action in suggestedActions"
                :key="action.label"
                class="group inline-flex items-center gap-1.5 rounded-md border border-dashed px-3 py-1.5 text-xs transition-colors"
                :class="suggestedVariantClass[action.variant]"
                :title="action.suggestReason"
                @click.stop="handleAction(action)"
              >
                <span v-if="action.icon" class="text-xs opacity-70">{{ action.icon }}</span>
                <span>{{ action.label }}</span>
                <span class="text-[10px] opacity-50">💡</span>
              </button>
            </div>
            <p v-if="suggestedActions[0]?.suggestReason" class="text-[10px] text-slate-500 italic">
              {{ suggestedActions[0].suggestReason }}
            </p>
          </div>
        </div>

        <!-- String detail (fallback) -->
        <div v-else-if="stringDetail" class="rounded-md bg-black/20 px-3 py-2">
          <p class="text-xs text-slate-400 font-mono">{{ stringDetail }}</p>
        </div>
      </div>
    </Transition>
  </div>
</template>

<style scoped>
.expand-enter-active,
.expand-leave-active {
  transition: all 0.2s ease;
  overflow: hidden;
}
.expand-enter-from,
.expand-leave-to {
  opacity: 0;
  max-height: 0;
}
.expand-enter-to,
.expand-leave-from {
  opacity: 1;
  max-height: 400px;
}
</style>
