<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { RouterLink } from 'vue-router'
import {
  Clock, Radio, Scan, CheckCircle, XCircle, X,
  Monitor, AlertTriangle, Timer, ArrowRight,
} from 'lucide-vue-next'
import type { CommandStep } from '@/composables/useCommandTracker'

const props = defineProps<{
  steps: CommandStep[]
  progressPercent: number
  isDone: boolean
  targets?: string[]
  shield?: boolean
  result?: Record<string, unknown> | null
  startedAt?: string | null
  completedAt?: string | null
}>()

const emit = defineEmits<{
  dismiss: []
}>()

const STEP_ICONS = [Clock, Radio, Scan, CheckCircle]

function connectorStatus(index: number): 'complete' | 'active' | 'pending' {
  const current = props.steps[index]
  const next = props.steps[index + 1]
  if (!next) return 'pending'
  if (current?.status === 'complete' && (next.status === 'complete' || next.status === 'active')) {
    return 'complete'
  }
  if (current?.status === 'complete' || current?.status === 'active') {
    return 'active'
  }
  return 'pending'
}

const barColor = computed(() => {
  if (props.steps.some(s => s.status === 'failed')) return 'bg-rose-500'
  if (props.isDone) return 'bg-emerald-500'
  return 'bg-cyan-500'
})

const hasFailed = computed(() => props.steps.some(s => s.status === 'failed'))

const duration = computed(() => {
  if (!props.startedAt || !props.completedAt) return null
  const ms = new Date(props.completedAt).getTime() - new Date(props.startedAt).getTime()
  if (ms < 1000) return '<1s'
  const s = Math.round(ms / 1000)
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m ${s % 60}s`
})

const resultErrors = computed(() => {
  if (!props.result?.errors) return []
  return props.result.errors as string[]
})

// Live step message from agent progress updates
const activeStepMessage = computed(() => {
  if (props.isDone || !props.result?.step) return null
  return props.result.step as string
})

// Live elapsed timer
const elapsed = ref('')
let elapsedTimer: ReturnType<typeof setInterval> | null = null

function updateElapsed() {
  if (!props.startedAt || props.isDone) {
    elapsed.value = ''
    return
  }
  const ms = Date.now() - new Date(props.startedAt).getTime()
  const s = Math.floor(ms / 1000)
  if (s < 60) elapsed.value = `${s}s`
  else elapsed.value = `${Math.floor(s / 60)}m ${s % 60}s`
}

onMounted(() => {
  updateElapsed()
  elapsedTimer = setInterval(updateElapsed, 1000)
})

onUnmounted(() => {
  if (elapsedTimer) clearInterval(elapsedTimer)
})
</script>

<template>
  <div class="command-tracker">
    <!-- Progress bar -->
    <div class="progress-bar-track">
      <div
        :class="['progress-bar-fill', barColor]"
        :style="{ width: `${progressPercent}%` }"
      />
    </div>

    <!-- Step timeline -->
    <div class="timeline-track">
      <template v-for="(step, index) in steps" :key="step.name">
        <!-- Step node -->
        <div class="step-node" :class="[step.status]">
          <div class="dot-wrapper">
            <div class="dot" :class="[step.status]">
              <XCircle v-if="step.status === 'failed'" :size="14" />
              <component v-else :is="STEP_ICONS[index] || CheckCircle" :size="14" />
            </div>
            <div v-if="step.status === 'active'" class="pulse-ring" />
          </div>
          <span class="step-label" :class="[step.status]">
            {{ step.name }}
          </span>
        </div>

        <!-- Connector -->
        <div
          v-if="index < steps.length - 1"
          class="connector"
          :class="connectorStatus(index)"
        />
      </template>
    </div>

    <!-- Live activity (while scanning) -->
    <div v-if="!isDone && (activeStepMessage || elapsed)" class="activity-bar">
      <div v-if="activeStepMessage" class="activity-message">
        <div class="activity-dot" />
        {{ activeStepMessage }}
      </div>
      <span v-if="elapsed" class="activity-elapsed">
        <Timer :size="11" />
        {{ elapsed }}
      </span>
    </div>

    <!-- Targets info -->
    <div v-if="targets?.length && !isDone && !activeStepMessage" class="targets-info">
      <span class="targets-label">Hedefler:</span>
      <span class="targets-list">{{ targets.join(', ') }}</span>
      <span v-if="shield" class="shield-badge">Kalkan</span>
    </div>

    <!-- Scan report summary (when done) -->
    <div v-if="isDone && result" class="scan-report">
      <div class="report-header">
        <span :class="hasFailed ? 'text-rose-400' : 'text-emerald-400'" class="report-title">
          {{ hasFailed ? 'Tarama Başarısız' : 'Tarama Tamamlandı' }}
        </span>
        <span v-if="duration" class="report-duration">
          <Timer :size="11" />
          {{ duration }}
        </span>
      </div>
      <div class="report-stats">
        <div class="stat">
          <Monitor :size="14" class="text-cyan-400" />
          <span class="stat-value">{{ result.assets_discovered ?? 0 }}</span>
          <span class="stat-label">cihaz bulundu</span>
        </div>
        <div class="stat">
          <Scan :size="14" class="text-slate-400" />
          <span class="stat-value">{{ result.targets_scanned ?? 0 }}</span>
          <span class="stat-label">alt ağ tarandı</span>
        </div>
      </div>
      <!-- Navigate to assets -->
      <RouterLink
        v-if="!hasFailed && Number(result.assets_discovered ?? 0) > 0"
        to="/assets"
        class="view-assets-link"
      >
        Cihazları Görüntüle
        <ArrowRight :size="13" />
      </RouterLink>
      <div v-if="resultErrors.length" class="report-errors">
        <div class="error-header">
          <AlertTriangle :size="12" />
          {{ resultErrors.length }} uyarı
        </div>
        <div v-for="(err, i) in resultErrors" :key="i" class="error-line">
          {{ err }}
        </div>
      </div>
    </div>

    <!-- Dismiss button (when done) -->
    <button
      v-if="isDone"
      class="dismiss-btn"
      @click="emit('dismiss')"
    >
      <X :size="12" />
      Kapat
    </button>
  </div>
</template>

<style scoped>
.command-tracker {
  padding: 12px 16px;
  background: rgba(15, 23, 42, 0.8);
  border: 1px solid rgba(100, 116, 139, 0.2);
  border-radius: 12px;
  position: relative;
}

/* --- Progress Bar --- */
.progress-bar-track {
  height: 3px;
  background: rgba(100, 116, 139, 0.15);
  border-radius: 2px;
  margin-bottom: 14px;
  overflow: hidden;
}

.progress-bar-fill {
  height: 100%;
  border-radius: 2px;
  transition: width 0.6s ease;
}

/* --- Timeline --- */
.timeline-track {
  display: flex;
  align-items: flex-start;
  justify-content: center;
  gap: 0;
}

.step-node {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 5px;
  min-width: 72px;
  position: relative;
}

.dot-wrapper {
  position: relative;
  width: 28px;
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.dot {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 2px solid rgba(100, 116, 139, 0.3);
  background: rgba(15, 23, 42, 0.9);
  color: rgba(100, 116, 139, 0.4);
  transition: all 0.3s ease;
  position: relative;
  z-index: 2;
}

.dot.pending {
  border-color: rgba(100, 116, 139, 0.3);
  color: rgba(100, 116, 139, 0.4);
}

.dot.active {
  border-color: #22d3ee;
  background: rgba(34, 211, 238, 0.1);
  color: #22d3ee;
}

.dot.complete {
  border-color: #34d399;
  background: rgba(52, 211, 153, 0.1);
  color: #34d399;
}

.dot.failed {
  border-color: #f87171;
  background: rgba(248, 113, 113, 0.1);
  color: #f87171;
}

/* --- Pulse --- */
.pulse-ring {
  position: absolute;
  top: 50%;
  left: 50%;
  width: 28px;
  height: 28px;
  transform: translate(-50%, -50%);
  border-radius: 50%;
  border: 2px solid #22d3ee;
  animation: pulse 2s ease-out infinite;
  z-index: 1;
}

@keyframes pulse {
  0% { transform: translate(-50%, -50%) scale(1); opacity: 0.5; }
  70% { transform: translate(-50%, -50%) scale(1.7); opacity: 0; }
  100% { transform: translate(-50%, -50%) scale(1.7); opacity: 0; }
}

/* --- Label --- */
.step-label {
  font-size: 10px;
  font-weight: 500;
  color: rgba(100, 116, 139, 0.5);
  text-align: center;
  white-space: nowrap;
  transition: color 0.3s;
}

.step-label.active { color: #22d3ee; }
.step-label.complete { color: #34d399; }
.step-label.failed { color: #f87171; }

/* --- Connector --- */
.connector {
  flex-shrink: 0;
  width: 32px;
  height: 2px;
  margin-top: 14px;
  background: rgba(100, 116, 139, 0.2);
  transition: background 0.3s;
}

.connector.complete { background: #34d399; }
.connector.active { background: linear-gradient(90deg, #34d399, #22d3ee); }

/* --- Targets --- */
.targets-info {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 10px;
  padding-top: 10px;
  border-top: 1px solid rgba(100, 116, 139, 0.1);
  font-size: 11px;
}

.targets-label { color: rgba(148, 163, 184, 0.6); }
.targets-list { color: rgba(148, 163, 184, 0.8); }

.shield-badge {
  background: rgba(34, 211, 238, 0.12);
  color: #22d3ee;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
}

/* --- Activity Bar --- */
.activity-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-top: 10px;
  padding: 8px 10px;
  background: rgba(34, 211, 238, 0.04);
  border: 1px solid rgba(34, 211, 238, 0.1);
  border-radius: 8px;
}

.activity-message {
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 11px;
  color: #22d3ee;
  font-weight: 500;
}

.activity-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #22d3ee;
  animation: blink 1.2s ease-in-out infinite;
  flex-shrink: 0;
}

@keyframes blink {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}

.activity-elapsed {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  color: rgba(148, 163, 184, 0.5);
  font-variant-numeric: tabular-nums;
}

/* --- Scan Report --- */
.scan-report {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid rgba(100, 116, 139, 0.15);
}

.report-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}

.report-title {
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.02em;
}

.report-duration {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  color: rgba(148, 163, 184, 0.6);
}

.report-stats {
  display: flex;
  gap: 16px;
  margin-bottom: 8px;
}

.stat {
  display: flex;
  align-items: center;
  gap: 6px;
}

.stat-value {
  font-size: 18px;
  font-weight: 700;
  color: #e2e8f0;
  line-height: 1;
}

.stat-label {
  font-size: 10px;
  color: rgba(148, 163, 184, 0.5);
}

.view-assets-link {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  margin-top: 4px;
  padding: 4px 10px;
  font-size: 11px;
  font-weight: 600;
  color: #22d3ee;
  background: rgba(34, 211, 238, 0.08);
  border: 1px solid rgba(34, 211, 238, 0.2);
  border-radius: 6px;
  text-decoration: none;
  transition: all 0.2s;
}

.view-assets-link:hover {
  background: rgba(34, 211, 238, 0.15);
  border-color: rgba(34, 211, 238, 0.4);
}

.report-errors {
  margin-top: 8px;
  padding: 8px 10px;
  background: rgba(248, 113, 113, 0.06);
  border: 1px solid rgba(248, 113, 113, 0.15);
  border-radius: 8px;
}

.error-header {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 11px;
  font-weight: 600;
  color: #fca5a5;
  margin-bottom: 4px;
}

.error-line {
  font-size: 10px;
  color: rgba(248, 113, 113, 0.7);
  line-height: 1.4;
  word-break: break-all;
}

/* --- Dismiss --- */
.dismiss-btn {
  position: absolute;
  top: 8px;
  right: 8px;
  display: flex;
  align-items: center;
  gap: 3px;
  padding: 2px 8px;
  border-radius: 6px;
  font-size: 10px;
  color: rgba(148, 163, 184, 0.6);
  background: transparent;
  border: none;
  cursor: pointer;
  transition: color 0.2s;
}

.dismiss-btn:hover { color: rgba(148, 163, 184, 1); }
</style>
