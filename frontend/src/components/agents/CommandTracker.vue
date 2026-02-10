<script setup lang="ts">
import { computed } from 'vue'
import {
  Clock, Radio, Scan, CheckCircle, XCircle, X,
} from 'lucide-vue-next'
import type { CommandStep } from '@/composables/useCommandTracker'

const props = defineProps<{
  steps: CommandStep[]
  progressPercent: number
  isDone: boolean
  targets?: string[]
  shield?: boolean
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

    <!-- Targets info -->
    <div v-if="targets?.length" class="targets-info">
      <span class="targets-label">Targets:</span>
      <span class="targets-list">{{ targets.join(', ') }}</span>
      <span v-if="shield" class="shield-badge">Shield</span>
    </div>

    <!-- Dismiss button (when done) -->
    <button
      v-if="isDone"
      class="dismiss-btn"
      @click="emit('dismiss')"
    >
      <X :size="12" />
      Dismiss
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
