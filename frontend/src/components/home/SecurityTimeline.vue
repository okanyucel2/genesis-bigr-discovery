<script setup lang="ts">
import { computed } from 'vue'
import { useTimeline } from '@/composables/useTimeline'
import TimelineItemComp from '@/components/home/TimelineItem.vue'
import type {
  FirewallEvent,
  FamilyTimelineEntry,
  AssetChange,
  CollectiveSignalReport,
} from '@/types/api'
import type { ShieldStatus } from '@/types/home-dashboard'

const props = defineProps<{
  firewallEvents: FirewallEvent[]
  familyTimeline: FamilyTimelineEntry[]
  changes: AssetChange[]
  collectiveThreats?: CollectiveSignalReport[]
  deviceLookup?: Record<string, string>
  localIp?: string | null
  shieldStatus?: ShieldStatus
}>()

const { visibleCount, buildTimeline, toggleExpand, isExpanded, showMore } = useTimeline()

const allItems = computed(() =>
  buildTimeline(
    props.firewallEvents,
    props.familyTimeline,
    props.changes,
    props.collectiveThreats ?? [],
    props.deviceLookup ?? {},
    props.localIp ?? null,
    props.shieldStatus,
  ),
)

const visibleItems = computed(() => allItems.value.slice(0, visibleCount.value))
const hasMore = computed(() => allItems.value.length > visibleCount.value)
</script>

<template>
  <div class="security-timeline">
    <h3 class="mb-4 text-sm font-semibold text-slate-300">Zaman Cizelgesi</h3>

    <div v-if="allItems.length === 0" class="py-8 text-center text-sm text-slate-500">
      Henuz olay yok
    </div>

    <div v-else class="space-y-2">
      <TimelineItemComp
        v-for="item in visibleItems"
        :key="item.id"
        :item="item"
        :expanded="isExpanded(item.id)"
        @toggle="toggleExpand(item.id)"
      />

      <button
        v-if="hasMore"
        class="mt-3 w-full rounded-lg bg-white/5 py-2 text-xs text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-300"
        @click="showMore"
      >
        Daha fazla goster ({{ allItems.length - visibleCount }} kaldi)
      </button>
    </div>
  </div>
</template>
