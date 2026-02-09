<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useAssetsStore } from '@/stores/assets'
import { BIGR_CATEGORIES, BIGR_CATEGORY_LIST } from '@/types/bigr'
import type { BigrCategory } from '@/types/bigr'
import { useSubnets } from '@/composables/useSubnets'
import SearchInput from '@/components/shared/SearchInput.vue'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { X } from 'lucide-vue-next'

const store = useAssetsStore()
const { subnets, fetchSubnets } = useSubnets()

onMounted(() => {
  fetchSubnets()
})

function handleSearchUpdate(value: string) {
  store.setSearchQuery(value)
}

function handleCategoryChange(e: Event) {
  const val = (e.target as HTMLSelectElement).value
  store.setCategory(val ? (val as BigrCategory) : null)
}

function handleSubnetChange(e: Event) {
  const val = (e.target as HTMLSelectElement).value
  store.setSubnet(val || null)
  store.fetchAssets(val || undefined)
}

function clearFilters() {
  store.setCategory(null)
  store.setSearchQuery('')
  store.setSubnet(null)
  store.fetchAssets()
}

const activeFilterCount = computed(() => {
  let count = 0
  if (store.selectedCategory !== null) count++
  if (store.searchQuery !== '') count++
  if (store.selectedSubnet !== null) count++
  return count
})

const hasActiveFilters = computed(() => activeFilterCount.value > 0)
</script>

<template>
  <div class="flex flex-wrap items-center gap-3">
    <SearchInput
      :model-value="store.searchQuery"
      placeholder="Search by IP, hostname, vendor, MAC..."
      class="w-64"
      @update:model-value="handleSearchUpdate"
    />

    <select
      :value="store.selectedCategory ?? ''"
      class="h-10 rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
      @change="handleCategoryChange"
    >
      <option value="">All Categories</option>
      <option
        v-for="cat in BIGR_CATEGORY_LIST"
        :key="cat"
        :value="cat"
      >
        {{ BIGR_CATEGORIES[cat].label }}
      </option>
    </select>

    <select
      :value="store.selectedSubnet ?? ''"
      class="h-10 rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
      @change="handleSubnetChange"
    >
      <option value="">All Subnets</option>
      <option
        v-for="subnet in subnets"
        :key="subnet.id"
        :value="subnet.cidr"
      >
        {{ subnet.cidr }}{{ subnet.label ? ` (${subnet.label})` : '' }}
      </option>
    </select>

    <div v-if="hasActiveFilters" class="flex items-center gap-2">
      <Badge variant="secondary" class="gap-1">
        {{ activeFilterCount }} active
      </Badge>
      <Button
        variant="ghost"
        size="sm"
        class="h-8 gap-1 text-muted-foreground hover:text-foreground"
        @click="clearFilters"
      >
        <X :size="14" />
        Clear
      </Button>
    </div>
  </div>
</template>
