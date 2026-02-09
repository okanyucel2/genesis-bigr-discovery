<script setup lang="ts">
import { onMounted } from 'vue'
import { useAssetsStore } from '@/stores/assets'
import AssetFilters from '@/components/assets/AssetFilters.vue'
import AssetTable from '@/components/assets/AssetTable.vue'
import LoadingState from '@/components/shared/LoadingState.vue'

const store = useAssetsStore()

onMounted(() => {
  if (store.assets.length === 0) {
    store.fetchAssets()
  }
})
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-bold text-white">Assets</h1>
      <p class="mt-1 text-sm text-muted-foreground">
        Discovered network assets with BİGR classification
      </p>
    </div>

    <AssetFilters />

    <div class="glass-card rounded-lg border border-border/50 p-1">
      <LoadingState
        v-if="store.loading"
        message="Discovering assets..."
      />

      <div
        v-else-if="store.error"
        class="flex flex-col items-center justify-center py-12 text-center"
      >
        <p class="text-sm text-destructive">{{ store.error }}</p>
        <button
          class="mt-3 text-sm text-primary hover:underline"
          @click="store.fetchAssets()"
        >
          Try again
        </button>
      </div>

      <template v-else>
        <div class="flex items-center justify-between px-4 py-3">
          <p class="text-sm text-muted-foreground">
            Showing
            <span class="font-medium text-foreground">
              {{ store.filteredAssets.length }}
            </span>
            of
            <span class="font-medium text-foreground">
              {{ store.totalAssets }}
            </span>
            assets
          </p>
        </div>

        <AssetTable :assets="store.filteredAssets" />
      </template>
    </div>
  </div>
</template>
