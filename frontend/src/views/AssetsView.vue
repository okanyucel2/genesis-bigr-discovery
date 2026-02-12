<script setup lang="ts">
import { onMounted, watch } from 'vue'
import { useAssetsStore } from '@/stores/assets'
import { useUiStore } from '@/stores/ui'
import AssetFilters from '@/components/assets/AssetFilters.vue'
import AssetTable from '@/components/assets/AssetTable.vue'
import LoadingState from '@/components/shared/LoadingState.vue'

const store = useAssetsStore()
const ui = useUiStore()

watch(() => ui.selectedNetwork, () => {
  store.fetchAssets(undefined, undefined, ui.selectedNetwork ?? undefined)
})

onMounted(() => {
  if (store.assets.length === 0) {
    store.fetchAssets(undefined, undefined, ui.selectedNetwork ?? undefined)
  }
})
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-bold text-white">Cihazlar</h1>
      <p class="mt-1 text-sm text-muted-foreground">
        BİGR sınıflandırmalı ağ cihazları
      </p>
    </div>

    <AssetFilters />

    <div class="glass-card rounded-lg border border-border/50 p-1">
      <LoadingState
        v-if="store.loading"
        message="Cihazlar keşfediliyor..."
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
          Tekrar Dene
        </button>
      </div>

      <template v-else>
        <div class="flex items-center justify-between px-4 py-3">
          <p class="text-sm text-muted-foreground">
            Gösteriliyor
            <span class="font-medium text-foreground">
              {{ store.filteredAssets.length }}
            </span>
            /
            <span class="font-medium text-foreground">
              {{ store.totalAssets }}
            </span>
            cihaz
          </p>
        </div>

        <AssetTable :assets="store.filteredAssets" />
      </template>
    </div>
  </div>
</template>
