<script setup lang="ts">
import { onMounted } from 'vue'
import { useCompliance } from '@/composables/useCompliance'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import LoadingState from '@/components/shared/LoadingState.vue'
import EmptyState from '@/components/shared/EmptyState.vue'
import ComplianceGauge from '@/components/compliance/ComplianceGauge.vue'
import ComplianceBreakdown from '@/components/compliance/ComplianceBreakdown.vue'
import ComplianceDistribution from '@/components/compliance/ComplianceDistribution.vue'
import SubnetComplianceTable from '@/components/compliance/SubnetComplianceTable.vue'
import ActionItemsList from '@/components/compliance/ActionItemsList.vue'

const { data, loading, error, fetchCompliance } = useCompliance()

onMounted(() => {
  fetchCompliance()
})
</script>

<template>
  <div class="space-y-6">
    <h1 class="text-2xl font-bold text-white">BIGR Compliance</h1>

    <LoadingState v-if="loading" message="Loading compliance data..." />

    <div v-else-if="error" class="rounded-lg border border-rose-500/30 bg-rose-500/10 p-4">
      <p class="text-sm text-rose-400">{{ error }}</p>
    </div>

    <EmptyState
      v-else-if="!data"
      title="No Compliance Data"
      description="Run a scan to generate compliance metrics."
    />

    <template v-else>
      <!-- Top row: Gauge + Breakdown -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle class="text-base">Compliance Score</CardTitle>
          </CardHeader>
          <CardContent class="flex justify-center">
            <ComplianceGauge
              :score="data.breakdown.compliance_score"
              :grade="data.breakdown.grade"
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle class="text-base">Classification Breakdown</CardTitle>
          </CardHeader>
          <CardContent>
            <ComplianceBreakdown :breakdown="data.breakdown" />
          </CardContent>
        </Card>
      </div>

      <!-- Middle row: Distribution + Subnet table -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle class="text-base">Category Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <ComplianceDistribution :distribution="data.distribution" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle class="text-base">Subnet Compliance</CardTitle>
          </CardHeader>
          <CardContent>
            <SubnetComplianceTable :subnets="data.subnet_compliance" />
          </CardContent>
        </Card>
      </div>

      <!-- Bottom: Action items -->
      <Card>
        <CardHeader>
          <CardTitle class="text-base">Action Items</CardTitle>
        </CardHeader>
        <CardContent>
          <ActionItemsList :items="data.action_items" />
        </CardContent>
      </Card>
    </template>
  </div>
</template>
