<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, watch, nextTick } from 'vue'
import * as d3 from 'd3'
import { RotateCcw } from 'lucide-vue-next'
import type { TopologyNode, TopologyEdge } from '@/types/api'

const props = defineProps<{
  nodes: TopologyNode[]
  edges: TopologyEdge[]
}>()

const emit = defineEmits<{
  'node-click': [node: TopologyNode]
}>()

const svgRef = ref<SVGSVGElement | null>(null)

// Tooltip reactive state
const tooltipVisible = ref(false)
const tooltipX = ref(0)
const tooltipY = ref(0)
const tooltipNode = ref<TopologyNode | null>(null)

const tooltipPorts = ref('')

// D3 refs kept outside Vue reactivity for performance
let svg: d3.Selection<SVGSVGElement, unknown, null, undefined>
let container: d3.Selection<SVGGElement, unknown, null, undefined>
let simulation: d3.Simulation<d3.SimulationNodeDatum, undefined>
let zoomBehavior: d3.ZoomBehavior<SVGSVGElement, unknown>

interface SimNode extends d3.SimulationNodeDatum, TopologyNode {}
interface SimEdge {
  source: SimNode | string
  target: SimNode | string
  type: string
  label: string | null
}

function getNodeShape(type: string): string {
  switch (type) {
    case 'gateway':
      return 'diamond'
    case 'switch':
      return 'square'
    default:
      return 'circle'
  }
}

function drawNodeShape(
  sel: d3.Selection<SVGGElement, SimNode, SVGGElement, unknown>,
) {
  // Remove existing shapes
  sel.selectAll('.node-shape').remove()

  sel.each(function (d) {
    const g = d3.select(this)
    const shape = getNodeShape(d.type)
    const size = d.size

    if (shape === 'diamond') {
      const half = size
      g.append('polygon')
        .attr('class', 'node-shape')
        .attr('points', `0,${-half} ${half},0 0,${half} ${-half},0`)
        .attr('fill', d.color)
        .attr('fill-opacity', 0.25)
        .attr('stroke', d.color)
        .attr('stroke-width', 2)
    } else if (shape === 'square') {
      const half = size * 0.8
      g.append('rect')
        .attr('class', 'node-shape')
        .attr('x', -half)
        .attr('y', -half)
        .attr('width', half * 2)
        .attr('height', half * 2)
        .attr('rx', 3)
        .attr('fill', d.color)
        .attr('fill-opacity', 0.25)
        .attr('stroke', d.color)
        .attr('stroke-width', 2)
    } else {
      g.append('circle')
        .attr('class', 'node-shape')
        .attr('r', size)
        .attr('fill', d.color)
        .attr('fill-opacity', 0.25)
        .attr('stroke', d.color)
        .attr('stroke-width', 2)
    }
  })
}

function getEdgeColor(type: string): string {
  switch (type) {
    case 'gateway':
      return '#22d3ee' // cyan-400
    case 'switch':
      return '#94a3b8' // slate-400
    default:
      return '#475569' // slate-600
  }
}

function getEdgeDash(type: string): string {
  return type === 'subnet' ? '6,3' : 'none'
}

function showTooltip(event: MouseEvent, d: SimNode) {
  tooltipNode.value = d
  tooltipPorts.value = d.open_ports.length > 0 ? d.open_ports.join(', ') : 'None'
  tooltipX.value = event.offsetX + 12
  tooltipY.value = event.offsetY - 12
  tooltipVisible.value = true
}

function hideTooltip() {
  tooltipVisible.value = false
  tooltipNode.value = null
}

function highlightConnected(nodeId: string, active: boolean) {
  if (!container) return

  if (active) {
    const connectedIds = new Set<string>()
    connectedIds.add(nodeId)

    container.selectAll<SVGLineElement, SimEdge>('.edge-line').each(function (d) {
      const sourceId = typeof d.source === 'string' ? d.source : d.source.id
      const targetId = typeof d.target === 'string' ? d.target : d.target.id
      if (sourceId === nodeId) connectedIds.add(targetId)
      if (targetId === nodeId) connectedIds.add(sourceId)
    })

    container.selectAll<SVGGElement, SimNode>('.node-group').attr('opacity', (d) =>
      connectedIds.has(d.id) ? 1 : 0.15,
    )

    container.selectAll<SVGLineElement, SimEdge>('.edge-line').attr('opacity', (d) => {
      const sourceId = typeof d.source === 'string' ? d.source : d.source.id
      const targetId = typeof d.target === 'string' ? d.target : d.target.id
      return sourceId === nodeId || targetId === nodeId ? 1 : 0.08
    })

    container.selectAll<SVGTextElement, SimEdge>('.edge-label').attr('opacity', (d) => {
      const sourceId = typeof d.source === 'string' ? d.source : d.source.id
      const targetId = typeof d.target === 'string' ? d.target : d.target.id
      return sourceId === nodeId || targetId === nodeId ? 1 : 0.08
    })
  } else {
    container.selectAll('.node-group').attr('opacity', 1)
    container.selectAll('.edge-line').attr('opacity', 0.6)
    container.selectAll('.edge-label').attr('opacity', 0.7)
  }
}

function initGraph() {
  if (!svgRef.value) return

  // Clear previous graph
  d3.select(svgRef.value).selectAll('*').remove()

  svg = d3.select(svgRef.value)
  const width = svgRef.value.clientWidth
  const height = svgRef.value.clientHeight

  // Zoom behavior
  zoomBehavior = d3
    .zoom<SVGSVGElement, unknown>()
    .scaleExtent([0.1, 4])
    .on('zoom', (event) => {
      container.attr('transform', event.transform)
    })

  svg.call(zoomBehavior)

  container = svg.append('g')

  // Deep-copy nodes and edges for D3 mutation
  const simNodes: SimNode[] = props.nodes.map((n) => ({ ...n }))
  const simEdges: SimEdge[] = props.edges.map((e) => ({
    source: e.source,
    target: e.target,
    type: e.type,
    label: e.label,
  }))

  if (simNodes.length === 0) return

  // Force simulation
  simulation = d3
    .forceSimulation(simNodes as d3.SimulationNodeDatum[])
    .force(
      'link',
      d3
        .forceLink<d3.SimulationNodeDatum, SimEdge>(simEdges)
        .id((d) => (d as SimNode).id)
        .distance(120),
    )
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius((d) => (d as SimNode).size + 10))

  // Edges
  const edgeGroup = container
    .selectAll<SVGLineElement, SimEdge>('.edge-line')
    .data(simEdges)
    .join('line')
    .attr('class', 'edge-line')
    .attr('stroke', (d) => getEdgeColor(d.type))
    .attr('stroke-width', 1.5)
    .attr('stroke-dasharray', (d) => getEdgeDash(d.type))
    .attr('opacity', 0.6)

  // Edge labels
  const edgeLabelGroup = container
    .selectAll<SVGTextElement, SimEdge>('.edge-label')
    .data(simEdges.filter((e) => e.label))
    .join('text')
    .attr('class', 'edge-label')
    .attr('text-anchor', 'middle')
    .attr('dy', -6)
    .attr('fill', '#64748b')
    .attr('font-size', '9px')
    .attr('opacity', 0.7)
    .text((d) => d.label ?? '')

  // Node groups
  const nodeGroup = container
    .selectAll<SVGGElement, SimNode>('.node-group')
    .data(simNodes)
    .join('g')
    .attr('class', 'node-group')
    .style('cursor', 'pointer')

  // Draw shapes
  drawNodeShape(nodeGroup)

  // Node labels
  nodeGroup
    .append('text')
    .attr('class', 'node-label')
    .attr('text-anchor', 'middle')
    .attr('dy', (d) => d.size + 14)
    .attr('fill', '#94a3b8')
    .attr('font-size', '10px')
    .text((d) => d.label)

  // Drag behavior
  const drag = d3
    .drag<SVGGElement, SimNode>()
    .on('start', (event, d) => {
      if (!event.active) simulation.alphaTarget(0.3).restart()
      d.fx = d.x
      d.fy = d.y
    })
    .on('drag', (event, d) => {
      d.fx = event.x
      d.fy = event.y
    })
    .on('end', (event, d) => {
      if (!event.active) simulation.alphaTarget(0)
      d.fx = null
      d.fy = null
    })

  nodeGroup.call(drag)

  // Click handler
  nodeGroup.on('click', (_event, d) => {
    const originalNode = props.nodes.find((n) => n.id === d.id)
    if (originalNode) {
      emit('node-click', originalNode)
    }
  })

  // Hover handlers
  nodeGroup
    .on('mouseenter', (event, d) => {
      showTooltip(event as MouseEvent, d)
      highlightConnected(d.id, true)
    })
    .on('mousemove', (event, d) => {
      showTooltip(event as MouseEvent, d)
    })
    .on('mouseleave', (_, d) => {
      hideTooltip()
      highlightConnected(d.id, false)
    })

  // Tick function
  simulation.on('tick', () => {
    edgeGroup
      .attr('x1', (d) => (d.source as SimNode).x ?? 0)
      .attr('y1', (d) => (d.source as SimNode).y ?? 0)
      .attr('x2', (d) => (d.target as SimNode).x ?? 0)
      .attr('y2', (d) => (d.target as SimNode).y ?? 0)

    edgeLabelGroup
      .attr('x', (d) => {
        const sx = (d.source as SimNode).x ?? 0
        const tx = (d.target as SimNode).x ?? 0
        return (sx + tx) / 2
      })
      .attr('y', (d) => {
        const sy = (d.source as SimNode).y ?? 0
        const ty = (d.target as SimNode).y ?? 0
        return (sy + ty) / 2
      })

    nodeGroup.attr('transform', (d) => `translate(${d.x ?? 0},${d.y ?? 0})`)
  })
}

function resetZoom() {
  if (!svg || !zoomBehavior) return
  svg.transition().duration(500).call(zoomBehavior.transform, d3.zoomIdentity)
}

onMounted(() => {
  nextTick(() => {
    initGraph()
  })
})

watch(
  () => [props.nodes, props.edges],
  () => {
    if (simulation) {
      simulation.stop()
    }
    nextTick(() => {
      initGraph()
    })
  },
  { deep: true },
)

onBeforeUnmount(() => {
  if (simulation) {
    simulation.stop()
  }
})
</script>

<template>
  <div class="relative h-full w-full">
    <svg
      ref="svgRef"
      class="h-full w-full"
      style="background: transparent"
    />

    <!-- Tooltip (Vue-rendered, safe from XSS) -->
    <div
      v-if="tooltipVisible && tooltipNode"
      class="pointer-events-none absolute z-50 max-w-xs rounded-lg border border-white/10 bg-slate-900/95 px-3 py-2 shadow-xl backdrop-blur-sm"
      :style="{ left: tooltipX + 'px', top: tooltipY + 'px' }"
    >
      <div class="space-y-1 text-xs">
        <div v-if="tooltipNode.ip">
          <span class="text-slate-500">IP:</span>
          <span class="ml-1 font-mono text-cyan-400">{{ tooltipNode.ip }}</span>
        </div>
        <div v-if="tooltipNode.hostname">
          <span class="text-slate-500">Host:</span>
          <span class="ml-1 text-white">{{ tooltipNode.hostname }}</span>
        </div>
        <div v-if="tooltipNode.vendor">
          <span class="text-slate-500">Vendor:</span>
          <span class="ml-1 text-white">{{ tooltipNode.vendor }}</span>
        </div>
        <div>
          <span class="text-slate-500">Category:</span>
          <span class="ml-1 text-white">{{ tooltipNode.bigr_category }}</span>
        </div>
        <div>
          <span class="text-slate-500">Type:</span>
          <span class="ml-1 text-white">{{ tooltipNode.type }}</span>
        </div>
        <div>
          <span class="text-slate-500">Ports:</span>
          <span class="ml-1 text-slate-300">{{ tooltipPorts }}</span>
        </div>
      </div>
    </div>

    <!-- Reset Zoom Button -->
    <button
      class="absolute bottom-3 right-3 flex items-center gap-1.5 rounded-lg border border-white/10 bg-slate-900/80 px-2.5 py-1.5 text-xs text-slate-400 backdrop-blur-sm transition-colors hover:bg-slate-800 hover:text-slate-200"
      title="Reset zoom"
      @click="resetZoom"
    >
      <RotateCcw :size="12" />
      Reset
    </button>
  </div>
</template>
