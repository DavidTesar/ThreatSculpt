import type { AttackSurfaceGraph, GraphEdge, GraphNode } from '@/types/domain';

export interface PositionedNode extends GraphNode {
  x: number;
  y: number;
  radius: number;
}

export interface GraphLayout {
  nodes: PositionedNode[];
  edges: GraphEdge[];
  byId: Map<string, PositionedNode>;
  width: number;
  height: number;
}

const MIN_NODE_RADIUS = 3.5;
const MAX_NODE_RADIUS = 11;
const SERVICE_RADIUS = 15;

/**
 * A deterministic radial layout: business services on an inner ring, the assets that
 * support each one fanned out in the sector around it, unmapped assets parked in an outer
 * arc of their own.
 *
 * Deliberately not a force simulation. A force layout costs an animation frame budget for
 * hundreds of nodes, produces a different picture on every load — which makes it useless
 * for "show me what changed since last week" — and buys nothing here, because the graph
 * has a known two-level structure. This is O(n), stable, and puts the services where the
 * reader expects them.
 */
export function computeLayout(
  graph: AttackSurfaceGraph,
  width: number,
  height: number,
): GraphLayout {
  const centerX = width / 2;
  const centerY = height / 2;
  const shortest = Math.min(width, height);
  const innerRing = shortest * 0.19;
  const outerRing = shortest * 0.4;
  const strayRing = shortest * 0.47;

  const services = graph.nodes.filter((node) => node.kind === 'service');
  const others = graph.nodes.filter((node) => node.kind !== 'service');

  const maxWeight = Math.max(1, ...graph.nodes.map((node) => node.weight));

  const positioned: PositionedNode[] = [];
  const serviceAngles = new Map<string, number>();

  services.forEach((service, index) => {
    const angle = (index / Math.max(1, services.length)) * Math.PI * 2 - Math.PI / 2;
    serviceAngles.set(service.id, angle);
    positioned.push({
      ...service,
      x: centerX + Math.cos(angle) * innerRing,
      y: centerY + Math.sin(angle) * innerRing,
      radius: SERVICE_RADIUS,
    });
  });

  // Group assets by the first service they connect to, so a cluster sits near its service.
  const primaryService = new Map<string, string>();
  for (const edge of graph.edges) {
    if (!primaryService.has(edge.source)) primaryService.set(edge.source, edge.target);
  }

  const bySector = new Map<string, GraphNode[]>();
  const strays: GraphNode[] = [];
  for (const node of others) {
    const serviceId = primaryService.get(node.id);
    if (serviceId && serviceAngles.has(serviceId)) {
      bySector.set(serviceId, [...(bySector.get(serviceId) ?? []), node]);
    } else {
      strays.push(node);
    }
  }

  const sectorWidth = (Math.PI * 2) / Math.max(1, services.length);

  for (const [serviceId, members] of bySector) {
    const baseAngle = serviceAngles.get(serviceId) ?? 0;
    members.forEach((node, index) => {
      // Spread across the sector, and across two or three rings when the sector is busy,
      // so a service with sixty assets does not become one unreadable arc.
      const ringCount = members.length > 26 ? 3 : members.length > 12 ? 2 : 1;
      const ring = index % ringCount;
      const positionInRing = Math.floor(index / ringCount);
      const perRing = Math.ceil(members.length / ringCount);
      const spread = sectorWidth * 0.82;
      const offset = perRing <= 1 ? 0 : (positionInRing / (perRing - 1) - 0.5) * spread;
      const angle = baseAngle + offset;
      const distance = outerRing + ring * (shortest * 0.045);

      positioned.push({
        ...node,
        x: centerX + Math.cos(angle) * distance,
        y: centerY + Math.sin(angle) * distance,
        radius: scaleRadius(node.weight, maxWeight, node.represents),
      });
    });
  }

  strays.forEach((node, index) => {
    const angle = (index / Math.max(1, strays.length)) * Math.PI * 2 - Math.PI / 2;
    positioned.push({
      ...node,
      x: centerX + Math.cos(angle) * strayRing,
      y: centerY + Math.sin(angle) * strayRing,
      radius: scaleRadius(node.weight, maxWeight, node.represents),
    });
  });

  const byId = new Map(positioned.map((node) => [node.id, node]));
  return { nodes: positioned, edges: graph.edges, byId, width, height };
}

/**
 * Area, not radius, scales with weight — a circle drawn with twice the radius reads as
 * four times the value, which would overstate every high-risk node.
 */
function scaleRadius(weight: number, maxWeight: number, represents: number | null): number {
  const normalized = Math.max(0, Math.min(1, weight / maxWeight));
  const base = MIN_NODE_RADIUS + Math.sqrt(normalized) * (MAX_NODE_RADIUS - MIN_NODE_RADIUS);
  // Aggregate nodes stand in for many assets, so they are drawn proportionally larger.
  return represents ? Math.min(MAX_NODE_RADIUS + 6, base + Math.sqrt(represents)) : base;
}

/** Nearest node under the cursor, or null when the pointer is over empty space. */
export function hitTest(layout: GraphLayout, x: number, y: number): PositionedNode | null {
  let best: PositionedNode | null = null;
  let bestDistance = Infinity;

  for (const node of layout.nodes) {
    const dx = node.x - x;
    const dy = node.y - y;
    const distance = Math.sqrt(dx * dx + dy * dy);
    // A few pixels of slack, so small nodes are not impossible to hit.
    if (distance <= node.radius + 4 && distance < bestDistance) {
      best = node;
      bestDistance = distance;
    }
  }

  return best;
}
