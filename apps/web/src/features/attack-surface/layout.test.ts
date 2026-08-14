import { describe, expect, it } from 'vitest';
import { computeLayout, hitTest } from './layout';
import { buildAttackSurface } from '@/mocks/derive';
import { buildDb } from '@/mocks/db';
import type { AttackSurfaceGraph, GraphNode, GraphNodeKind } from '@/types/domain';

/**
 * Node ids are namespaced and weights are decimal strings, exactly as the control plane
 * emits them — `business_service:<id>`, not a bare uuid, and `"90.00"`, not `90`.
 */
function node(id: string, kind: GraphNodeKind, weight: number): GraphNode {
  const isService = kind === 'business_service';
  return {
    id: `${kind}:${id}`,
    type: kind,
    label: id,
    weight: weight.toFixed(2),
    exposure: isService ? null : 'internal',
    criticality: isService ? 'critical' : null,
    represents: null,
  };
}

const SERVICE_ID = 'business_service:s1';
const ASSET_HEAVY = 'asset:a1';
const ASSET_LIGHT = 'asset:a2';

const SIMPLE: AttackSurfaceGraph = {
  nodes: [node('s1', 'business_service', 50), node('a1', 'asset', 90), node('a2', 'asset', 10)],
  edges: [
    { source: ASSET_HEAVY, target: SERVICE_ID, type: 'supports' },
    { source: ASSET_LIGHT, target: SERVICE_ID, type: 'supports' },
  ],
  aggregated: false,
  node_cap: 500,
  total_assets: 2,
};

describe('computeLayout', () => {
  it('positions every node inside the viewport', () => {
    const layout = computeLayout(SIMPLE, 1000, 620);

    expect(layout.nodes).toHaveLength(3);
    for (const positioned of layout.nodes) {
      expect(positioned.x).toBeGreaterThan(0);
      expect(positioned.x).toBeLessThan(1000);
      expect(positioned.y).toBeGreaterThan(0);
      expect(positioned.y).toBeLessThan(620);
    }
  });

  it('is deterministic — the same graph always draws the same picture', () => {
    // A force simulation would move nodes on every load, making "what changed since last
    // week?" unanswerable. This layout must be stable.
    const first = computeLayout(SIMPLE, 1000, 620);
    const second = computeLayout(SIMPLE, 1000, 620);

    expect(first.nodes.map((n) => [n.id, n.x, n.y])).toEqual(
      second.nodes.map((n) => [n.id, n.x, n.y]),
    );
  });

  it('scales node area, not radius, with weight', () => {
    const layout = computeLayout(SIMPLE, 1000, 620);
    const heavy = layout.byId.get(ASSET_HEAVY);
    const light = layout.byId.get(ASSET_LIGHT);

    expect(heavy!.radius).toBeGreaterThan(light!.radius);
    // Radius must grow sub-linearly, or a 9× weight would look 81× bigger.
    expect(heavy!.radius / light!.radius).toBeLessThan(9);
  });

  it('places services nearer the centre than the assets that support them', () => {
    const layout = computeLayout(SIMPLE, 1000, 620);
    const distance = (id: string) => {
      const n = layout.byId.get(id)!;
      return Math.hypot(n.x - 500, n.y - 310);
    };

    expect(distance(SERVICE_ID)).toBeLessThan(distance(ASSET_HEAVY));
  });

  it('handles the full fixture estate without dropping nodes', () => {
    const graph = buildAttackSurface(buildDb());
    const layout = computeLayout(graph, 1000, 620);

    expect(layout.nodes).toHaveLength((graph.nodes ?? []).length);
    expect(layout.nodes.every((n) => Number.isFinite(n.x) && Number.isFinite(n.y))).toBe(true);
  });

  it('survives an empty graph', () => {
    const layout = computeLayout(
      { nodes: [], edges: [], aggregated: false, node_cap: 500, total_assets: 0 },
      800,
      600,
    );

    expect(layout.nodes).toHaveLength(0);
  });
});

describe('hitTest', () => {
  it('finds the node under the cursor', () => {
    const layout = computeLayout(SIMPLE, 1000, 620);
    const target = layout.byId.get(ASSET_HEAVY)!;

    expect(hitTest(layout, target.x, target.y)?.id).toBe(ASSET_HEAVY);
  });

  it('returns null over empty space', () => {
    const layout = computeLayout(SIMPLE, 1000, 620);

    expect(hitTest(layout, 5, 5)).toBeNull();
  });
});

describe('buildAttackSurface aggregation', () => {
  it('stays under the node cap and flags aggregation when the estate is large', () => {
    const graph = buildAttackSurface(buildDb());

    const nodes = graph.nodes ?? [];
    expect(nodes.length).toBeLessThanOrEqual(graph.node_cap);
    if (graph.aggregated) {
      expect(nodes.some((n) => n.type === 'aggregated_assets')).toBe(true);
      expect(graph.total_assets).toBeGreaterThan(0);
    }
  });
});
