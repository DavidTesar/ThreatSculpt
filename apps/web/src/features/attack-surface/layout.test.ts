import { describe, expect, it } from 'vitest';
import { computeLayout, hitTest } from './layout';
import { buildAttackSurface } from '@/mocks/derive';
import { buildDb } from '@/mocks/db';
import type { AttackSurfaceGraph, GraphNode } from '@/types/domain';

function node(id: string, kind: GraphNode['kind'], weight: number): GraphNode {
  return {
    id,
    kind,
    label: id,
    weight,
    exposure: kind === 'service' ? null : 'internal',
    criticality: kind === 'service' ? 'critical' : null,
    open_findings: 0,
    represents: null,
  };
}

const SIMPLE: AttackSurfaceGraph = {
  nodes: [node('s1', 'service', 50), node('a1', 'asset', 90), node('a2', 'asset', 10)],
  edges: [
    { source: 'a1', target: 's1', kind: 'supports' },
    { source: 'a2', target: 's1', kind: 'supports' },
  ],
  aggregated: false,
  node_cap: 500,
  total_nodes: 3,
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
    const heavy = layout.byId.get('a1');
    const light = layout.byId.get('a2');

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

    expect(distance('s1')).toBeLessThan(distance('a1'));
  });

  it('handles the full fixture estate without dropping nodes', () => {
    const graph = buildAttackSurface(buildDb());
    const layout = computeLayout(graph, 1000, 620);

    expect(layout.nodes).toHaveLength(graph.nodes.length);
    expect(layout.nodes.every((n) => Number.isFinite(n.x) && Number.isFinite(n.y))).toBe(true);
  });

  it('survives an empty graph', () => {
    const layout = computeLayout(
      { nodes: [], edges: [], aggregated: false, node_cap: 500, total_nodes: 0 },
      800,
      600,
    );

    expect(layout.nodes).toHaveLength(0);
  });
});

describe('hitTest', () => {
  it('finds the node under the cursor', () => {
    const layout = computeLayout(SIMPLE, 1000, 620);
    const target = layout.byId.get('a1')!;

    expect(hitTest(layout, target.x, target.y)?.id).toBe('a1');
  });

  it('returns null over empty space', () => {
    const layout = computeLayout(SIMPLE, 1000, 620);

    expect(hitTest(layout, 5, 5)).toBeNull();
  });
});

describe('buildAttackSurface aggregation', () => {
  it('stays under the node cap and flags aggregation when the estate is large', () => {
    const graph = buildAttackSurface(buildDb());

    expect(graph.nodes.length).toBeLessThanOrEqual(graph.node_cap);
    if (graph.aggregated) {
      expect(graph.nodes.some((n) => n.kind === 'aggregate')).toBe(true);
      expect(graph.total_nodes).toBeGreaterThan(graph.node_cap);
    }
  });
});
