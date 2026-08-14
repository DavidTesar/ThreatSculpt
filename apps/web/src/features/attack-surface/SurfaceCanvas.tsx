import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { computeLayout, hitTest, type PositionedNode } from './layout';
import { nodeExposure, nodeKind, nodeWeight } from './nodes';
import { formatScore } from '@/lib/format';
import { CRITICALITY_LABEL, EXPOSURE_LABEL } from '@/lib/risk';
import { toCriticality, type AttackSurfaceGraph, type Exposure } from '@/types/domain';

/** The colour ramp is keyed by exposure tier; anything else falls back to muted ink. */
function exposureLabelOf(exposure: Exposure | null): string {
  return exposure ? EXPOSURE_LABEL[exposure] : 'Position unknown';
}

/**
 * One line describing a node. The graph payload carries no open-findings count, so this
 * says what the node *is*; the count lives on the asset and finding views that have it.
 */
function describeNode(node: PositionedNode): string {
  const criticality = toCriticality(node.criticality);
  switch (nodeKind(node)) {
    case 'business_service':
      return criticality
        ? `Business service · ${CRITICALITY_LABEL[criticality].toLowerCase()} criticality`
        : 'Business service';
    case 'aggregated_assets':
      return `${node.represents ?? 0} assets · ${exposureLabelOf(nodeExposure(node))}`;
    case 'exposure':
      return `Exposure tier · ${exposureLabelOf(nodeExposure(node))}`;
    default:
      return `Asset · ${exposureLabelOf(nodeExposure(node))}`;
  }
}

const WIDTH = 1000;
const HEIGHT = 620;

/** Reads a CSS custom property so the canvas honours the active theme. */
function cssVar(name: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback;
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}

/**
 * The graph is drawn to a canvas rather than as SVG or DOM.
 *
 * At the documented 500-node cap plus edges, a DOM-per-node approach means well over a
 * thousand elements, each with its own style recalculation and hit-testing — which is
 * exactly the failure mode API.md warns about. One canvas is a single element; hover
 * hit-testing is a distance check over an array.
 *
 * Accessibility is handled by the sibling node list rather than by trying to make canvas
 * pixels focusable: the list is real DOM, keyboard navigable, and carries the same data.
 */
export function SurfaceCanvas({
  graph,
  selectedId,
  onSelect,
}: {
  graph: AttackSurfaceGraph;
  selectedId: string | null;
  onSelect: (node: PositionedNode | null) => void;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [hovered, setHovered] = useState<PositionedNode | null>(null);
  const [pointer, setPointer] = useState<{ x: number; y: number } | null>(null);

  const layout = useMemo(() => computeLayout(graph, WIDTH, HEIGHT), [graph]);

  const highlightedId = hovered?.id ?? selectedId;

  // Neighbours of the focused node, so hovering dims everything unrelated.
  const connected = useMemo(() => {
    if (!highlightedId) return null;
    const ids = new Set<string>([highlightedId]);
    for (const edge of layout.edges) {
      if (edge.source === highlightedId) ids.add(edge.target);
      else if (edge.target === highlightedId) ids.add(edge.source);
    }
    return ids;
  }, [highlightedId, layout.edges]);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    // jsdom has no 2d context; the component still renders its accessible list.
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = WIDTH * dpr;
    canvas.height = HEIGHT * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, WIDTH, HEIGHT);

    const edgeColor = cssVar('--graph-edge', 'rgba(120,120,120,0.3)');
    const strokeColor = cssVar('--graph-node-stroke', '#fff');
    const brand = cssVar('--brand', '#0f5f63');
    const inkMuted = cssVar('--ink-muted', '#57524b');
    const exposureColors: Record<string, string> = {
      internet: cssVar('--exp-internet', '#a3122b'),
      dmz: cssVar('--exp-dmz', '#b4531b'),
      internal: cssVar('--exp-internal', '#3c5a88'),
      isolated: cssVar('--exp-isolated', '#4a7c68'),
    };

    // --- edges first, so nodes sit on top
    for (const edge of layout.edges) {
      const source = layout.byId.get(edge.source);
      const target = layout.byId.get(edge.target);
      if (!source || !target) continue;

      const isRelevant = !connected || (connected.has(edge.source) && connected.has(edge.target));

      ctx.beginPath();
      ctx.moveTo(source.x, source.y);
      // A slight curve towards the centre keeps dense sectors from becoming a solid block.
      const midX = (source.x + target.x) / 2;
      const midY = (source.y + target.y) / 2;
      ctx.quadraticCurveTo(
        midX + (WIDTH / 2 - midX) * 0.18,
        midY + (HEIGHT / 2 - midY) * 0.18,
        target.x,
        target.y,
      );
      ctx.strokeStyle = isRelevant ? edgeColor : withAlpha(edgeColor, 0.25);
      ctx.lineWidth = isRelevant ? 1 : 0.6;
      // `exposes` edges are dashed, so the distinction survives without colour.
      ctx.setLineDash(edge.type === 'exposes' ? [3, 3] : []);
      ctx.stroke();
    }
    ctx.setLineDash([]);

    // --- nodes
    for (const node of layout.nodes) {
      const dimmed = connected ? !connected.has(node.id) : false;
      const isFocus = node.id === highlightedId;

      ctx.globalAlpha = dimmed ? 0.22 : 1;

      if (nodeKind(node) === 'business_service') {
        // Services are squares — a different shape, not just a different colour.
        const size = node.radius;
        ctx.beginPath();
        ctx.roundRect(node.x - size, node.y - size, size * 2, size * 2, 4);
        ctx.fillStyle = brand;
        ctx.fill();
        ctx.lineWidth = 2;
        ctx.strokeStyle = strokeColor;
        ctx.stroke();
      } else {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = exposureColors[nodeExposure(node) ?? 'internal'] ?? inkMuted;
        ctx.fill();
        ctx.lineWidth = 1.25;
        ctx.strokeStyle = strokeColor;
        ctx.stroke();

        // Aggregate nodes get a second ring, marking them as a rollup rather than a host.
        if (nodeKind(node) === 'aggregated_assets') {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 3, 0, Math.PI * 2);
          ctx.lineWidth = 1;
          ctx.strokeStyle = exposureColors[nodeExposure(node) ?? 'internal'] ?? inkMuted;
          ctx.stroke();
        }
      }

      if (isFocus) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + 6, 0, Math.PI * 2);
        ctx.lineWidth = 2;
        ctx.strokeStyle = brand;
        ctx.stroke();
      }

      ctx.globalAlpha = 1;
    }

    // --- service labels, drawn last so nothing overlaps them
    ctx.font = `600 12px ${cssVar('--font-ui', 'sans-serif')}`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    for (const node of layout.nodes) {
      if (nodeKind(node) !== 'business_service') continue;
      const dimmed = connected ? !connected.has(node.id) : false;
      ctx.globalAlpha = dimmed ? 0.3 : 1;

      const label = node.label;
      const metrics = ctx.measureText(label);
      const y = node.y + node.radius + 13;

      ctx.fillStyle = withAlpha(cssVar('--surface', '#fff'), 0.86);
      ctx.beginPath();
      ctx.roundRect(node.x - metrics.width / 2 - 5, y - 8, metrics.width + 10, 16, 4);
      ctx.fill();

      ctx.fillStyle = cssVar('--ink', '#17161a');
      ctx.fillText(label, node.x, y);
      ctx.globalAlpha = 1;
    }
  }, [layout, connected, highlightedId]);

  useEffect(() => {
    draw();
  }, [draw]);

  // Redraw on theme change — the canvas has no CSS to cascade into it.
  useEffect(() => {
    const observer = new MutationObserver(() => draw());
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    });
    return () => observer.disconnect();
  }, [draw]);

  const toGraphCoords = (event: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    return {
      x: ((event.clientX - rect.left) / rect.width) * WIDTH,
      y: ((event.clientY - rect.top) / rect.height) * HEIGHT,
      screenX: event.clientX - rect.left,
      screenY: event.clientY - rect.top,
    };
  };

  const handleMove = (event: React.MouseEvent<HTMLCanvasElement>) => {
    const coords = toGraphCoords(event);
    if (!coords) return;
    const node = hitTest(layout, coords.x, coords.y);
    setHovered(node);
    setPointer(node ? { x: coords.screenX, y: coords.screenY } : null);
  };

  const handleClick = (event: React.MouseEvent<HTMLCanvasElement>) => {
    const coords = toGraphCoords(event);
    if (!coords) return;
    onSelect(hitTest(layout, coords.x, coords.y));
  };

  return (
    <div className="surface__canvaswrap">
      <canvas
        ref={canvasRef}
        className="surface__canvas"
        style={{ aspectRatio: `${WIDTH} / ${HEIGHT}` }}
        onMouseMove={handleMove}
        onMouseLeave={() => {
          setHovered(null);
          setPointer(null);
        }}
        onClick={handleClick}
        role="img"
        aria-label={`Attack surface map: ${layout.nodes.length} nodes and ${layout.edges.length} connections. A keyboard-navigable list of the same data follows.`}
      />

      {hovered && pointer ? (
        <div
          className="surface__tooltip"
          style={{
            left: Math.min(pointer.x + 14, 760),
            top: Math.max(8, pointer.y - 12),
          }}
        >
          <p className="surface__tooltiptitle">{hovered.label}</p>
          <p className="subtle">{describeNode(hovered)}</p>
          <p className="subtle">Top risk {formatScore(nodeWeight(hovered))}</p>
        </div>
      ) : null}

      <div className="surface__legend">
        <span className="surface__legenditem">
          <svg width="12" height="12" aria-hidden="true">
            <rect width="12" height="12" rx="3" fill="var(--brand)" />
          </svg>
          Business service
        </span>
        <span className="surface__legenditem">
          <svg width="12" height="12" aria-hidden="true">
            <circle cx="6" cy="6" r="5" fill="var(--exp-internet)" />
          </svg>
          Internet-facing asset
        </span>
        <span className="surface__legenditem">
          <svg width="12" height="12" aria-hidden="true">
            <circle cx="6" cy="6" r="5" fill="var(--exp-internal)" />
          </svg>
          Internal asset
        </span>
        <span className="surface__legenditem">
          <svg width="26" height="8" aria-hidden="true">
            <line
              x1="0"
              y1="4"
              x2="26"
              y2="4"
              stroke="var(--ink-subtle)"
              strokeWidth="1.5"
              strokeDasharray="3 3"
            />
          </svg>
          Exposes (internet or DMZ)
        </span>
        <span className="surface__legenditem">
          <svg width="26" height="8" aria-hidden="true">
            <line x1="0" y1="4" x2="26" y2="4" stroke="var(--ink-subtle)" strokeWidth="1.5" />
          </svg>
          Supports
        </span>
        <span className="subtle">Circle size = highest business risk on that node.</span>
      </div>
    </div>
  );
}

/** Applies an alpha to a colour string, handling hex and rgb() forms. */
function withAlpha(color: string, alpha: number): string {
  if (color.startsWith('#')) {
    const hex = color.slice(1);
    const full =
      hex.length === 3
        ? hex
            .split('')
            .map((c) => c + c)
            .join('')
        : hex;
    const r = parseInt(full.slice(0, 2), 16);
    const g = parseInt(full.slice(2, 4), 16);
    const b = parseInt(full.slice(4, 6), 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }
  if (color.startsWith('rgb')) {
    return color.replace(/rgba?\(([^)]+)\)/, (_match, inner: string) => {
      const parts = inner
        .split(/[\s,/]+/)
        .filter(Boolean)
        .slice(0, 3);
      return `rgba(${parts.join(', ')}, ${alpha})`;
    });
  }
  return color;
}
