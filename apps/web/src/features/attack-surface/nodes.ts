/**
 * Reading the attack-surface graph the way the control plane actually emits it.
 *
 * Three things about that payload are easy to get wrong, and all three were:
 *
 *  - the discriminator is `type`, not `kind`, and its values are `asset`,
 *    `business_service`, `exposure` and `aggregated_assets`;
 *  - `id` is *namespaced* — `business_service:<uuid>`, not a bare uuid — because assets,
 *    services and exposure tiers share one id space in a single graph. Linking to
 *    `/assets/{node.id}` therefore has to strip the prefix;
 *  - `weight` is a `numeric`, so it arrives as a decimal string and sorts lexically
 *    unless parsed.
 */

import { parseDecimal } from '@/lib/format';
import { toExposure, toGraphNodeKind, type GraphNode, type GraphNodeKind } from '@/types/domain';

export function nodeKind(node: GraphNode): GraphNodeKind | null {
  return toGraphNodeKind(node.type);
}

/** Node weight as a number — `business_risk_score` for assets, rolled up for services. */
export function nodeWeight(node: GraphNode): number {
  return parseDecimal(node.weight) ?? 0;
}

export function nodeExposure(node: GraphNode) {
  return toExposure(node.exposure);
}

/**
 * The underlying resource id, with the `<type>:` namespace removed, or `null` for a node
 * that stands for no single resource (an exposure tier, an aggregate placeholder).
 */
export function nodeEntityId(node: GraphNode): string | null {
  const kind = nodeKind(node);
  if (kind !== 'asset' && kind !== 'business_service') return null;
  const separator = node.id.indexOf(':');
  return separator === -1 ? node.id : node.id.slice(separator + 1);
}

/** Where clicking this node should take the operator, or `null` when nowhere useful. */
export function nodeHref(node: GraphNode): string | null {
  const entityId = nodeEntityId(node);
  if (entityId === null) return null;
  return nodeKind(node) === 'asset'
    ? `/assets/${entityId}`
    : `/findings?service_id=${entityId}&status=open`;
}
