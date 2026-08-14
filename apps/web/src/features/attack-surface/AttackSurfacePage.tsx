import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { PageHeader } from '@/components/layout/PageHeader';
import { Card, CardBody, CardHead } from '@/components/ui/Card';
import { AsyncBoundary, EmptyState } from '@/components/ui/States';
import { ButtonLink } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { TextField } from '@/components/ui/Field';
import { SurfaceCanvas } from './SurfaceCanvas';
import { dashboardApi } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import { formatNumber, formatScore } from '@/lib/format';
import { nodeExposure, nodeHref, nodeKind, nodeWeight } from './nodes';
import { CRITICALITY_LABEL, EXPOSURE_LABEL } from '@/lib/risk';
import { toCriticality, type GraphNode } from '@/types/domain';

/** Keeps the node list workable when the graph is at its cap. */
const LIST_LIMIT = 120;

/**
 * What a node is, in one phrase. The graph payload carries no per-node findings count, so
 * this describes the node's role rather than inventing a number for it.
 */
function describeNode(node: GraphNode): string {
  const exposure = nodeExposure(node);
  const criticality = toCriticality(node.criticality);
  switch (nodeKind(node)) {
    case 'business_service':
      return criticality
        ? `Business service · ${CRITICALITY_LABEL[criticality].toLowerCase()} criticality`
        : 'Business service';
    case 'aggregated_assets':
      return `${formatNumber(node.represents ?? 0)} assets grouped`;
    case 'exposure':
      return exposure ? `Exposure tier · ${EXPOSURE_LABEL[exposure]}` : 'Exposure tier';
    default:
      return exposure ? `Asset · ${EXPOSURE_LABEL[exposure]}` : 'Asset';
  }
}

export function AttackSurfacePage() {
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [filter, setFilter] = useState('');

  const query = useQuery({
    queryKey: queryKeys.dashboard.attackSurface,
    queryFn: ({ signal }) => dashboardApi.attackSurface(signal),
  });

  const selectedExposure = selected ? nodeExposure(selected) : null;
  // Node ids are namespaced (`asset:<uuid>`), so the link is built from the stripped id.
  const selectedHref = selected ? nodeHref(selected) : null;

  const ranked = useMemo(() => {
    const nodes = query.data?.nodes ?? [];
    const needle = filter.toLowerCase().trim();
    return [...nodes]
      .filter((node) => !needle || node.label.toLowerCase().includes(needle))
      .sort((a, b) => nodeWeight(b) - nodeWeight(a))
      .slice(0, LIST_LIMIT);
  }, [query.data, filter]);

  return (
    <main className="main main--wide" id="main">
      <PageHeader
        eyebrow="Overview"
        title="Attack surface"
        lead="How your assets connect to the business services they support. Larger nodes carry higher business risk; dashed connections mean the asset is reachable from outside."
        actions={
          <ButtonLink to="/assets" variant="secondary">
            <Icon name="assets" size={15} />
            Asset list
          </ButtonLink>
        }
      />

      <AsyncBoundary
        isLoading={query.isPending}
        error={query.error}
        data={query.data}
        onRetry={() => void query.refetch()}
        loadingLabel="Building the attack surface map"
        isEmpty={(graph) => (graph.nodes ?? []).length === 0}
        empty={
          <Card>
            <EmptyState
              icon="graph"
              title="Nothing to map yet"
              body="Once you have discovered assets and mapped them to business services, this view shows how exposure reaches the things your organisation depends on."
              action={
                <ButtonLink to="/scans" variant="primary">
                  Run a discovery scan
                </ButtonLink>
              }
            />
          </Card>
        }
      >
        {(graph) => (
          <>
            {graph.aggregated ? (
              <div className="alert alert--info" style={{ marginBottom: 'var(--space-lg)' }}>
                <Icon name="info" size={16} className="alert__icon" />
                <div>
                  <p className="alert__title">Showing an aggregated view</p>
                  <p style={{ fontSize: 'var(--text-xs)' }}>
                    Your estate has {formatNumber(graph.total_assets)} assets, above the{' '}
                    {formatNumber(graph.node_cap)}-node limit for this map. Assets have been grouped
                    by service and network position — each ringed circle stands for many hosts. Use
                    the <Link to="/assets">asset list</Link> to work with individual hosts.
                  </p>
                </div>
              </div>
            ) : null}

            <div className="surface">
              <SurfaceCanvas
                graph={graph}
                selectedId={selected?.id ?? null}
                onSelect={setSelected}
              />

              <div className="stack stack--lg">
                {selected ? (
                  <Card as="section" aria-labelledby="selected-heading">
                    <CardHead
                      titleId="selected-heading"
                      title={selected.label}
                      subtitle={describeNode(selected)}
                      as="h2"
                      actions={
                        <button
                          type="button"
                          className="btn btn--ghost btn--sm"
                          onClick={() => setSelected(null)}
                          aria-label="Clear selection"
                        >
                          <Icon name="close" size={14} />
                        </button>
                      }
                    />
                    <CardBody>
                      <dl className="deflist">
                        {selectedExposure ? (
                          <>
                            <dt>Position</dt>
                            <dd>{EXPOSURE_LABEL[selectedExposure]}</dd>
                          </>
                        ) : null}
                        <dt>Top risk score</dt>
                        <dd>{formatScore(nodeWeight(selected))}</dd>
                      </dl>

                      {selectedHref ? (
                        <ButtonLink
                          to={selectedHref}
                          variant="secondary"
                          size="sm"
                          className="btn--full"
                          style={{ marginTop: 'var(--space-md)' }}
                        >
                          {nodeKind(selected) === 'asset' ? 'Open asset' : 'View findings'}
                        </ButtonLink>
                      ) : null}
                    </CardBody>
                  </Card>
                ) : null}

                {/*
                  The keyboard-and-screen-reader path to the same data. Canvas pixels cannot
                  be focused or announced, so the graph is paired with a real list rather
                  than being made inaccessible by its rendering choice.
                */}
                <Card as="section" aria-labelledby="nodelist-heading">
                  <CardHead
                    titleId="nodelist-heading"
                    title="Nodes by risk"
                    subtitle={
                      ranked.length >= LIST_LIMIT
                        ? `Highest ${LIST_LIMIT} of ${formatNumber((graph.nodes ?? []).length)}.`
                        : `${formatNumber(ranked.length)} shown.`
                    }
                    as="h2"
                  />
                  <CardBody>
                    <TextField
                      label="Filter nodes"
                      placeholder="Name or hostname"
                      value={filter}
                      onChange={(event) => setFilter(event.target.value)}
                    />
                  </CardBody>
                  <CardBody flush>
                    {ranked.length === 0 ? (
                      <EmptyState
                        icon="search"
                        title="No nodes match"
                        body="Try a shorter search term."
                        compact
                      />
                    ) : (
                      <ul className="nodelist">
                        {ranked.map((node) => (
                          <li key={node.id}>
                            <button
                              type="button"
                              className="nodelist__item"
                              aria-pressed={selected?.id === node.id}
                              onClick={() => setSelected(node)}
                            >
                              <span
                                className="nodelist__dot"
                                style={{
                                  background:
                                    nodeKind(node) === 'business_service'
                                      ? 'var(--brand)'
                                      : `var(--exp-${nodeExposure(node) ?? 'internal'})`,
                                  borderRadius: nodeKind(node) === 'business_service' ? 3 : '50%',
                                }}
                                aria-hidden="true"
                              />
                              <span className="nodelist__text">
                                <span className="nodelist__label">{node.label}</span>
                                <span className="nodelist__meta">{describeNode(node)}</span>
                              </span>
                              <span className="nodelist__score" data-numeric>
                                {formatScore(nodeWeight(node))}
                              </span>
                            </button>
                          </li>
                        ))}
                      </ul>
                    )}
                  </CardBody>
                </Card>
              </div>
            </div>
          </>
        )}
      </AsyncBoundary>
    </main>
  );
}
