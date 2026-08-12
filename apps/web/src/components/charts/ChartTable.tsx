import type { ReactNode } from 'react';

/**
 * The non-visual equivalent of a chart.
 *
 * A `<details>` rather than a visually-hidden table on purpose: sighted users who find the
 * chart hard to read precisely — which is most people, for a trend line — get the exact
 * figures too, instead of the data being available only to screen readers.
 */
export function ChartTable({
  summary,
  caption,
  headers,
  rows,
}: {
  summary: string;
  caption?: ReactNode;
  headers: string[];
  rows: (string | number)[][];
}) {
  return (
    <details className="charttable">
      <summary className="charttable__summary">{summary}</summary>
      <div className="charttable__body">
        {caption ? <p className="charttable__caption">{caption}</p> : null}
        <table className="table table--compact">
          <thead>
            <tr>
              {headers.map((header, i) => (
                <th key={header} scope="col" className={i > 0 ? 'table__num' : undefined}>
                  {header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, rowIndex) => (
              <tr key={rowIndex}>
                {row.map((cell, cellIndex) =>
                  cellIndex === 0 ? (
                    <th key={cellIndex} scope="row" style={{ fontWeight: 'var(--weight-medium)' }}>
                      {cell}
                    </th>
                  ) : (
                    <td key={cellIndex} className="table__num">
                      {cell}
                    </td>
                  ),
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
