import type { SVGProps } from 'react';

/**
 * A small inline icon set. Inline rather than an icon package: the app needs about twenty
 * glyphs, and a dependency for that is bytes and a supply-chain surface for no gain.
 *
 * Icons are decorative by default (`aria-hidden`), because in every use here the adjacent
 * text already carries the meaning. Pass a `title` when an icon is the only label.
 */

export type IconName =
  | 'dashboard'
  | 'graph'
  | 'findings'
  | 'assets'
  | 'network'
  | 'service'
  | 'scan'
  | 'agent'
  | 'settings'
  | 'search'
  | 'plus'
  | 'close'
  | 'check'
  | 'alert'
  | 'info'
  | 'shield'
  | 'lock'
  | 'unlock'
  | 'arrow-up'
  | 'arrow-down'
  | 'arrow-right'
  | 'arrow-left'
  | 'sort'
  | 'external'
  | 'copy'
  | 'trash'
  | 'refresh'
  | 'logout'
  | 'sun'
  | 'moon'
  | 'inbox'
  | 'clock'
  | 'chevron-down';

const PATHS: Record<IconName, string> = {
  dashboard: 'M3 13h8V3H3v10Zm0 8h8v-6H3v6Zm10 0h8V11h-8v10Zm0-18v6h8V3h-8Z',
  graph:
    'M12 3a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5Zm-7 12a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5Zm14 0a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5ZM11 8.2 6.6 14.4m10.8 0L13 8.2M7.4 17.5h9.2',
  findings: 'M12 2 3 6v6c0 5.2 3.8 9.4 9 10 5.2-.6 9-4.8 9-10V6l-9-4Zm0 6v5m0 3v.01',
  assets: 'M4 5h16v5H4V5Zm0 9h16v5H4v-5Zm3-6.5v.01M7 16.5v.01',
  network: 'M4 4h6v6H4V4Zm10 10h6v6h-6v-6ZM7 10v4h10v-4M7 14h10',
  service: 'M12 2 3 7l9 5 9-5-9-5ZM3 12l9 5 9-5M3 17l9 5 9-5',
  scan: 'M3 7V4h3M21 7V4h-3M3 17v3h3m15-3v3h-3M7 12h10',
  agent: 'M9 3h6v3H9V3Zm-4 6h14v11H5V9Zm4 4v.01M15 13v.01M9 17h6',
  settings:
    'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm7.4-3a7.4 7.4 0 0 0-.1-1.2l2-1.5-2-3.5-2.4 1a7.5 7.5 0 0 0-2-1.2L14.5 2h-5l-.4 2.6a7.5 7.5 0 0 0-2 1.2l-2.4-1-2 3.5 2 1.5a7.6 7.6 0 0 0 0 2.4l-2 1.5 2 3.5 2.4-1a7.5 7.5 0 0 0 2 1.2l.4 2.6h5l.4-2.6a7.5 7.5 0 0 0 2-1.2l2.4 1 2-3.5-2-1.5c.06-.4.1-.8.1-1.2Z',
  search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm10 2-4.35-4.35',
  plus: 'M12 5v14M5 12h14',
  close: 'M18 6 6 18M6 6l12 12',
  check: 'm5 13 4 4L19 7',
  alert: 'M12 3 2 20h20L12 3Zm0 6v5m0 3v.01',
  info: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm0-13v.01M12 11v6',
  shield: 'M12 2 3 6v6c0 5.2 3.8 9.4 9 10 5.2-.6 9-4.8 9-10V6l-9-4Z',
  lock: 'M6 11h12v10H6V11Zm3 0V7a3 3 0 0 1 6 0v4',
  unlock: 'M6 11h12v10H6V11Zm3 0V7a3 3 0 0 1 5.8-1',
  'arrow-up': 'M12 19V5m-6 6 6-6 6 6',
  'arrow-down': 'M12 5v14m6-6-6 6-6-6',
  'arrow-right': 'M5 12h14m-6-6 6 6-6 6',
  'arrow-left': 'M19 12H5m6-6-6 6 6 6',
  sort: 'm7 9 3-3 3 3M7 15l3 3 3-3',
  external: 'M14 4h6v6M20 4l-9 9M18 14v6H4V6h6',
  copy: 'M9 9h11v11H9V9ZM5 15H4V4h11v1',
  trash: 'M4 7h16M9 7V4h6v3m-8 0 1 14h8l1-14M10 11v6M14 11v6',
  refresh: 'M20 12a8 8 0 1 1-2.3-5.6M20 4v5h-5',
  logout: 'M15 4h4v16h-4M11 8l-4 4 4 4M7 12h10',
  sun: 'M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10Zm0-14v2m0 14v2M3 12h2m14 0h2M5.6 5.6l1.4 1.4m10 10 1.4 1.4m0-12.8-1.4 1.4m-10 10-1.4 1.4',
  moon: 'M21 13.2A9 9 0 1 1 10.8 3a7 7 0 0 0 10.2 10.2Z',
  inbox: 'M3 13h5l2 3h4l2-3h5M3 13 5 5h14l2 8v6H3v-6Z',
  clock: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm0-14v5l3 2',
  'chevron-down': 'm6 9 6 6 6-6',
};

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, 'name'> {
  name: IconName;
  size?: number;
  /** Supplying a title makes the icon meaningful to assistive tech instead of decorative. */
  title?: string;
}

export function Icon({ name, size = 16, title, ...rest }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden={title ? undefined : true}
      role={title ? 'img' : undefined}
      focusable="false"
      {...rest}
    >
      {title ? <title>{title}</title> : null}
      <path d={PATHS[name]} />
    </svg>
  );
}
