/**
 * Isometric solids shared by the hero theater and the access diagram.
 *
 * Cube faces sit on a 2:1 axonometric grid, so the face planes slope by
 * atan(0.5) = 26.565 degrees. Anything drawn onto a face is skewed by that
 * same angle so it lies in the plane rather than looking pasted on. The person
 * is built from smooth solids instead: a sphere on a cone.
 *
 * Gradient ids are prefixed per caller, because both components render into
 * the same document and SVG ids are global.
 */

const SKEW_RIGHT = "skewY(-26.565)";

/** Gradient definitions. Render once per caller, with a matching prefix. */
export const isoDefs = (p: string) => `
  <radialGradient id="${p}Head" cx="34%" cy="26%" r="78%">
    <stop offset="0" class="s-hi"/><stop offset="0.62" class="s-top"/><stop offset="1" class="s-left"/>
  </radialGradient>
  <linearGradient id="${p}Body" x1="0" y1="0" x2="1" y2="0.25">
    <stop offset="0" class="s-top"/><stop offset="0.5" class="s-left"/><stop offset="1" class="s-right"/>
  </linearGradient>
  <linearGradient id="${p}BodyBase" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0" class="s-left"/><stop offset="1" class="s-right2"/>
  </linearGradient>
  <linearGradient id="${p}Top" x1="0" y1="0" x2="0.6" y2="1">
    <stop offset="0" class="s-hi"/><stop offset="1" class="s-top2"/>
  </linearGradient>
  <linearGradient id="${p}Left" x1="0" y1="0" x2="0.3" y2="1">
    <stop offset="0" class="s-left"/><stop offset="1" class="s-left2"/>
  </linearGradient>
  <linearGradient id="${p}Right" x1="0" y1="0" x2="0.4" y2="1">
    <stop offset="0" class="s-right"/><stop offset="1" class="s-right2"/>
  </linearGradient>
  <linearGradient id="${p}aTop" x1="0" y1="0" x2="0.6" y2="1">
    <stop offset="0" class="s-a-top"/><stop offset="1" class="s-a-top2"/>
  </linearGradient>
  <linearGradient id="${p}aLeft" x1="0" y1="0" x2="0.3" y2="1">
    <stop offset="0" class="s-a-left"/><stop offset="1" class="s-a-left2"/>
  </linearGradient>
  <linearGradient id="${p}aRight" x1="0" y1="0" x2="0.4" y2="1">
    <stop offset="0" class="s-a-right"/><stop offset="1" class="s-a-right2"/>
  </linearGradient>
`;

export const personIcon = (p: string) => `
  <ellipse class="iso-shadow" cx="0" cy="33" rx="25" ry="6"/>
  <path fill="url(#${p}Body)" d="
    M -21,29
    C -21,5 -12,-7 0,-7
    C 12,-7 21,5 21,29
    A 21 6.5 0 0 1 -21,29 Z"/>
  <ellipse fill="url(#${p}BodyBase)" cx="0" cy="29" rx="21" ry="6.5"/>
  <circle fill="url(#${p}Head)" cx="0" cy="-23" r="13"/>
`;

export const agentIcon = (p: string) => `
  <ellipse class="iso-shadow" cx="0" cy="35" rx="29" ry="7"/>
  <polygon fill="url(#${p}Top)"   points="-28,-14 0,-28 28,-14 0,0"/>
  <polygon fill="url(#${p}Left)"  points="-28,-14 0,0 0,30 -28,16"/>
  <polygon fill="url(#${p}Right)" points="28,-14 28,16 0,30 0,0"/>
  <line x1="0" y1="-14" x2="0" y2="-34" class="iso-antenna"/>
  <circle class="iso-mark" cx="0" cy="-37" r="3.2"/>
  <g transform="translate(14 8) ${SKEW_RIGHT}">
    <rect class="iso-screen" x="-9.5" y="-9" width="19" height="15" rx="2.5"/>
    <circle class="iso-eye" cx="-4.2" cy="-2.2" r="2.3"/>
    <circle class="iso-eye" cx="4.2" cy="-2.2" r="2.3"/>
  </g>
`;

export const brokerIcon = (p: string) => `
  <ellipse class="iso-shadow" cx="0" cy="39" rx="32" ry="7.5"/>
  <polygon fill="url(#${p}aTop)"   points="-30,-22 0,-38 30,-22 0,-6"/>
  <polygon fill="url(#${p}aLeft)"  points="-30,-22 0,-6 0,34 -30,18"/>
  <polygon fill="url(#${p}aRight)" points="30,-22 30,18 0,34 0,-6"/>
  <g transform="translate(15 6) ${SKEW_RIGHT}">
    <path class="iso-a-mark" d="M -6,-4 A 6 6 0 0 1 6,-4 L 6,0 L 3,0 L 3,-4 A 3 3 0 0 0 -3,-4 L -3,0 L -6,0 Z"/>
    <rect class="iso-a-mark" x="-7.5" y="0" width="15" height="12" rx="2"/>
  </g>
`;

export const cubeIcon = (p: string) => `
  <ellipse class="iso-shadow" cx="0" cy="18" rx="17" ry="4.5"/>
  <polygon fill="url(#${p}Top)"   points="-17,-10 0,-19 17,-10 0,-1"/>
  <polygon fill="url(#${p}Left)"  points="-17,-10 0,-1 0,16 -17,7"/>
  <polygon fill="url(#${p}Right)" points="17,-10 17,7 0,16 0,-1"/>
`;

export const policyIcon = (p: string) => `
  <path fill="url(#${p}Top)" d="M -11,-13 L 5,-13 L 11,-7 L 11,13 L -11,13 Z"/>
  <path fill="url(#${p}Left)" d="M 5,-13 L 11,-7 L 5,-7 Z"/>
  <rect class="iso-mark" x="-7" y="-5" width="14" height="1.6" rx="0.8"/>
  <rect class="iso-mark" x="-7" y="-0.5" width="14" height="1.6" rx="0.8"/>
  <rect class="iso-mark" x="-7" y="4" width="9" height="1.6" rx="0.8"/>
`;

/** Stop colours for the gradients above. Scoped styles cannot reach them. */
export const isoStopCss = `
  .s-hi { stop-color: var(--iso-hi); }
  .s-top { stop-color: var(--iso-top); }
  .s-top2 { stop-color: var(--iso-top2); }
  .s-left { stop-color: var(--iso-left); }
  .s-left2 { stop-color: var(--iso-left2); }
  .s-right { stop-color: var(--iso-right); }
  .s-right2 { stop-color: var(--iso-right2); }
  .s-a-top { stop-color: var(--iso-a-top); }
  .s-a-top2 { stop-color: var(--iso-a-top2); }
  .s-a-left { stop-color: var(--iso-a-left); }
  .s-a-left2 { stop-color: var(--iso-a-left2); }
  .s-a-right { stop-color: var(--iso-a-right); }
  .s-a-right2 { stop-color: var(--iso-a-right2); }
`;
