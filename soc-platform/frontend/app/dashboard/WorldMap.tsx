"use client";

import { useMemo } from "react";

// Stylized world dot-map: continents approximated as unions of ellipses in lon/lat space,
// rasterized onto a coarse grid with a seeded PRNG for organic/dotted edges. No image asset or
// network fetch involved (this app loads zero external resources by design), and the seeded RNG
// keeps the pattern identical across server/client renders so React hydration never mismatches.

interface Blob {
  lon: number;
  lat: number;
  rx: number;
  ry: number;
}

const CONTINENTS: Blob[] = [
  { lon: -105, lat: 48, rx: 24, ry: 16 },   // N. America
  { lon: -100, lat: 65, rx: 20, ry: 10 },   // Canada/Arctic
  { lon: -122, lat: 40, rx: 8, ry: 14 },    // US west coast
  { lon: -42, lat: 74, rx: 9, ry: 7 },      // Greenland
  { lon: -90, lat: 18, rx: 7, ry: 7 },      // Central America
  { lon: -60, lat: -5, rx: 14, ry: 12 },    // N. South America
  { lon: -66, lat: -30, rx: 9, ry: 16 },    // S. South America
  { lon: 12, lat: 52, rx: 14, ry: 9 },      // Europe
  { lon: 16, lat: 63, rx: 8, ry: 7 },       // Scandinavia
  { lon: -3, lat: 54, rx: 4, ry: 5 },       // UK/Ireland
  { lon: 15, lat: 20, rx: 18, ry: 12 },     // N. Africa
  { lon: 22, lat: -10, rx: 15, ry: 18 },    // S. Africa
  { lon: 90, lat: 55, rx: 45, ry: 18 },     // Central/N Asia
  { lon: 110, lat: 65, rx: 35, ry: 10 },    // Siberia
  { lon: 48, lat: 28, rx: 10, ry: 10 },     // Middle East
  { lon: 78, lat: 20, rx: 10, ry: 11 },     // India
  { lon: 105, lat: 33, rx: 16, ry: 10 },    // China
  { lon: 138, lat: 37, rx: 4, ry: 8 },      // Japan
  { lon: 105, lat: 10, rx: 12, ry: 8 },     // SE Asia
  { lon: 115, lat: -3, rx: 14, ry: 5 },     // Indonesia
  { lon: 135, lat: -25, rx: 13, ry: 8 },    // Australia
  { lon: 172, lat: -42, rx: 3, ry: 5 },     // New Zealand
];

// Fixed "hub" markers - a few glowing pulse points to echo the network/monitoring feel of the
// reference design, positioned over a few well-known landmasses.
const HUBS: Blob[] = [
  { lon: -98, lat: 39, rx: 0, ry: 0 },
  { lon: 10, lat: 51, rx: 0, ry: 0 },
  { lon: 103, lat: 36, rx: 0, ry: 0 },
  { lon: 133, lat: -27, rx: 0, ry: 0 },
];

function mulberry32(seed: number) {
  let a = seed;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function landDistance(lon: number, lat: number): number {
  let best = Infinity;
  for (const b of CONTINENTS) {
    const d = Math.sqrt(((lon - b.lon) / b.rx) ** 2 + ((lat - b.lat) / b.ry) ** 2);
    if (d < best) best = d;
  }
  return best;
}

const LON_STEP = 4;
const LAT_STEP = 3.6;
const LAT_TOP = 78;
const LAT_BOTTOM = -60;

function buildDots() {
  const rand = mulberry32(1337);
  const dots: { x: number; y: number; r: number }[] = [];
  for (let lat = LAT_TOP; lat >= LAT_BOTTOM; lat -= LAT_STEP) {
    for (let lon = -178; lon <= 178; lon += LON_STEP) {
      const d = landDistance(lon, lat);
      let draw = false;
      if (d <= 0.82) draw = true;
      else if (d <= 1.12) draw = rand() > 0.45;
      if (!draw) continue;
      dots.push({
        x: lon + 180,
        y: LAT_TOP - lat,
        r: 0.55 + rand() * 0.35,
      });
    }
  }
  return dots;
}

export default function WorldMapBackground({ opacity = 0.55 }: { opacity?: number }) {
  const dots = useMemo(buildDots, []);
  const viewW = 360;
  const viewH = LAT_TOP - LAT_BOTTOM;

  return (
    <svg
      viewBox={`0 0 ${viewW} ${viewH}`}
      preserveAspectRatio="none"
      style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none" }}
      aria-hidden="true"
    >
      <defs>
        <radialGradient id="wm-vignette" cx="30%" cy="25%" r="85%">
          <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.16" />
          <stop offset="55%" stopColor="var(--accent)" stopOpacity="0.05" />
          <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
        </radialGradient>
        <radialGradient id="wm-hub-glow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.9" />
          <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
        </radialGradient>
      </defs>

      <rect x={0} y={0} width={viewW} height={viewH} fill="url(#wm-vignette)" />

      <g fill="var(--accent)" opacity={opacity}>
        {dots.map((d, i) => (
          <circle key={i} cx={d.x} cy={d.y} r={d.r} />
        ))}
      </g>

      <g>
        {HUBS.map((h, i) => {
          const cx = h.lon + 180;
          const cy = LAT_TOP - h.lat;
          return (
            <g key={i}>
              <circle cx={cx} cy={cy} r={7} fill="url(#wm-hub-glow)" />
              <circle cx={cx} cy={cy} r={1.1} fill="var(--accent)">
                <animate attributeName="opacity" values="1;0.35;1" dur="2.4s" repeatCount="indefinite" begin={`${i * 0.4}s`} />
              </circle>
            </g>
          );
        })}
      </g>
    </svg>
  );
}
