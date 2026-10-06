"use client";

// Small SVG chart primitives for the Overview dashboard - no charting library, the app has
// none and only two chart shapes are needed (a part-to-whole donut, a single-series trend
// line), each used at most twice, so this stays a focused local file rather than a generic
// abstraction. Mark specs (2px lines, 2px surface gaps/rings, hairline gridlines, legend for
// >=2 series, hover tooltips) follow the dataviz skill's references/marks-and-anatomy.md and
// references/interaction.md.

import { useEffect, useRef, useState } from "react";

// A stat-tile trend sparkline (marks-and-anatomy.md's "Figures" contract: 12-point sparkline,
// current period in the accent hue) - no axes, gridlines, or tooltip; it's a glance-level
// shape, the exact value already lives in the tile's headline number beside it.
export function Sparkline({ data, color = "var(--blue)", width = 64, height = 22 }: { data: number[]; color?: string; width?: number; height?: number }) {
  if (data.length < 2) return null;

  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const pad = 2;

  const points = data.map((v, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = pad + (1 - (v - min) / range) * (height - pad * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const last = points[points.length - 1].split(",").map(Number);

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} style={{ overflow: "visible" }}>
      <polyline points={points.join(" ")} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" opacity={0.85} />
      <circle cx={last[0]} cy={last[1]} r={2} fill={color} />
    </svg>
  );
}

export function useCountUp(value: number, durationMs = 500): number {
  const [display, setDisplay] = useState(value);
  const fromRef = useRef(value);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduceMotion) {
      setDisplay(value);
      fromRef.current = value;
      return;
    }

    const from = fromRef.current;
    const to = value;
    if (from === to) return;

    const start = performance.now();
    if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);

    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / durationMs);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(from + (to - from) * eased);
      if (t < 1) {
        rafRef.current = requestAnimationFrame(tick);
      } else {
        fromRef.current = to;
      }
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
    };
  }, [value, durationMs]);

  return display;
}

export interface DonutSlice {
  label: string;
  value: number;
  color: string;
}

export function Donut({ slices, size = 132, centerLabel = "flagged" }: { slices: DonutSlice[]; size?: number; centerLabel?: string }) {
  const [hovered, setHovered] = useState<number | null>(null);
  const total = slices.reduce((s, d) => s + d.value, 0);
  const radius = size / 2 - 14;
  const circumference = 2 * Math.PI * radius;
  const gapDeg = total > 0 ? 2 : 0; // 2px-equivalent surface gap between segments

  let cursor = 0;
  const arcs = slices.map((slice, i) => {
    const fraction = total > 0 ? slice.value / total : 0;
    const startDeg = cursor * 360;
    const sweepDeg = Math.max(0, fraction * 360 - gapDeg);
    cursor += fraction;
    return { ...slice, startDeg, sweepDeg, index: i };
  });

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 20, flexWrap: "wrap" }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ overflow: "visible" }}>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="var(--raised)" strokeWidth={14} />
        {arcs.map((arc) => {
          const dash = (arc.sweepDeg / 360) * circumference;
          return (
            <circle
              key={arc.label}
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke={arc.color}
              strokeWidth={hovered === arc.index ? 17 : 14}
              strokeDasharray={`${dash} ${circumference - dash}`}
              strokeDashoffset={-((arc.startDeg / 360) * circumference)}
              strokeLinecap="butt"
              transform={`rotate(-90 ${size / 2} ${size / 2})`}
              style={{ transition: "stroke-width 0.15s ease, opacity 0.4s ease" }}
              tabIndex={0}
              onMouseEnter={() => setHovered(arc.index)}
              onMouseLeave={() => setHovered(null)}
              onFocus={() => setHovered(arc.index)}
              onBlur={() => setHovered(null)}
            >
              <title>{`${arc.label}: ${arc.value}`}</title>
            </circle>
          );
        })}
        <text x="50%" y="47%" textAnchor="middle" fontSize={22} fontWeight={700} fill="var(--text)" fontFamily="var(--mono)">
          {total}
        </text>
        <text x="50%" y="62%" textAnchor="middle" fontSize={9} fill="var(--muted)" style={{ textTransform: "uppercase", letterSpacing: "0.06em" }}>
          {centerLabel}
        </text>
      </svg>

      <div style={{ display: "flex", flexDirection: "column", gap: 7, flex: 1, minWidth: 120 }}>
        {slices.map((s, i) => (
          <div
            key={s.label}
            onMouseEnter={() => setHovered(i)}
            onMouseLeave={() => setHovered(null)}
            style={{
              display: "flex", alignItems: "center", gap: 8, fontSize: 11,
              opacity: hovered === null || hovered === i ? 1 : 0.5, transition: "opacity 0.15s ease",
            }}
          >
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: s.color, flexShrink: 0 }} />
            <span style={{ color: "var(--muted)", flex: 1 }}>{s.label}</span>
            <span style={{ color: "var(--text)", fontFamily: "var(--mono)", fontWeight: 600 }}>{s.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// 270deg arc gauge (gap centered at the bottom) - the "command center" reading for a single
// live 0-100 metric, in place of a flat progress bar. Single value -> no legend needed.
export function RadialGauge({
  value, label, color, size = 168, strokeWidth = 14,
}: {
  value: number;
  label: string;
  color: string;
  size?: number;
  strokeWidth?: number;
}) {
  const radius = size / 2 - strokeWidth;
  const circumference = 2 * Math.PI * radius;
  const arcFraction = 0.75; // 270 of 360 degrees
  const arcLength = circumference * arcFraction;
  const clamped = Math.max(0, Math.min(100, value));
  const progress = arcLength * (clamped / 100);

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <g transform={`rotate(135 ${size / 2} ${size / 2})`}>
        <circle
          cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="var(--raised)"
          strokeWidth={strokeWidth} strokeLinecap="round"
          strokeDasharray={`${arcLength} ${circumference - arcLength}`}
        />
        <circle
          cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color}
          strokeWidth={strokeWidth} strokeLinecap="round"
          strokeDasharray={`${progress} ${circumference - progress}`}
          style={{ transition: "stroke-dasharray 0.6s ease, stroke 0.4s ease" }}
        />
      </g>
      <text x="50%" y="49%" textAnchor="middle" fontSize={size * 0.24} fontWeight={700} fill="var(--text)" fontFamily="var(--mono)">
        {Math.round(clamped)}
      </text>
      <text x="50%" y="65%" textAnchor="middle" fontSize={11} fontWeight={700} fill={color} style={{ textTransform: "uppercase", letterSpacing: "0.08em" }}>
        {label}
      </text>
    </svg>
  );
}

export interface TrendPoint {
  t: string;
  value: number;
}

export function TrendChart({
  data, color = "var(--blue)", height = 96, formatValue = (v: number) => String(Math.round(v)),
}: {
  data: TrendPoint[];
  color?: string;
  height?: number;
  formatValue?: (v: number) => string;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const width = 320;
  const padX = 4;
  const padY = 10;

  if (data.length < 2) {
    return (
      <div style={{ height, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--dim)", fontSize: 11 }}>
        Gathering data...
      </div>
    );
  }

  const values = data.map((d) => d.value);
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const range = max - min || 1;

  const points = data.map((d, i) => {
    const x = padX + (i / (data.length - 1)) * (width - padX * 2);
    const y = padY + (1 - (d.value - min) / range) * (height - padY * 2);
    return { x, y, ...d };
  });

  const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(" ");
  const areaPath = `${linePath} L ${points[points.length - 1].x.toFixed(1)} ${height - padY} L ${points[0].x.toFixed(1)} ${height - padY} Z`;
  const baselineY = padY + (1 - (0 - min) / range) * (height - padY * 2);

  const active = hover !== null ? points[hover] : points[points.length - 1];

  return (
    <div style={{ position: "relative" }}>
      <svg
        width="100%"
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        onMouseLeave={() => setHover(null)}
        onMouseMove={(e) => {
          const rect = e.currentTarget.getBoundingClientRect();
          const relX = ((e.clientX - rect.left) / rect.width) * width;
          let nearest = 0;
          let best = Infinity;
          points.forEach((p, i) => {
            const d = Math.abs(p.x - relX);
            if (d < best) { best = d; nearest = i; }
          });
          setHover(nearest);
        }}
      >
        {min < 0 && max > 0 && (
          <line x1={0} y1={baselineY} x2={width} y2={baselineY} stroke="var(--border)" strokeWidth={1} />
        )}
        <path d={areaPath} fill={color} opacity={0.1} stroke="none" />
        <path d={linePath} fill="none" stroke={color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        {hover !== null && (
          <line x1={active.x} y1={padY} x2={active.x} y2={height - padY} stroke="var(--border)" strokeWidth={1} />
        )}
        <circle cx={active.x} cy={active.y} r={4} fill={color} stroke="var(--surf-solid)" strokeWidth={2} />
      </svg>

      {hover !== null && (
        <div
          style={{
            position: "absolute", top: 4, pointerEvents: "none",
            left: `${Math.min(78, Math.max(2, (active.x / width) * 100))}%`,
            background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 5,
            padding: "4px 8px", fontSize: 11, whiteSpace: "nowrap",
          }}
        >
          <span style={{ color: "var(--text)", fontWeight: 700, fontFamily: "var(--mono)" }}>{formatValue(active.value)}</span>
          <span style={{ color: "var(--muted)", marginLeft: 6 }}>{active.t}</span>
        </div>
      )}
    </div>
  );
}
