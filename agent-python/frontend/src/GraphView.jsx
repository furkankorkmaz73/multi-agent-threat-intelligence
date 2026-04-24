import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";

function inferNodeType(id, rootId) {
  if (id === rootId) return "root";
  if (id.startsWith("cve:")) return "cve";
  if (id.startsWith("urlhaus:") || id.startsWith("url:")) return "ioc";
  if (id.startsWith("dread:")) return "dread";
  if (id.startsWith("tag:")) return "tag";
  if (id.startsWith("keyword:")) return "keyword";
  if (id.startsWith("product:")) return "product";
  if (id.startsWith("threat:")) return "threat";
  if (id.startsWith("status:")) return "status";
  if (id.startsWith("cvss:")) return "cvss";
  if (id.startsWith("time:")) return "time";
  return "other";
}

function nodeColor(type) {
  switch (type) {
    case "root":
      return "#60a5fa";
    case "cve":
      return "#f97316";
    case "ioc":
      return "#ef4444";
    case "dread":
      return "#a855f7";
    case "tag":
      return "#22c55e";
    case "keyword":
      return "#94a3b8";
    case "product":
      return "#facc15";
    case "threat":
      return "#fb7185";
    case "status":
      return "#38bdf8";
    case "cvss":
      return "#f59e0b";
    case "time":
      return "#10b981";
    default:
      return "#cbd5e1";
  }
}

function shorten(label, max = 24) {
  if (!label) return "";
  return label.length > max ? `${label.slice(0, max)}…` : label;
}

export default function GraphView({ entityId, source, edges }) {
  const containerRef = useRef(null);
  const [size, setSize] = useState({ width: 900, height: 460 });

  useEffect(() => {
    if (!containerRef.current) return undefined;

    const updateSize = () => {
      const width = Math.max(320, containerRef.current?.clientWidth || 900);
      setSize({ width, height: 460 });
    };

    updateSize();
    const observer = new ResizeObserver(updateSize);
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  const graphData = useMemo(() => {
    if (!edges?.length || !entityId || !source) {
      return { nodes: [], links: [] };
    }

    const rootId = `${source}:${entityId}`;
    const nodeMap = new Map();

    nodeMap.set(rootId, {
      id: rootId,
      label: entityId,
      type: "root",
    });

    const links = edges.map((edge, idx) => {
      if (!nodeMap.has(edge.source)) {
        nodeMap.set(edge.source, {
          id: edge.source,
          label: edge.source,
          type: inferNodeType(edge.source, rootId),
        });
      }

      if (!nodeMap.has(edge.target)) {
        nodeMap.set(edge.target, {
          id: edge.target,
          label: edge.target,
          type: inferNodeType(edge.target, rootId),
        });
      }

      return {
        id: `${edge.source}-${edge.target}-${idx}`,
        source: edge.source,
        target: edge.target,
        relation: edge.relation || "related_to",
        weight: edge.weight ?? 1,
        confidence: edge.confidence ?? 0.5,
      };
    });

    return {
      nodes: Array.from(nodeMap.values()),
      links,
    };
  }, [edges, entityId, source]);

  if (!graphData.nodes.length) {
    return <div style={{ color: "#9ca3af" }}>No graph visualization available.</div>;
  }

  return (
    <div
      ref={containerRef}
      style={{
        width: "100%",
        height: 460,
        minWidth: 0,
        background: "linear-gradient(180deg, rgba(2,6,23,0.9), rgba(8,15,28,0.96))",
        border: "1px solid rgba(148,163,184,0.12)",
        borderRadius: 18,
        overflow: "hidden",
      }}
    >
      <ForceGraph2D
        width={size.width}
        height={size.height}
        graphData={graphData}
        backgroundColor="#030712"
        nodeRelSize={6}
        cooldownTicks={100}
        d3VelocityDecay={0.25}
        linkWidth={(link) => Math.max(1, Number(link.weight || 1))}
        linkColor={(link) =>
          Number(link.confidence || 0.5) >= 0.75
            ? "rgba(96,165,250,0.55)"
            : "rgba(148,163,184,0.28)"
        }
        nodeCanvasObject={(node, ctx, globalScale) => {
          const label = shorten(node.label || node.id);
          const fontSize = Math.max(10 / globalScale, 4);
          const radius = node.type === "root" ? 7 : 5;

          ctx.beginPath();
          ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false);
          ctx.fillStyle = nodeColor(node.type);
          ctx.shadowBlur = node.type === "root" ? 12 : 0;
          ctx.shadowColor = nodeColor(node.type);
          ctx.fill();
          ctx.shadowBlur = 0;

          ctx.font = `${fontSize}px Sans-Serif`;
          ctx.fillStyle = "#e5e7eb";
          ctx.fillText(label, node.x + 9, node.y + 3);
        }}
        linkDirectionalParticles={(link) => (Number(link.confidence || 0.5) >= 0.75 ? 2 : 1)}
        linkDirectionalParticleWidth={(link) => (Number(link.confidence || 0.5) >= 0.75 ? 1.8 : 1.1)}
        enableNodeDrag
      />
    </div>
  );
}
