// graph/load.js
//
// Load the dependency graph into FalkorDB, and read it back.
// Inputs are public: SAMPLE (offline demo tree) or a real npm lockfile,
// plus the OSV API (api.osv.dev, no key) for live advisories.
//
// FalkorDB's named-parameter binding is unreliable from raw RESP, so we pass
// values as escaped Cypher string literals (see q()). All values are package
// names / semver constraints / advisory ids — escaped safely before use.

import { Falkor, q } from "./falkor.js";
import { SAMPLE, SCHEMA_STATEMENTS } from "./schema.js";

export const falkor = () => new Falkor();

// Run a statement, return rows as objects keyed by column name.
export async function rows(stmt) {
  const f = falkor();
  const res = await f.query(stmt);
  return toRows(res);
}

// FalkorDB reply: [ [col1,col2,...], [[v1,v2],...], [stats...] ]
export function toRows(res) {
  if (!Array.isArray(res)) return [];
  const header = Array.isArray(res[0]) ? res[0] : [];
  const data = Array.isArray(res[1]) ? res[1] : [];
  return data.map((row) => {
    const o = {};
    header.forEach((h, i) => (o[h] = Array.isArray(row) ? row[i] : row));
    return o;
  });
}

export async function reset() {
  const f = falkor();
  for (const s of SCHEMA_STATEMENTS) { try { await f.query(s); } catch { /* exists */ } }
  await f.query("MATCH (n) DETACH DELETE n");
}

export async function loadSample() {
  await reset();
  const f = falkor();
  for (const p of SAMPLE.packages) {
    await f.query(`MERGE (p:Package {name:${q(p.name)}})`);
    for (const v of p.versions || []) {
      await f.query(
        `MATCH (p:Package {name:${q(p.name)}}) ` +
        `MERGE (p)-[:HAS_VERSION]->(:Version {version:${q(v)}, pkg:${q(p.name)}})`);
    }
  }
  for (const [parent, child, constraint] of SAMPLE.edges) {
    await f.query(
      `MATCH (a:Package {name:${q(parent)}}), (b:Package {name:${q(child)}}) ` +
      `MERGE (a)-[:DEPENDS_ON {constraint:${q(constraint)}}]->(b)`);
  }
  for (const a of SAMPLE.advisories) {
    await f.query(
      `MERGE (adv:Advisory {id:${q(a.id)}, severity:${q(a.severity)}, summary:${q(a.summary)}})`);
    await f.query(
      `MATCH (adv:Advisory {id:${q(a.id)}}), (p:Package {name:${q(a.pkg)}}) ` +
      `MERGE (adv)-[:AFFECTS {introduced:${q(a.introduced)}, fixed:${q(a.fixed)}}]->(p)`);
  }
  return { packages: SAMPLE.packages.length, edges: SAMPLE.edges.length, advisories: SAMPLE.advisories.length };
}

// Pull live advisories from OSV for one package (public API, no key).
export async function fetchOSV(name, ecosystem = "npm") {
  const r = await fetch("https://api.osv.dev/v1/query", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ package: { name, ecosystem } }),
  });
  const j = await r.json();
  return (j.vulns || []).map((v) => ({
    id: v.id,
    severity: (v.severity?.[0]?.score) || "unknown",
    summary: v.summary || "",
    affected: v.affected || [],
  }));
}
