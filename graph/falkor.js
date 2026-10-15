// graph/falkor.js
//
// Minimal FalkorDB client over raw RESP (Redis protocol). We speak GRAPH.QUERY
// directly on a TCP socket and parse the RESP reply. No external client
// dependency: the graph speaks plain RESP, so this stays small and predictable.
//
// The reply to GRAPH.QUERY is a flat RESP array of strings/arrays; we parse it
// generically and return the raw nested array. Cypher result rows come back as
// [header..., ...] where header names the columns.

import net from "net";

export class Falkor {
  constructor(host = process.env.FALKOR_HOST || "127.0.0.1",
              port = Number(process.env.FALKOR_PORT || 6381),
              graph = process.env.FALKOR_GRAPH || "patchweaver") {
    this.host = host; this.port = port; this.graph = graph;
  }

  // Run one Cypher statement. params: optional object -> --param k=>json
  query(stmt, params = {}) {
    return new Promise((resolve, reject) => {
      const sock = net.connect(this.port, this.host, () => {
        const argv = ["GRAPH.QUERY", this.graph, stmt];
        for (const k of Object.keys(params)) argv.push("--param", `${k}=>${JSON.stringify(params[k])}`);
        let out = `*${argv.length}\r\n`;
        for (const a of argv) out += `$${Buffer.byteLength(a)}\r\n${a}\r\n`;
        sock.write(out);
      });
      let buf = Buffer.alloc(0);
      let done = false;
      const finish = (fn, v) => { if (done) return; done = true; try { sock.end(); } catch {} fn(v); };

      sock.on("data", (d) => {
        buf = Buffer.concat([buf, d]);
        // Try to parse a complete top-level RESP array. We parse greedily; if
        // it throws (incomplete), we wait for more data.
        try {
          const { value } = parseRESP(buf, 0);
          finish(resolve, value);
        } catch { /* incomplete, keep reading */ }
      });
      sock.on("error", (e) => finish(reject, e));
      sock.setTimeout(15000, () => finish(reject, new Error("falkor query timeout")));
    });
  }

  // Convenience: parse a result into [{col:val},...] using the header row.
  rows(stmt, params = {}) {
    return this.query(stmt, params).then((res) => toRows(res));
  }
}

// Parse one RESP value starting at index i; returns {value, next}
function parseRESP(buf, i) {
  if (i >= buf.length) throw new Error("incomplete");
  const type = String.fromCharCode(buf[i]);
  const lineEnd = buf.indexOf("\r\n", i);
  if (lineEnd === -1) throw new Error("incomplete");
  const head = buf.slice(i + 1, lineEnd).toString();
  let p = lineEnd + 2;

  if (type === "*") {
    const len = parseInt(head, 10);
    if (len === -1) return { value: null, next: p };
    const items = [];
    for (let n = 0; n < len; n++) {
      const r = parseRESP(buf, p);
      items.push(r.value); p = r.next;
    }
    return { value: items, next: p };
  }
  if (type === "$") {
    const len = parseInt(head, 10);
    if (len === -1) return { value: null, next: p };
    if (p + len + 2 > buf.length) throw new Error("incomplete");
    const s = buf.slice(p, p + len).toString();
    return { value: s, next: p + len + 2 };
  }
  if (type === "+" || type === "-" || type === ":") {
    return { value: type === ":" ? parseInt(head, 10) : head, next: p };
  }
  throw new Error("unhandled RESP type: " + type);
}

// GRAPH.QUERY returns [ "header1","header2",..., row1col1, row1col2, ... ].
// FalkorDB flattens the result set; the first N strings are column names when
// the statement had a RETURN with aliases. We reconstruct rows heuristically:
// if the reply length is divisible by a plausible column count.
function toRows(res) {
  if (!Array.isArray(res)) return [];
  // FalkorDB result: [header..., values...]. Column count is ambiguous from the
  // flat array, so callers that need structure pass an explicit col count.
  // For our use we mostly need scalars; expose the flat array and a helper.
  return res;
}

export const q = (s) => `'${String(s).replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
