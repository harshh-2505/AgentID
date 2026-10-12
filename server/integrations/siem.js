// Ships authority events to a SIEM in batches.
//
//   attachSiem(authority, { kind, url, token, batchMs })
//     kind 'webhook'     JSON lines (application/x-ndjson), Authorization: Bearer <token> if given
//     kind 'splunk-hec'  HEC event format, Authorization: Splunk <token>; url is the
//                        collector endpoint, e.g. https://splunk:8088/services/collector/event
//     kind 'otlp'        OTLP/HTTP JSON logs; url is the collector's /v1/logs
//
// Delivery is at-least-once within a bounded queue: failed batches are retried with
// exponential backoff, then put back at the head of the queue. When the queue is full the
// oldest records are dropped and counted, so a dead sink never grows memory without bound.
// The ledger stays the source of truth; every record carries ledgerSeq where one exists.

import os from 'node:os';
import { fetchPoster } from './slack.js';

const DEFAULT_EVENTS = ['decision', 'approval', 'revoked', 'freeze', 'federation', 'witness'];
const SEVERITY = { INFO: 9, WARN: 13, ERROR: 17 };

// Flattens one authority event into the record every format starts from.
export function toRecord({ type, data }, { authority, ts = Date.now() } = {}) {
  if (type === 'decision') {
    const { receipt, checks, ...d } = data;
    return {
      ts: d.ts ?? ts, type, authority, decision: d.decision, failedAt: d.failedAt ?? undefined,
      agent: d.agent, agentName: d.agentName, action: d.action, resource: d.resource, params: d.params,
      reason: d.reason, risk: d.risk?.score, riskFactors: d.risk?.factors?.map((f) => f.label),
      approvalId: d.approvalId ?? undefined, via: d.via ?? undefined, ledgerSeq: d.ledgerSeq,
      decisionId: d.id, intentHash: d.intentHash, receipt: !!receipt,
      failedDetail: d.failedAt ? checks?.find((c) => c.key === d.failedAt)?.detail : undefined,
    };
  }
  return { ts, type, authority, ...data };
}

function severityOf(r) {
  if (r.type === 'decision') return r.decision === 'allow' ? 'INFO' : r.decision === 'step_up' ? 'WARN' : 'ERROR';
  if (r.type === 'revoked' || r.type === 'freeze' || (r.type === 'federation' && r.ok === false)) return 'WARN';
  return 'INFO';
}

function summary(r) {
  if (r.type === 'decision') return `${r.decision} ${r.action} on ${r.resource} by ${r.agentName || r.agent}${r.failedAt ? ` (failed at ${r.failedAt})` : ''}`;
  if (r.type === 'approval') return `approval ${r.id} ${r.status}`;
  if (r.type === 'revoked') return `revoked ${r.target}`;
  if (r.type === 'freeze') return `principal ${r.principal} ${r.frozen ? 'frozen' : 'unfrozen'}`;
  return r.type;
}

// OTLP AnyValue. 64-bit ints are strings in OTLP/JSON.
function anyValue(v) {
  if (typeof v === 'boolean') return { boolValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { intValue: String(v) } : { doubleValue: v };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(anyValue) } };
  if (v && typeof v === 'object') return { kvlistValue: { values: Object.entries(v).filter(([, x]) => x !== undefined && x !== null).map(([key, x]) => ({ key, value: anyValue(x) })) } };
  return { stringValue: String(v) };
}

export const formats = {
  webhook: (records, { token }) => ({
    headers: { 'content-type': 'application/x-ndjson', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: records.map((r) => JSON.stringify(r)).join('\n') + '\n',
  }),
  // HEC accepts several event objects concatenated in one request body.
  'splunk-hec': (records, { token, host, index }) => ({
    headers: { 'content-type': 'application/json', authorization: `Splunk ${token}` },
    body: records.map((r) => JSON.stringify({ time: r.ts / 1000, host, source: 'agentid', sourcetype: `agentid:${r.type}`, index, event: r })).join('\n'),
  }),
  otlp: (records, { token, host, authority, headers = {} }) => ({
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
    body: JSON.stringify({
      resourceLogs: [{
        resource: { attributes: [
          { key: 'service.name', value: { stringValue: 'agentid' } },
          { key: 'host.name', value: { stringValue: host } },
          ...(authority ? [{ key: 'agentid.authority', value: { stringValue: authority } }] : []),
        ] },
        scopeLogs: [{
          scope: { name: 'agentid.authority', version: '1' },
          logRecords: records.map((r) => {
            const sev = severityOf(r);
            const { ts, ...rest } = r;
            return {
              timeUnixNano: (BigInt(Math.round(ts)) * 1_000_000n).toString(),
              observedTimeUnixNano: (BigInt(Date.now()) * 1_000_000n).toString(),
              severityNumber: SEVERITY[sev],
              severityText: sev,
              body: { stringValue: summary(r) },
              attributes: Object.entries(rest).filter(([, v]) => v !== undefined && v !== null).map(([k, v]) => ({ key: 'agentid.' + k, value: anyValue(v) })),
            };
          }),
        }],
      }],
    }),
  }),
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// options: kind, url, token, batchMs = 2000, maxBatch = 200, maxQueue = 10000, retries = 4,
// backoffMs = 500, events (types to ship, or ['*']), host, index (Splunk), headers (OTLP),
// post (injectable HTTP poster), onError.
export function attachSiem(authority, opts) {
  const { kind, url, batchMs = 2000, maxBatch = 200, maxQueue = 10_000, retries = 4, backoffMs = 500, post = fetchPoster, onError } = opts;
  const format = formats[kind];
  if (!format) throw new Error(`unknown SIEM kind ${kind}; use webhook, splunk-hec or otlp`);
  if (!url) throw new Error('SIEM url is required');
  if (kind === 'splunk-hec' && !opts.token) throw new Error('Splunk HEC needs a token');
  const events = opts.events || DEFAULT_EVENTS;
  const fmtOpts = { token: opts.token, host: opts.host || os.hostname(), index: opts.index, headers: opts.headers, authority: authority.did };
  const queue = [];
  const stats = { queued: 0, sent: 0, batches: 0, dropped: 0, retried: 0, failed: 0 };
  let sending = null;
  let stopped = false;

  const enqueue = (records) => {
    queue.push(...records);
    const over = queue.length - maxQueue;
    if (over > 0) { queue.splice(0, over); stats.dropped += over; }
  };

  const unsubscribe = authority.on((ev) => {
    if (stopped || !(events.includes('*') || events.includes(ev.type))) return;
    try { enqueue([toRecord(ev, { authority: authority.did })]); stats.queued++; } catch (e) { onError?.(e); }
    if (queue.length >= maxBatch) flush();
  });

  async function sendBatch(batch) {
    const { headers, body } = format(batch, fmtOpts);
    for (let attempt = 0; ; attempt++) {
      let res;
      try { res = await post(url, { method: 'POST', headers, body }); } catch (e) { res = { ok: false, status: 0, error: e }; }
      if (res.ok) return true;
      // 4xx other than 408/429 means the sink rejected the payload or credentials; retrying won't help.
      if (res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 429) {
        stats.failed += batch.length;
        onError?.(new Error(`SIEM ${kind} rejected batch: HTTP ${res.status}`));
        return true;
      }
      if (attempt >= retries || stopped) return false;
      stats.retried++;
      await sleep(backoffMs * 2 ** attempt * (0.75 + Math.random() / 2));
    }
  }

  function flush() {
    if (sending) return sending;
    sending = (async () => {
      try {
        while (queue.length) {
          const batch = queue.splice(0, maxBatch);
          if (await sendBatch(batch)) {
            stats.sent += batch.length;
            stats.batches++;
          } else {
            // Put it back at the head; enqueue's bound still applies via drop-oldest.
            queue.unshift(...batch);
            const over = queue.length - maxQueue;
            if (over > 0) { queue.splice(0, over); stats.dropped += over; }
            onError?.(new Error(`SIEM ${kind} unreachable; ${queue.length} records queued`));
            break;
          }
        }
      } finally {
        sending = null;
      }
    })();
    return sending;
  }

  const timer = setInterval(() => { if (queue.length) flush(); }, batchMs);
  timer.unref?.();

  return {
    flush,
    stats,
    get pending() { return queue.length; },
    async stop({ drain = true } = {}) {
      unsubscribe();
      clearInterval(timer);
      if (drain) { await sending; await flush(); }
      stopped = true;
    },
  };
}

export function siemConfigFromEnv(env = process.env) {
  if (!env.SIEM_URL) return null;
  return {
    kind: env.SIEM_KIND || 'webhook',
    url: env.SIEM_URL,
    token: env.SIEM_TOKEN,
    batchMs: env.SIEM_BATCH_MS ? Number(env.SIEM_BATCH_MS) : undefined,
    index: env.SIEM_INDEX,
    events: env.SIEM_EVENTS ? env.SIEM_EVENTS.split(',').map((s) => s.trim()) : undefined,
  };
}
