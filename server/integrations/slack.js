// Co-sign from Slack: a held request becomes a Block Kit message with Approve / Decline
// buttons; a click comes back to POST /integrations/slack/actions, is checked against
// Slack's request signature and an allow-list of approvers, and is turned into a CoSign.
//
// config.slack:
//   signingSecret   Slack app signing secret (verifies every interaction)
//   approvers       { <Slack user id>: { key: 'approver' | 'operational' | 'root', ...anything cosign needs } }
//   webhookUrl      incoming webhook, or botToken + channel for chat.postMessage
//   cosign          async (approvalId, decision, approver, { slackUser }) => result   (production;
//                   without it the demo world signs with approver.key)
//   consoleUrl      optional link shown on each message
//   post            optional HTTP poster (url, { method, headers, body }) => { ok, status, text }
//
// Slack ids are not keys: a Slack account is only mapped to a signing key the operator
// chose. The CoSign itself is still made by a principal key, so the ledger records it.

import { createHmac, timingSafeEqual } from 'node:crypto';

const TOLERANCE_SEC = 300;
const httpError = (status, message) => Object.assign(new Error(message), { status });

export async function fetchPoster(url, { method = 'POST', headers = {}, body } = {}) {
  const res = await fetch(url, { method, headers, body });
  return { ok: res.ok, status: res.status, text: await res.text() };
}

// Agent-supplied text (reason, resource) is untrusted: escape it so it cannot @channel,
// fake a link, or break out of the formatting. Slack only needs &, < and > escaped.
const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const clip = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
const money = (ap) => (ap.amount ? `${Number(ap.amount).toLocaleString('en-US', { maximumFractionDigits: 2 })} ${ap.params?.currency || ''}`.trim() : '—');

export function approvalBlocks(ap, { result, actor, error, consoleUrl } = {}) {
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: clip(`Co-sign needed: ${ap.agentName || 'agent'}`, 150) } },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*Action*\n\`${esc(ap.action)}\`` },
        { type: 'mrkdwn', text: `*Resource*\n\`${esc(clip(String(ap.resource), 200))}\`` },
        { type: 'mrkdwn', text: `*Amount*\n${esc(money(ap))}` },
        { type: 'mrkdwn', text: `*Risk score*\n${ap.risk?.score ?? '—'}` },
      ],
    },
    { type: 'section', text: { type: 'mrkdwn', text: `*Agent's reason*\n>${esc(clip(ap.reason || '(none given)', 600))}` } },
    { type: 'section', text: { type: 'mrkdwn', text: `*Why it was held*\n${(ap.reasons || []).map((r) => '• ' + esc(r)).join('\n') || '—'}` } },
  ];
  const factors = ap.risk?.factors || [];
  if (factors.length) blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: clip('Risk factors: ' + factors.map((f) => `${esc(f.label)} (+${f.points})`).join(' · '), 2900) }] });

  if (result || error) {
    const text = error
      ? `:warning: ${esc(error)}`
      : result.status === 'approved' ? `:white_check_mark: *Approved* by <@${actor}> — allowed${result.decision?.ledgerSeq !== undefined ? `, ledger #${result.decision.ledgerSeq}` : ''}`
      : result.status === 'declined' ? `:no_entry: *Declined* by <@${actor}>${result.decision?.ledgerSeq !== undefined ? `, ledger #${result.decision.ledgerSeq}` : ''}`
      : `:hourglass: <@${actor}> responded; ${result.signatures ?? ''} signature(s), waiting for quorum`;
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text } });
  }
  if (!result || result.status === 'pending' || error) {
    blocks.push({
      type: 'actions',
      block_id: 'agentid_cosign',
      elements: [
        { type: 'button', action_id: 'agentid_approve', style: 'primary', text: { type: 'plain_text', text: 'Approve' }, value: ap.id,
          confirm: { title: { type: 'plain_text', text: 'Approve this request?' }, text: { type: 'mrkdwn', text: `Your key will co-sign \`${esc(ap.action)}\` on \`${esc(clip(String(ap.resource), 120))}\`.` }, confirm: { type: 'plain_text', text: 'Approve' }, deny: { type: 'plain_text', text: 'Cancel' } } },
        { type: 'button', action_id: 'agentid_decline', style: 'danger', text: { type: 'plain_text', text: 'Decline' }, value: ap.id },
      ],
    });
  }
  const ctxLine = [`Approval \`${ap.id}\``];
  if (ap.expiresAt) ctxLine.push(`expires <!date^${Math.floor(ap.expiresAt / 1000)}^{time}|${new Date(ap.expiresAt).toISOString()}>`);
  if (consoleUrl) ctxLine.push(`<${consoleUrl}|Open console>`);
  blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: ctxLine.join(' · ') }] });
  return blocks;
}

const fallbackText = (ap) => `Co-sign needed: ${ap.agentName} wants ${ap.action} on ${ap.resource}${ap.amount ? ' for ' + money(ap) : ''}`;

export async function postApprovalMessage(ap, { webhookUrl, botToken, channel, consoleUrl, post = fetchPoster } = {}) {
  const message = { text: fallbackText(ap), blocks: approvalBlocks(ap, { consoleUrl }) };
  if (webhookUrl) {
    const res = await post(webhookUrl, { headers: { 'content-type': 'application/json' }, body: JSON.stringify(message) });
    if (!res.ok) throw new Error(`Slack webhook returned ${res.status}`);
    return res;
  }
  if (botToken && channel) {
    const res = await post('https://slack.com/api/chat.postMessage', {
      headers: { 'content-type': 'application/json; charset=utf-8', authorization: `Bearer ${botToken}` },
      body: JSON.stringify({ channel, ...message }),
    });
    // chat.postMessage reports errors in a 200 body.
    let data = {};
    try { data = JSON.parse(res.text || '{}'); } catch { /* not JSON */ }
    if (!res.ok || data.ok === false) throw new Error(`Slack chat.postMessage failed: ${data.error || res.status}`);
    return res;
  }
  throw new Error('Slack needs webhookUrl, or botToken and channel');
}

// Posts a message for each newly pending approval. Returns an unsubscribe function.
export function attachSlack(authority, config = {}) {
  const cfg = config.slack || config;
  const seen = new Set();
  return authority.on(async ({ type, data }) => {
    // 'approval' pending also fires when one guardian of a quorum signs; post only once.
    if (type !== 'approval' || data?.status !== 'pending' || seen.has(data.id)) return;
    seen.add(data.id);
    if (seen.size > 5000) seen.delete(seen.values().next().value);
    try {
      const ap = await authority.approval(data.id);
      if (ap?.status === 'pending') await postApprovalMessage(ap, cfg);
    } catch (e) {
      cfg.onError?.(e);
    }
  });
}

// Slack request signing v0: HMAC-SHA256 over "v0:{timestamp}:{raw body}".
export function verifySlackSignature({ signingSecret, timestamp, signature, rawBody, nowSec = Math.floor(Date.now() / 1000), toleranceSec = TOLERANCE_SEC }) {
  if (!signingSecret) return { ok: false, reason: 'Slack signing secret is not configured' };
  if (!timestamp || !signature) return { ok: false, reason: 'missing Slack signature headers' };
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(nowSec - ts) > toleranceSec) return { ok: false, reason: 'stale Slack request' };
  const expected = Buffer.from('v0=' + createHmac('sha256', signingSecret).update(`v0:${timestamp}:`).update(rawBody ?? '').digest('hex'));
  const given = Buffer.from(String(signature));
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return { ok: false, reason: 'bad Slack signature' };
  return { ok: true };
}

const header = (req, name) => {
  const v = req?.headers?.[name] ?? req?.headers?.[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
};

export function routes(ctx) {
  return [
    ['POST', '/integrations/slack/actions', async (body, _params, _query, req) => {
      const cfg = ctx.config?.slack || {};
      const rawBody = req?.rawBody ?? Buffer.from('');
      const sig = verifySlackSignature({
        signingSecret: cfg.signingSecret,
        timestamp: header(req, 'x-slack-request-timestamp'),
        signature: header(req, 'x-slack-signature'),
        rawBody,
        nowSec: Math.floor((cfg.now?.() ?? Date.now()) / 1000),
      });
      if (!sig.ok) throw httpError(401, sig.reason);

      const form = body?.payload ? body : Object.fromEntries(new URLSearchParams(rawBody.toString('utf8')));
      let payload;
      try { payload = JSON.parse(form.payload); } catch { throw httpError(400, 'payload is not JSON'); }
      if (payload.type !== 'block_actions') return { ok: true, ignored: payload.type };
      const action = payload.actions?.find((a) => a.action_id === 'agentid_approve' || a.action_id === 'agentid_decline');
      if (!action) return { ok: true, ignored: 'no AgentID action' };
      const decision = action.action_id === 'agentid_approve' ? 'approve' : 'decline';
      const approvalId = action.value;
      const user = payload.user?.id;
      const post = cfg.post || fetchPoster;
      // Interaction responses are delivered through response_url; the HTTP body is just the ack.
      const respond = async (msg) => {
        if (payload.response_url) {
          try { await post(payload.response_url, { headers: { 'content-type': 'application/json' }, body: JSON.stringify(msg) }); } catch (e) { cfg.onError?.(e); }
        }
        return msg;
      };

      const approver = cfg.approvers?.[user];
      if (!approver) return respond({ response_type: 'ephemeral', replace_original: false, text: `<@${user}> is not an approver for AgentID co-signs.` });

      const ap = await ctx.authority().approval(approvalId);
      if (!ap) return respond({ response_type: 'ephemeral', replace_original: false, text: `Approval ${esc(approvalId)} was not found.` });

      let result;
      try {
        if (cfg.cosign) result = await cfg.cosign(approvalId, decision, approver, { slackUser: user, payload });
        else if (ctx.world?.()) result = await ctx.world().approve(approvalId, decision, { key: approver.key });
        else throw new Error('no co-sign backend configured (config.slack.cosign)');
      } catch (e) {
        const fresh = (await ctx.authority().approval(approvalId)) || ap;
        // Already closed elsewhere: show the final state, without buttons.
        if (fresh.status !== 'pending') {
          return respond({ replace_original: true, text: `Request is already ${fresh.status}`, blocks: approvalBlocks(fresh, { result: { status: fresh.status }, actor: user, error: `Already ${fresh.status}: ${e.message}`, consoleUrl: cfg.consoleUrl }).filter((b) => b.type !== 'actions') });
        }
        return respond({ response_type: 'ephemeral', replace_original: false, text: `Could not record your ${decision}: ${esc(e.message)}` });
      }
      const text = result.status === 'pending' ? `Recorded <@${user}>'s ${decision}` : `${result.status === 'approved' ? 'Approved' : 'Declined'} by <@${user}>`;
      return respond({ replace_original: true, text, blocks: approvalBlocks(ap, { result, actor: user, consoleUrl: cfg.consoleUrl }) });
    }],
  ];
}

export function slackConfigFromEnv(env = process.env) {
  if (!env.SLACK_SIGNING_SECRET && !env.SLACK_WEBHOOK_URL && !env.SLACK_BOT_TOKEN) return null;
  return {
    signingSecret: env.SLACK_SIGNING_SECRET,
    webhookUrl: env.SLACK_WEBHOOK_URL,
    botToken: env.SLACK_BOT_TOKEN,
    channel: env.SLACK_CHANNEL,
    consoleUrl: env.AGENTID_CONSOLE_URL,
    approvers: env.SLACK_APPROVERS ? JSON.parse(env.SLACK_APPROVERS) : {},
  };
}
