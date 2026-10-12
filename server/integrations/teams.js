// Co-sign from Microsoft Teams: an Adaptive Card per held request, posted through an
// incoming webhook (or a Workflows "post to channel" URL), and a route that accepts the
// card's Action.Execute invoke.
//
// Scope: this is the card builder, the poster and a route stub. Buttons on cards posted
// by an incoming webhook are display-only; for clickable co-sign, register a bot and point
// its messaging endpoint at POST /integrations/teams/actions. A production bot MUST
// validate the Bot Framework JWT in the Authorization header (issuer, audience = your
// bot's app id, signing keys from the Bot Framework OpenID metadata). The shared-secret
// header checked here only stands in for that in development and behind a trusted relay.
//
// config.teams:
//   webhookUrl     where cards are posted
//   sharedSecret   value expected in the x-agentid-teams-secret header
//   approvers      { <AAD object id or Teams user id>: { key: 'approver', ... } }
//   cosign         async (approvalId, decision, approver, { teamsUser }) => result  (production)
//   consoleUrl, post, onError   as for Slack

import { timingSafeEqual } from 'node:crypto';
import { fetchPoster } from './slack.js';

const httpError = (status, message) => Object.assign(new Error(message), { status });
const money = (ap) => (ap.amount ? `${Number(ap.amount).toLocaleString('en-US', { maximumFractionDigits: 2 })} ${ap.params?.currency || ''}`.trim() : '—');

// `action` is 'Execute' (Universal Actions, needs a bot) or 'Submit' (classic bot messages).
export function approvalCard(ap, { action = 'Execute', consoleUrl, result } = {}) {
  const button = (title, decision, style) => (action === 'Execute'
    ? { type: 'Action.Execute', title, verb: 'agentid_' + decision, style, data: { approvalId: ap.id, decision } }
    : { type: 'Action.Submit', title, style, data: { agentid: true, approvalId: ap.id, decision } });
  const body = [
    { type: 'TextBlock', size: 'Medium', weight: 'Bolder', wrap: true, text: `Co-sign needed: ${ap.agentName || 'agent'}` },
    {
      type: 'FactSet',
      facts: [
        { title: 'Action', value: String(ap.action) },
        { title: 'Resource', value: String(ap.resource) },
        { title: 'Amount', value: money(ap) },
        { title: 'Risk score', value: String(ap.risk?.score ?? '—') },
        { title: 'Approval', value: ap.id },
      ],
    },
    { type: 'TextBlock', wrap: true, weight: 'Bolder', text: 'Agent\'s reason', spacing: 'Medium' },
    // Adaptive Cards render a Markdown subset; the reason is agent-written, so show it plain.
    { type: 'RichTextBlock', inlines: [{ type: 'TextRun', text: ap.reason || '(none given)', italic: true }] },
    { type: 'TextBlock', wrap: true, weight: 'Bolder', text: 'Why it was held', spacing: 'Medium' },
    { type: 'RichTextBlock', inlines: [{ type: 'TextRun', text: (ap.reasons || []).join('\n') || '—' }] },
  ];
  if (ap.risk?.factors?.length) {
    body.push({ type: 'RichTextBlock', inlines: [{ type: 'TextRun', isSubtle: true, size: 'Small', text: 'Risk factors: ' + ap.risk.factors.map((f) => `${f.label} (+${f.points})`).join(' · ') }] });
  }
  if (result) body.push({ type: 'TextBlock', wrap: true, weight: 'Bolder', color: result.status === 'approved' ? 'Good' : result.status === 'declined' ? 'Attention' : 'Default', text: result.text || `Request ${result.status}` });
  const actions = !result || result.status === 'pending' ? [button('Approve', 'approve', 'positive'), button('Decline', 'decline', 'destructive')] : [];
  if (consoleUrl) actions.push({ type: 'Action.OpenUrl', title: 'Open console', url: consoleUrl });
  return { type: 'AdaptiveCard', $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', version: '1.5', body, actions };
}

// Incoming webhooks and Workflows accept a message with the card as an attachment.
export const teamsMessage = (card) => ({
  type: 'message',
  attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', contentUrl: null, content: card }],
});

export async function postTeamsApproval(ap, { webhookUrl, consoleUrl, action, post = fetchPoster } = {}) {
  if (!webhookUrl) throw new Error('Teams needs webhookUrl');
  const res = await post(webhookUrl, { headers: { 'content-type': 'application/json' }, body: JSON.stringify(teamsMessage(approvalCard(ap, { consoleUrl, action }))) });
  if (!res.ok) throw new Error(`Teams webhook returned ${res.status}`);
  return res;
}

export function attachTeams(authority, config = {}) {
  const cfg = config.teams || config;
  const seen = new Set();
  return authority.on(async ({ type, data }) => {
    if (type !== 'approval' || data?.status !== 'pending' || seen.has(data.id)) return;
    seen.add(data.id);
    if (seen.size > 5000) seen.delete(seen.values().next().value);
    try {
      const ap = await authority.approval(data.id);
      if (ap?.status === 'pending') await postTeamsApproval(ap, cfg);
    } catch (e) {
      cfg.onError?.(e);
    }
  });
}

function secretMatches(expected, given) {
  if (!expected || typeof given !== 'string') return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(given);
  return a.length === b.length && timingSafeEqual(a, b);
}

// The invoke response Teams expects for adaptiveCard/action: a refreshed card.
const invokeCard = (card) => ({ statusCode: 200, type: 'application/vnd.microsoft.card.adaptive', value: card });
const invokeMessage = (text) => ({ statusCode: 200, type: 'application/vnd.microsoft.activity.message', value: text });

export function routes(ctx) {
  return [
    ['POST', '/integrations/teams/actions', async (body, _params, _query, req) => {
      const cfg = ctx.config?.teams || {};
      if (!secretMatches(cfg.sharedSecret, req?.headers?.['x-agentid-teams-secret'])) throw httpError(401, 'bad or missing x-agentid-teams-secret');
      if (body?.type !== 'invoke' || body.name !== 'adaptiveCard/action') return invokeMessage('ignored');
      const act = body.value?.action || {};
      const data = act.data || {};
      const decision = data.decision || (act.verb === 'agentid_approve' ? 'approve' : act.verb === 'agentid_decline' ? 'decline' : null);
      if (act.type !== 'Action.Execute' || !data.approvalId || !decision) return invokeMessage('not an AgentID action');
      const user = body.from?.aadObjectId || body.from?.id;
      const approver = cfg.approvers?.[user];
      if (!approver) return invokeMessage('You are not an approver for AgentID co-signs.');
      const ap = await ctx.authority().approval(data.approvalId);
      if (!ap) return invokeMessage('Approval not found.');
      try {
        const result = cfg.cosign
          ? await cfg.cosign(ap.id, decision, approver, { teamsUser: user, activity: body })
          : ctx.world?.() ? await ctx.world().approve(ap.id, decision, { key: approver.key })
          : (() => { throw new Error('no co-sign backend configured (config.teams.cosign)'); })();
        const who = body.from?.name || user;
        const text = result.status === 'pending' ? `${who} responded; waiting for quorum` : `${result.status === 'approved' ? 'Approved' : 'Declined'} by ${who}`;
        return invokeCard(approvalCard(ap, { consoleUrl: cfg.consoleUrl, result: { status: result.status, text } }));
      } catch (e) {
        return invokeMessage('Could not record your decision: ' + e.message);
      }
    }],
  ];
}

export function teamsConfigFromEnv(env = process.env) {
  if (!env.TEAMS_WEBHOOK_URL && !env.TEAMS_SHARED_SECRET) return null;
  return {
    webhookUrl: env.TEAMS_WEBHOOK_URL,
    sharedSecret: env.TEAMS_SHARED_SECRET,
    consoleUrl: env.AGENTID_CONSOLE_URL,
    approvers: env.TEAMS_APPROVERS ? JSON.parse(env.TEAMS_APPROVERS) : {},
  };
}
