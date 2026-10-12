"""HTTP client for an AgentID authority, plus offline receipt checks for relying services."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .encoding import b64u, unb64u
from .keys import verify_sealed

RECEIPT_HEADER = 'agentid-receipt'


class AuthorityError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class AuthorityClient:
    def __init__(self, base_url: str = 'http://localhost:4600', timeout: float = 30.0):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout

    def _call(self, method, path, body=None):
        data = json.dumps(body, ensure_ascii=False).encode('utf-8') if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method,
                                     headers={'content-type': 'application/json'} if data else {})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                return json.loads(res.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read().decode('utf-8')).get('error')
            except ValueError:
                msg = None
            raise AuthorityError(msg or f'HTTP {e.code}', e.code) from None

    def discover(self): return self._call('GET', '/.well-known/agentid')
    def register_principal(self, reg): return self._call('POST', '/v1/principals', reg)
    def endorse_attestor(self, end): return self._call('POST', '/v1/attestors', end)
    def register_passport(self, pp): return self._call('POST', '/v1/passports', pp)
    def register_mandate(self, m): return self._call('POST', '/v1/mandates', m)
    def verify_intent(self, intent): return self._call('POST', '/v1/intents', intent)
    def approval(self, id): return self._call('GET', '/v1/approvals/' + urllib.parse.quote(id, safe=''))
    def approval_request(self, id): return self._call('GET', '/v1/approvals/' + urllib.parse.quote(id, safe='') + '/request')
    def cosign(self, c): return self._call('POST', '/v1/approvals/' + urllib.parse.quote(c['approval'], safe='') + '/cosign', c)
    def revoke(self, r): return self._call('POST', '/v1/revocations', r)
    def ledger(self, start=0): return self._call('GET', f'/v1/ledger?from={int(start)}')
    def verify_ledger(self): return self._call('GET', '/v1/ledger/verify')

    def act(self, agent, *, timeout: float = 120.0, poll: float = 1.0, on_hold=None, **req) -> dict:
        """Submits agent.intent(**req) and, when the authority holds it for a co-sign, waits for the outcome."""
        first = self.verify_intent(agent.intent(**req))
        return settle(self, first, timeout=timeout, poll=poll, on_hold=on_hold)


def settle(client, first: dict, timeout: float = 120.0, poll: float = 1.0, on_hold=None) -> dict:
    """Polls client.approval() until a step_up decision is resolved; returns the final decision."""
    if first.get('decision') != 'step_up':
        return first
    if on_hold:
        on_hold(first)
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        time.sleep(poll)
        ap = client.approval(first['approvalId']) or {}
        # An approval can read as approved a moment before its decision and receipt land.
        if ap.get('status') == 'pending' or (ap.get('status') == 'approved' and not ap.get('receipt')):
            continue
        if ap.get('decision'):
            return {**ap['decision'], 'receipt': ap.get('receipt')}
        if ap.get('status') == 'approved' and ap.get('receipt'):
            return {**first, 'decision': 'allow', 'failedAt': None, 'receipt': ap['receipt']}
        return {**first, 'decision': 'deny', 'failedAt': 'cosign', 'note': ap.get('note') or ap.get('status')}
    return {**first, 'decision': 'deny', 'failedAt': 'cosign', 'timedOut': True}


def verify_receipt(receipt, authority_did: str, aud: str = None, max_age_sec: int = 120) -> dict:
    """Checks a receipt offline against the authority's identifier. Same rules as verifyReceipt in JS."""
    fail = lambda reason: {'ok': False, 'reason': reason}
    if not isinstance(receipt, dict) or receipt.get('type') != 'Receipt':
        return fail('not a receipt')
    if not verify_sealed(receipt, authority_did):
        return fail('receipt is not signed by the authority')
    if aud and receipt.get('aud') != aud and receipt.get('aud') != 'any':
        return fail('receipt is for a different service')
    if int(time.time()) - receipt.get('iat', 0) > max_age_sec:
        return fail('receipt is too old')
    return {'ok': True, 'receipt': receipt}


def encode_receipt(receipt: dict) -> str:
    return b64u(json.dumps(receipt, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))


def decode_receipt(value: str) -> dict:
    return json.loads(unb64u(value).decode('utf-8'))
