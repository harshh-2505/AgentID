import asyncio
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import agentid as a  # noqa: E402


class CanonicalTest(unittest.TestCase):
    # Expected values are what core/encoding.js canonical() prints for the same input.
    CASES = [
        (5.0, '5'), (-5.0, '-5'), (0.1, '0.1'), (1e21, '1e+21'), (1e20, '100000000000000000000'),
        (1e16, '10000000000000000'), (1.5e-7, '1.5e-7'), (0.000001, '0.000001'), (-0.0, '0'),
        (5e-324, '5e-324'), (2 ** 64, '18446744073709552000'), (2 ** 53 + 1, '9007199254740992'),
        (float('nan'), 'null'), (True, 'true'), (None, 'null'),
        ('héllo 😀', '"héllo 😀"'), (' ', '" "'), ('\x00\x1f\x7f\b\n"\\', '"\\u0000\\u001f\x7f\\b\\n\\"\\\\"'),
        ('\ud800', '"\\ud800"'),
        ({'b': 1, 'a': [1, {'z': None, 'y': True}], '😀': 1, '￿': 2, 'é': 3, 'A': 4},
         '{"A":4,"a":[1,{"y":true,"z":null}],"b":1,"é":3,"😀":1,"￿":2}'),
        ([], '[]'), ({}, '{}'),
    ]

    def test_matches_js(self):
        for value, expected in self.CASES:
            with self.subTest(value=value):
                self.assertEqual(a.canonical(value), expected)

    def test_b64u(self):
        for n in range(0, 40):
            data = os.urandom(n)
            self.assertNotIn('=', a.b64u(data))
            self.assertEqual(a.unb64u(a.b64u(data)), data)
        self.assertRegex(a.random_id('in'), r'^in_[A-Za-z0-9_-]{12}$')


class KeysTest(unittest.TestCase):
    def test_did_roundtrip(self):
        s = a.Signer.generate()
        self.assertTrue(s.did.startswith('did:agentid:'))
        self.assertEqual(a.did_from_public_key(a.public_key_from_did(s.did)), s.did)
        with self.assertRaises(ValueError):
            a.public_key_from_did('did:agentid:AAAA')

    def test_seal_and_verify(self):
        s, other = a.Signer.generate(), a.Signer.generate()
        sealed = s.seal({'type': 'Thing', 'n': 5.0, 'proof': 'replaced'})
        self.assertEqual(sealed['proof']['kid'], s.did)
        self.assertTrue(a.verify_sealed(sealed, s.did))
        self.assertTrue(a.verify_sealed(sealed))
        self.assertTrue(a.verify_sealed({**sealed, 'n': 5}), 'integral floats sign like ints')
        self.assertFalse(a.verify_sealed(sealed, other.did))
        self.assertFalse(a.verify_sealed({**sealed, 'n': 6}))
        self.assertFalse(a.verify_sealed({**sealed, 'proof': {**sealed['proof'], 'kid': other.did}}))
        self.assertFalse(a.verify_sealed(None))

    def test_jwk_roundtrip(self):
        s = a.Signer.generate()
        jwk = s.export()
        self.assertEqual(a.Signer.from_jwk(jwk).did, s.did)
        with self.assertRaises(ValueError):
            a.Signer.from_jwk({**jwk, 'x': a.Signer.generate().export()['x']})


class AgentTest(unittest.TestCase):
    def test_intent_shape(self):
        agent = a.Agent(a.Signer.generate(), passport={'id': 'pp_1'}, mandate={'id': 'md_1'}, attestation={'format': 'agentid-host'})
        i = agent.intent(action='payments.send', resource='vendor:x', params={'amount': 1}, reason='r', aud='payments')
        self.assertEqual(set(i), {'type', 'v', 'id', 'agent', 'passport', 'mandate', 'action', 'resource', 'params',
                                  'reason', 'aud', 'nonce', 'iat', 'exp', 'attestation', 'proof'})
        self.assertEqual((i['type'], i['v'], i['passport'], i['mandate'], i['exp'] - i['iat']), ('Intent', 1, 'pp_1', 'md_1', 60))
        self.assertTrue(a.verify_sealed(i, agent.did))

    def test_absent_fields_match_js(self):
        i = a.Agent(a.Signer.generate()).intent(action='x', resource='y')
        self.assertNotIn('passport', i)
        self.assertIsNone(i['attestation'])
        self.assertEqual((i['params'], i['reason'], i['aud']), ({}, '', 'any'))


def receipt_from(authority, **over):
    return authority.seal({'type': 'Receipt', 'v': 1, 'authority': authority.did, 'intent': 'in_1', 'agent': 'did:agentid:x',
                           'action': 'payments.send', 'resource': 'vendor:x', 'params': {'amount': 1}, 'aud': 'payments',
                           'cosigners': [], 'ledgerSeq': 3, 'iat': int(time.time()), **over})


class ReceiptTest(unittest.TestCase):
    def test_verify_receipt(self):
        auth = a.Signer.generate()
        r = receipt_from(auth)
        self.assertTrue(a.verify_receipt(r, auth.did, aud='payments')['ok'])
        self.assertEqual(a.verify_receipt(r, auth.did, aud='search')['reason'], 'receipt is for a different service')
        self.assertEqual(a.verify_receipt(r, a.Signer.generate().did)['reason'], 'receipt is not signed by the authority')
        self.assertEqual(a.verify_receipt(receipt_from(auth, iat=int(time.time()) - 500), auth.did)['reason'], 'receipt is too old')
        self.assertEqual(a.verify_receipt({'type': 'Intent'}, auth.did)['reason'], 'not a receipt')
        self.assertTrue(a.verify_receipt(receipt_from(auth, aud='any'), auth.did, aud='search')['ok'])

    def test_header_roundtrip(self):
        r = receipt_from(a.Signer.generate(), resource='vendor:blåbær')
        h = a.encode_receipt(r)
        self.assertRegex(h, r'^[A-Za-z0-9_-]+$')
        self.assertEqual(a.decode_receipt(h), r)
        self.assertEqual(a.RECEIPT_HEADER, 'agentid-receipt')


class FakeClient:
    """Answers like the /v1 API: up to 500 allow, up to 1000 step_up, above that deny."""

    def __init__(self, authority, approve_after=0, outcome='approved'):
        self.authority = authority
        self.approve_after = approve_after
        self.outcome = outcome
        self.intents = []
        self.polls = 0

    def verify_intent(self, intent):
        self.intents.append(intent)
        assert a.verify_sealed(intent, intent['agent'])
        amount = intent['params'].get('amount', 0)
        base = {'action': intent['action'], 'resource': intent['resource'], 'params': intent['params'], 'checks': []}
        if amount > 1000:
            return {**base, 'decision': 'deny', 'failedAt': 'limits', 'checks': [{'key': 'limits', 'status': 'fail', 'detail': 'amount above 1000'}]}
        if amount > 500:
            return {**base, 'decision': 'step_up', 'failedAt': 'cosign', 'approvalId': 'ap_1'}
        return {**base, 'decision': 'allow', 'failedAt': None, 'receipt': self._receipt(intent)}

    def approval(self, id):
        self.polls += 1
        if self.approve_after is None or self.polls <= self.approve_after:
            return {'id': id, 'status': 'pending', 'decision': None, 'receipt': None}
        if self.outcome == 'declined':
            return {'id': id, 'status': 'declined', 'decision': {'decision': 'deny', 'failedAt': 'cosign'}, 'receipt': None}
        intent = self.intents[-1]
        receipt = self._receipt(intent)
        return {'id': id, 'status': 'approved', 'decision': {'decision': 'allow', 'via': 'cosign', 'action': intent['action']}, 'receipt': receipt}

    def _receipt(self, intent):
        return receipt_from(self.authority, intent=intent['id'], action=intent['action'], resource=intent['resource'],
                            params=intent['params'], aud=intent['aud'])


class AdapterTest(unittest.TestCase):
    def setUp(self):
        self.auth = a.Signer.generate()
        self.agent = a.Agent(a.Signer.generate(), passport={'id': 'pp_1'}, mandate={'id': 'md_1'})

    def tool(self, client, **kw):
        @a.guard(client=client, agent=self.agent, action='payments.send', resource=lambda vendor, amount: 'vendor:' + vendor,
                 reason=lambda vendor, amount: f'pay {vendor}', aud='payments', poll=0.01, timeout=0.5, authority=self.auth.did, **kw)
        def pay(vendor: str, amount: int) -> dict:
            """Pay a vendor."""
            return {'paid': amount, 'receipt': a.current_receipt()}
        return pay

    def test_allow(self):
        client = FakeClient(self.auth)
        pay = self.tool(client)
        out = pay('acme', amount=200)
        self.assertEqual(out['paid'], 200)
        self.assertEqual(out['receipt']['resource'], 'vendor:acme')
        self.assertEqual(client.intents[0]['params'], {'vendor': 'acme', 'amount': 200}, 'params default to the bound arguments')
        self.assertEqual(client.intents[0]['reason'], 'pay acme')
        self.assertIsNone(a.current_receipt(), 'the receipt is only visible during the call')
        self.assertEqual((pay.__name__, pay.__doc__), ('pay', 'Pay a vendor.'))

    def test_deny(self):
        pay = self.tool(FakeClient(self.auth))
        with self.assertRaises(a.AgentIDDenied) as cm:
            pay('acme', 5000)
        self.assertEqual(cm.exception.failed_at, 'limits')
        self.assertIn('amount above 1000', str(cm.exception))

    def test_step_up(self):
        held = []
        client = FakeClient(self.auth, approve_after=2)
        out = self.tool(client, on_hold=held.append)('acme', 700)
        self.assertEqual((out['paid'], held[0]['decision'], client.polls), (700, 'step_up', 3))

    def test_step_up_declined_and_timeout(self):
        with self.assertRaises(a.AgentIDDenied) as cm:
            self.tool(FakeClient(self.auth, approve_after=1, outcome='declined'))('acme', 700)
        self.assertNotIsInstance(cm.exception, a.AgentIDTimeout)
        with self.assertRaises(a.AgentIDTimeout):
            self.tool(FakeClient(self.auth, approve_after=None))('acme', 700)

    def test_bad_receipt_is_rejected(self):
        client = FakeClient(a.Signer.generate())
        with self.assertRaises(a.AgentIDDenied) as cm:
            self.tool(client)('acme', 10)
        self.assertEqual(cm.exception.failed_at, 'receipt')

    def test_async_tool(self):
        @a.guard(client=FakeClient(self.auth), agent=self.agent, action='search.run', resource='index:docs',
                 params=lambda q: {'q': q})
        async def search(q):
            await asyncio.sleep(0)
            return a.current_receipt()['params']
        self.assertEqual(asyncio.run(search('agents')), {'q': 'agents'})


class ClientTest(unittest.TestCase):
    def test_act_settles_through_http_shape(self):
        auth = a.Signer.generate()
        agent = a.Agent(a.Signer.generate())
        client = FakeClient(auth, approve_after=1)
        first = client.verify_intent(agent.intent(action='payments.send', resource='vendor:x', params={'amount': 600}, aud='payments'))
        out = a.settle(client, first, poll=0.01, timeout=1)
        self.assertEqual((out['decision'], out['via']), ('allow', 'cosign'))
        self.assertTrue(a.verify_receipt(out['receipt'], auth.did)['ok'])

    def test_http_error(self):
        with self.assertRaises(Exception):
            a.AuthorityClient('http://127.0.0.1:9', timeout=1).discover()


if __name__ == '__main__':
    unittest.main()
