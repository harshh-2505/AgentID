# AgentID for Python

The agent side of AgentID in Python: Ed25519 keys, signed Intents, an HTTP client for
the authority, offline receipt checks, and a `@guard` decorator for tools. It signs the
same canonical bytes as the JavaScript core, so either side can verify the other
(`test/crosslang.test.js` checks this).

```sh
pip install ./sdk-python        # depends only on `cryptography`
python3 -m unittest discover -s sdk-python/tests
```

```python
import json
from agentid import Agent, AuthorityClient, guard, current_receipt, AgentIDDenied

agent = Agent.restore(json.load(open('agent.json')))   # AgentRuntime.export() from JS, or Agent.export()
client = AuthorityClient('http://localhost:4600')

# One call: sign, submit, wait for a co-sign if the mandate asks for one.
d = client.act(agent, action='payments.send', resource='vendor:acme',
               params={'amount': 120, 'currency': 'USD'}, reason='Invoice 118', aud='payments')

# Or guard a tool. It runs only on `allow`; deny raises AgentIDDenied, an unanswered co-sign AgentIDTimeout.
@guard(client=client, agent=agent, action='payments.send', aud='payments',
       resource=lambda vendor, amount: 'vendor:' + vendor,
       params=lambda vendor, amount: {'amount': amount, 'currency': 'USD'},
       reason=lambda vendor, amount: f'pay {vendor}')
def pay(vendor: str, amount: int) -> str:
    receipt = current_receipt()      # send it to the service in the `agentid-receipt` header
    ...
```

Relying services check receipts without calling the authority:
`verify_receipt(decode_receipt(header), authority_did, aud='payments')`.

| Python | JavaScript |
| --- | --- |
| `canonical`, `b64u`, `unb64u` | `core/encoding.js` |
| `Signer`, `verify_sealed`, `did_from_public_key` | `core/keys.js` |
| `Agent.intent` | `AgentRuntime.intent` |
| `AuthorityClient`, `verify_receipt`, `encode_receipt` | `sdk/index.js` |
| `guard`, `authorize` | `sdk/adapters.js` (`withAgentID`) |
