"""The agent side: holds the key, passport, mandate and attestation, and signs Intents."""

from .encoding import now_sec, random_id
from .keys import Signer


class Agent:
    def __init__(self, signer: Signer, passport: dict = None, mandate: dict = None, attestation: dict = None, name: str = None):
        self.signer = signer
        self.did = signer.did
        self.passport = passport
        self.mandate = mandate
        self.attestation = attestation
        self.name = name

    @classmethod
    def restore(cls, data: dict) -> 'Agent':
        """Loads what AgentRuntime.export() (JS) or Agent.export() writes."""
        return cls(Signer.from_jwk(data['jwk']), data.get('passport'), data.get('mandate'), data.get('attestation'), data.get('name'))

    def export(self) -> dict:
        return {'jwk': self.signer.export(), 'name': self.name, 'passport': self.passport, 'mandate': self.mandate, 'attestation': self.attestation}

    def intent(self, action: str, resource: str, params: dict = None, reason: str = '', aud: str = 'any', ttl_sec: int = 60) -> dict:
        """Builds a signed Intent with exactly the fields AgentRuntime.intent() signs."""
        iat = now_sec()
        body = {
            'type': 'Intent', 'v': 1, 'id': random_id('in'),
            'agent': self.did, 'passport': (self.passport or {}).get('id'), 'mandate': (self.mandate or {}).get('id'),
            'action': action, 'resource': resource, 'params': {} if params is None else params, 'reason': reason, 'aud': aud,
            'nonce': random_id('n'), 'iat': iat, 'exp': iat + ttl_sec,
            'attestation': self.attestation,
        }
        # JS leaves these undefined when absent, and canonical() drops undefined; attestation stays null.
        for k in ('passport', 'mandate', 'action', 'resource'):
            if body[k] is None:
                del body[k]
        return self.signer.seal(body)
