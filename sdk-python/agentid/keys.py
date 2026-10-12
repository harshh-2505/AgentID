"""Ed25519 keys and did:agentid identifiers, compatible with core/keys.js."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .encoding import b64u, canonical, unb64u

DID_PREFIX = 'did:agentid:'


def did_from_public_key(raw: bytes) -> str:
    return DID_PREFIX + b64u(raw)


def public_key_from_did(did: str) -> bytes:
    if not isinstance(did, str) or not did.startswith(DID_PREFIX):
        raise ValueError('not an AgentID identifier')
    raw = unb64u(did[len(DID_PREFIX):])
    if len(raw) != 32:
        raise ValueError('identifier does not hold a 32-byte Ed25519 key')
    return raw


def is_did(s) -> bool:
    return isinstance(s, str) and s.startswith(DID_PREFIX)


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class Signer:
    def __init__(self, private_key: Ed25519PrivateKey):
        self.private_key = private_key
        self.did = did_from_public_key(_raw_public(private_key))

    @classmethod
    def generate(cls) -> 'Signer':
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_jwk(cls, jwk: dict) -> 'Signer':
        if jwk.get('kty') != 'OKP' or jwk.get('crv') != 'Ed25519' or 'd' not in jwk:
            raise ValueError('not an Ed25519 private JWK')
        signer = cls(Ed25519PrivateKey.from_private_bytes(unb64u(jwk['d'])))
        if 'x' in jwk and unb64u(jwk['x']) != public_key_from_did(signer.did):
            raise ValueError('JWK public key does not match its private key')
        return signer

    def export(self) -> dict:
        d = self.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return {'kty': 'OKP', 'crv': 'Ed25519', 'd': b64u(d), 'x': b64u(_raw_public(self.private_key))}

    def sign_bytes(self, data: bytes) -> str:
        return b64u(self.private_key.sign(data))

    def seal(self, body: dict) -> dict:
        """Returns a copy of `body` carrying a detached proof over its canonical form."""
        clean = {k: v for k, v in body.items() if k != 'proof'}
        sig = self.sign_bytes(canonical(clean).encode('utf-8'))
        return {**clean, 'proof': {'alg': 'Ed25519', 'kid': self.did, 'sig': sig}}


def verify_sealed(obj, expected_kid: str = None) -> bool:
    """True when obj['proof'] is a valid signature by expected_kid (or by the key the proof names)."""
    try:
        proof = obj.get('proof')
        if not proof or proof.get('alg') != 'Ed25519' or not proof.get('sig'):
            return False
        if expected_kid and proof.get('kid') != expected_kid:
            return False
        key = Ed25519PublicKey.from_public_bytes(public_key_from_did(proof['kid']))
        body = {k: v for k, v in obj.items() if k != 'proof'}
        key.verify(unb64u(proof['sig']), canonical(body).encode('utf-8'))
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError, AttributeError):
        return False
