"""AgentID Python SDK: agent keys, signed intents, an authority client and receipt checks."""

from .encoding import b64u, unb64u, canonical, sha256, hash_object, random_id, now_sec
from .keys import Signer, verify_sealed, did_from_public_key, public_key_from_did, is_did
from .agent import Agent
from .client import (AuthorityClient, AuthorityError, settle, verify_receipt,
                     encode_receipt, decode_receipt, RECEIPT_HEADER)
from .adapters import guard, authorize, current_decision, current_receipt, AgentIDDenied, AgentIDTimeout

__version__ = '0.1.0'
