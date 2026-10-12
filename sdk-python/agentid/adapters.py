"""Wrap any tool function so it only runs with an AgentID receipt.

    @guard(client=client, agent=agent, action='payments.send',
           resource=lambda vendor, amount: 'vendor:' + vendor)
    def pay(vendor: str, amount: int) -> str:
        receipt = current_receipt()
        ...

The wrapped function keeps its name, docstring and signature, so frameworks that
build a tool schema from them (LangGraph, OpenAI Agents SDK, CrewAI) see the original.
"""

import asyncio
import contextvars
import functools
import inspect

from .client import settle, verify_receipt

_current = contextvars.ContextVar('agentid_decision', default=None)


class AgentIDDenied(Exception):
    def __init__(self, decision: dict):
        self.decision = decision
        self.failed_at = decision.get('failedAt')
        check = next((c for c in decision.get('checks') or [] if c.get('status') in ('fail', 'hold')), None)
        self.detail = decision.get('note') or (check or {}).get('detail') or ''
        super().__init__(f"AgentID denied {decision.get('action')} on {decision.get('resource')}"
                         + (f' at {self.failed_at}' if self.failed_at else '') + (f': {self.detail}' if self.detail else ''))


class AgentIDTimeout(AgentIDDenied):
    """The request needed a co-sign and nobody answered in time."""


def current_decision() -> dict:
    """The allow decision for the tool call in progress (None outside a guarded call)."""
    return _current.get()


def current_receipt() -> dict:
    d = _current.get()
    return d and d.get('receipt')


def authorize(client, agent, *, timeout=120.0, poll=1.0, on_hold=None, authority=None, **req) -> dict:
    """Sends one intent, waits out a step_up, and returns the allow decision or raises."""
    d = settle(client, client.verify_intent(agent.intent(**req)), timeout=timeout, poll=poll, on_hold=on_hold)
    if d.get('decision') != 'allow':
        raise (AgentIDTimeout if d.get('timedOut') else AgentIDDenied)(d)
    if authority:
        v = verify_receipt(d.get('receipt'), authority, aud=req.get('aud'))
        if not v['ok']:
            raise AgentIDDenied({**d, 'decision': 'deny', 'failedAt': 'receipt', 'note': v['reason']})
    return d


def guard(*, client, agent, action, resource, params=None, reason='', aud='any',
          timeout=120.0, poll=1.0, on_hold=None, authority=None):
    """`resource`, `params` and `reason` are values or callables taking the tool's own arguments.
    `params` defaults to the tool's bound arguments. Pass `authority` (its did) to also check the receipt."""

    def deco(fn):
        sig = inspect.signature(fn)

        def request(args, kwargs):
            at = lambda v: v(*args, **kwargs) if callable(v) else v
            if params is None:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                p = dict(bound.arguments)
            else:
                p = at(params)
            return dict(action=action, resource=at(resource), params=p, reason=at(reason), aud=aud,
                        timeout=timeout, poll=poll, on_hold=on_hold, authority=authority)

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                d = await asyncio.to_thread(authorize, client, agent, **request(args, kwargs))
                token = _current.set(d)
                try:
                    return await fn(*args, **kwargs)
                finally:
                    _current.reset(token)
            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            d = authorize(client, agent, **request(args, kwargs))
            token = _current.set(d)
            try:
                return fn(*args, **kwargs)
            finally:
                _current.reset(token)
        return wrapper

    return deco
