# ILLUSTRATIVE ONLY: not executed by the test suite. Needs `pip install langgraph langchain-anthropic`.
#
# A LangGraph ReAct agent whose payment tool runs only with an AgentID receipt.
# @tool reads the guarded function's name, docstring and signature, so the model
# sees an ordinary `pay_vendor(vendor, amount)` tool.

import json

import requests
from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from agentid import Agent, AuthorityClient, RECEIPT_HEADER, current_receipt, encode_receipt, guard

agent_id = Agent.restore(json.load(open('agent.json')))   # key, passport, mandate, attestation
authority = AuthorityClient('http://localhost:4600')


@tool
@guard(client=authority, agent=agent_id, action='payments.send', aud='payments', timeout=300,
       resource=lambda vendor, amount: 'vendor:' + vendor,
       params=lambda vendor, amount: {'amount': amount, 'currency': 'USD'},
       reason=lambda vendor, amount: f'LangGraph agent paying {vendor}')
def pay_vendor(vendor: str, amount: int) -> str:
    """Pay a carrier invoice in USD."""
    res = requests.post('http://localhost:4700/pay', json={'vendor': vendor, 'amount': amount},
                        headers={RECEIPT_HEADER: encode_receipt(current_receipt())})
    return res.json().get('message') or res.json().get('error')


# AgentIDDenied raised inside the tool becomes a tool error message the model can read
# (ToolNode handles tool errors by default), so a denial does not crash the graph.
graph = create_react_agent(ChatAnthropic(model='claude-opus-5-5'), tools=[pay_vendor])

if __name__ == '__main__':
    out = graph.invoke({'messages': [('user', 'Pay blue-line 320 USD for invoice CI-118.')]})
    print(out['messages'][-1].content)
