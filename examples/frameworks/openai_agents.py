# ILLUSTRATIVE ONLY: not executed by the test suite. Needs `pip install openai-agents`.
#
# OpenAI Agents SDK: @function_tool builds the schema from the guarded function,
# which keeps the original signature and docstring.

import json

from agents import Agent as LLMAgent, Runner, function_tool

import agentid
from agentid import AgentIDDenied, AuthorityClient, current_receipt, guard

identity = agentid.Agent.restore(json.load(open('agent.json')))
authority = AuthorityClient('http://localhost:4600')


@guard(client=authority, agent=identity, action='crm.records.export', aud='crm',
       resource=lambda segment: 'segment:' + segment,
       params=lambda segment: {'segment': segment},
       reason=lambda segment: f'quarterly churn report for {segment}')
def _export(segment: str) -> str:
    receipt = current_receipt()
    return f'exported {segment} (ledger #{receipt["ledgerSeq"]})'


@function_tool
def export_segment(segment: str) -> str:
    """Export the CRM records of one customer segment."""
    try:
        return _export(segment)
    except AgentIDDenied as e:
        # Tell the model why, so it can explain or ask a person instead of retrying.
        return f'Not authorized: {e.detail or e.failed_at}'


analyst = LLMAgent(name='Analyst', instructions='Help with CRM reporting.', tools=[export_segment])

if __name__ == '__main__':
    print(Runner.run_sync(analyst, 'Export the enterprise segment for the churn report.').final_output)
