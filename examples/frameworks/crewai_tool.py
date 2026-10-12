# ILLUSTRATIVE ONLY: not executed by the test suite. Needs `pip install crewai`.
#
# CrewAI: the guarded function becomes a crew tool. A step_up waits (up to `timeout`)
# for the principal to co-sign from their approval app before the deploy runs.

import json

from crewai import Agent as CrewAgent, Crew, Task
from crewai.tools import tool

from agentid import Agent, AuthorityClient, current_receipt, guard

identity = Agent.restore(json.load(open('agent.json')))
authority = AuthorityClient('http://localhost:4600')


@tool('Deploy service')
@guard(client=authority, agent=identity, action='deploy.production', aud='ci', timeout=600,
       on_hold=lambda d: print('waiting for co-sign:', d['approvalId']),
       resource=lambda service, version: 'service:' + service,
       params=lambda service, version: {'version': version},
       reason=lambda service, version: f'release {version} of {service}')
def deploy(service: str, version: str) -> str:
    """Deploy a tagged version of a service to production."""
    return f'deployed {service}@{version}; receipt {current_receipt()["intent"]}'


releaser = CrewAgent(role='Release engineer', goal='Ship approved releases safely',
                     backstory='Runs the release checklist.', tools=[deploy])
task = Task(description='Deploy billing-api version 2.4.1.', expected_output='Deployment summary', agent=releaser)

if __name__ == '__main__':
    print(Crew(agents=[releaser], tasks=[task]).kickoff())
