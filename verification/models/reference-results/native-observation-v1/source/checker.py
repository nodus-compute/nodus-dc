"""Exhaustive finite transition-graph exploration; no randomized or scenario loops."""
from collections import deque
from dataclasses import asdict, dataclass, is_dataclass
import time


@dataclass(frozen=True)
class Transition:
    action: str
    target: object


def encode(state):
    if is_dataclass(state):
        return asdict(state)
    if isinstance(state, tuple):
        return [encode(value) for value in state]
    return state


def explore(model, mutation=None, max_states=1_000_000):
    """BFS every reachable state until completion, counterexample or honest bound.

    max_states is an operational guard, NOT a state-space constraint. Hitting it
    produces incomplete and cannot qualify a profile. Model bounds live in model.
    """
    started=time.monotonic()
    initial=model.initial()
    queue=deque([initial])
    parents={initial:None}
    explored=0
    transitions=0
    counts={}
    violations=[]
    last=None
    outcome='passed'
    completed=True
    while queue:
        state=queue.popleft()
        explored+=1
        violated=model.violations(state)
        if violated:
            violations=violated
            last=state
            outcome='counterexample'
            completed=False
            break
        for transition in model.successors(state, mutation):
            transitions+=1
            counts[transition.action.split(':',1)[0]]=counts.get(transition.action.split(':',1)[0],0)+1
            target=transition.target
            if target not in parents:
                if len(parents)>=max_states:
                    outcome='incomplete_state_limit'
                    completed=False
                    queue.clear()
                    break
                parents[target]=(state,transition.action)
                queue.append(target)
        if outcome!='passed':
            break
    trace=[]
    if last is not None:
        current=last
        while parents[current] is not None:
            previous,action=parents[current]
            trace.append({'action':action,'state':encode(current)})
            current=previous
        trace.append({'action':'Init','state':encode(current)})
        trace.reverse()
    return {
        'profile':model.name,
        'mutation':mutation,
        'outcome':outcome,
        'exhaustive_search_completed':completed,
        'reachable_states_discovered':len(parents),
        'states_explored':explored,
        'transitions_explored':transitions,
        'pending_states_at_stop':len(queue),
        'transition_counts':dict(sorted(counts.items())),
        'violated_properties':violations,
        'counterexample':trace,
        'elapsed_seconds':round(time.monotonic()-started,6),
        'bounds':model.bounds,
        'assumptions':model.assumptions,
        'properties':model.properties,
        'fairness':'None. This run checks safety over all reachable bounded states; no liveness or wall-clock guarantee is claimed.',
        'max_states_guard':max_states,
        'proof_scope':'Only this finite abstract model. Implementation, GPU and processor conformance remain unverified.'
    }
