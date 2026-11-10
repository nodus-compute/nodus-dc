"""Finite safety model for a one-way terminal native return, not hardware proof."""
from dataclasses import dataclass, replace
from checker import Transition


@dataclass(frozen=True)
class State:
    stage: str = 'idle'
    running: bool = True
    held: bool = True
    sticky: bool = False
    external_active: bool = False
    owner_busy: bool = False
    history_valid: bool = True
    node_exact: bool = True
    key_exact: bool = True
    consent_revoked: bool = False
    initial_clean: bool = False
    node_retired: bool = False
    node_ack: bool = False
    key_retired: bool = False
    key_ack: bool = False
    uncertain: bool = False
    wait: int = 0
    fresh_wait: int = 0
    wait_proof: bool = False
    bad_wait: bool = False
    rejected_401: bool = False
    agent_inactive: bool = False
    files_removed: bool = False
    credential_matches: bool = True
    final_clean: bool = False
    gpu_valid: bool = False


class NativeHandbackModel:
    name = 'terminal_native_handback'
    bounds = {'hosts': 1, 'exclusive_local_leases': 1, 'node_identities': 'exact or stale',
              'api_key_identities': 'exact or stale', 'remote_deletion_operations': 2,
              'monotonic_wait_buckets': [0, 1, 2],
              'full_wait_bucket': '2 represents at least31 actual seconds since this process wait began',
              'crashes': 'arbitrarily many via finite cycles',
              'local_threads': 'one authority-lock owner; concurrent admission attempts are explicit transitions'}
    assumptions = [
        'Trusted operator controls the host before ready; arbitrary malicious root/database editing is outside the model.',
        'Verified HTTPS authenticates the existing platform. A successful exact Node DELETE transaction irreversibly revokes all bound node credentials and enrolled membership.',
        'APIKey names cannot be reused, and exact self-key DELETE permanently revokes that credential. The documented authentication-cache bound is30seconds.',
        'SQLite stage commits are atomic and durable. A lost remote acknowledgement is distinct from a completed transaction.',
        'Systemd inactive/control-group and GPU cleanup observations are abstract truthful predicates; actual kernel/device evidence requires independent qualification.',
        'One held whole-host lease and the shared host lock are preconditions. No new native-to-lending/reimage cycle is modeled.',
        'No wall-clock or finite completion guarantee: network, cleanup, revocation or the operator may never progress.'
    ]
    properties = ['ReadyRequiresExactRemoteRetirementAndCleanup', 'NativeHoldNeverUnlocks',
                  'NativeHoldNeverAdmitsExternal', 'UnknownDeleteOutcomeQuarantines',
                  'RestartCannotReuseMonotonicWait', 'InvalidHistoryNeverPrepares',
                  'LiveOwnerWorkNeverPrepares']

    def initial(self):
        return State()

    def successors(self, s, mutation):
        if not s.running:
            uncertain = s.uncertain or s.stage in {'node_pending', 'key_pending'}
            yield Transition('Restart', replace(s, running=True, uncertain=uncertain,
                             fresh_wait=0, wait=s.wait if mutation == 'reuse_wait_after_restart' else 0))
            return
        yield Transition('Crash', replace(s, running=False))
        if s.sticky:
            if mutation == 'expiry_unlocks_native':
                yield Transition('LeaseExpiry', replace(s, held=False))
            else:
                yield Transition('LeaseExpiryQuarantine', s)
            if mutation == 'admit_external_after_native':
                yield Transition('ExternalAdmission', replace(s, external_active=True))
            else:
                yield Transition('ExternalAdmissionDenied', s)
        if s.stage == 'idle':
            yield Transition('RevokeExactConsent', replace(s, consent_revoked=True))
            yield Transition('VerifyInitialCleanup', replace(s, initial_clean=True))
            yield Transition('RotateConnectionCredential', replace(s, history_valid=False))
            yield Transition('StaleNodeUID', replace(s, node_exact=False))
            yield Transition('StaleKeyUID', replace(s, key_exact=False))
            yield Transition('StartOwnerWork', replace(s, owner_busy=True))
            yield Transition('StopOwnerWork', replace(s, owner_busy=False))
            valid = (s.consent_revoked and s.initial_clean and s.node_exact and s.key_exact
                     and (s.history_valid or mutation == 'ignore_history')
                     and (not s.owner_busy or mutation == 'ignore_live_work'))
            if valid:
                yield Transition('PersistNativeIntent', replace(s, stage='prepared', sticky=True))
            return
        if s.stage == 'prepared':
            yield Transition('PersistNodeDeleteIntent', replace(s, stage='node_pending'))
        elif s.stage == 'node_pending':
            if s.uncertain:
                yield Transition('QuarantineUnknownNodeOutcome', s)
                if mutation == 'infer_node_retirement_from_404':
                    yield Transition('Treat404AsNodeAck', replace(s, stage='node_ack', node_ack=True, uncertain=False))
            else:
                yield Transition('CommitRemoteNodeDelete', replace(s, node_retired=s.node_exact))
                if s.node_retired:
                    yield Transition('PersistExactNodeAck', replace(s, stage='node_ack', node_ack=True))
        elif s.stage == 'node_ack':
            yield Transition('PersistKeyDeleteIntent', replace(s, stage='key_pending'))
        elif s.stage == 'key_pending':
            if s.uncertain:
                yield Transition('QuarantineUnknownKeyOutcome', s)
            else:
                yield Transition('CommitRemoteKeyDelete', replace(s, key_retired=s.key_exact))
                if s.key_retired:
                    yield Transition('PersistExactKeyAck', replace(s, stage='key_ack', key_ack=True))
        elif s.stage == 'key_ack':
            if s.wait < 2:
                yield Transition('MonotonicWaitTick', replace(s, wait=s.wait+1, fresh_wait=min(s.fresh_wait+1, 2)))
            if s.wait == 2 or mutation == 'omit_full_wait':
                yield Transition('Authenticated401', replace(s, stage='rejected', rejected_401=True,
                                 wait_proof=s.fresh_wait == 2, bad_wait=s.fresh_wait != 2))
                if mutation == 'accept_non401':
                    yield Transition('Treat403AsRevoked', replace(s, stage='rejected', rejected_401=False, wait_proof=True))
            yield Transition('NetworkFailureOrStillAuthorized', s)
        elif s.stage == 'rejected':
            yield Transition('StopAndVerifyAgent', replace(s, stage='agent_stopped', agent_inactive=True))
            if mutation == 'omit_agent_stop':
                yield Transition('SkipAgentStop', replace(s, stage='agent_stopped'))
        elif s.stage == 'agent_stopped':
            yield Transition('CredentialFileChanged', replace(s, credential_matches=False))
            if s.credential_matches:
                yield Transition('RemoveBoundCredentialFiles', replace(s, stage='files_removed', files_removed=True))
        elif s.stage == 'files_removed':
            yield Transition('ObserveFinalDeviceClean', replace(s, final_clean=True, gpu_valid=True))
            yield Transition('ObserveFailedDeviceCleanup', replace(s, final_clean=False, gpu_valid=False))
            if s.final_clean and s.gpu_valid or mutation == 'omit_final_gpu_validation':
                yield Transition('PersistNativeReady', replace(s, stage='ready'))

    def violations(self, s):
        bad = []
        if s.stage == 'ready' and not all((s.held, s.sticky, s.history_valid, s.consent_revoked,
                s.node_exact, s.node_retired, s.node_ack, s.key_exact, s.key_retired, s.key_ack,
                s.initial_clean, s.wait_proof, s.rejected_401, s.agent_inactive,
                s.files_removed, s.credential_matches, s.final_clean, s.gpu_valid)):
            bad.append('ReadyRequiresExactRemoteRetirementAndCleanup')
        if s.sticky and not s.held:
            bad.append('NativeHoldNeverUnlocks')
        if s.sticky and s.external_active:
            bad.append('NativeHoldNeverAdmitsExternal')
        if s.uncertain and s.stage not in {'node_pending', 'key_pending'}:
            bad.append('UnknownDeleteOutcomeQuarantines')
        if s.bad_wait:
            bad.append('RestartCannotReuseMonotonicWait')
        if s.sticky and not s.history_valid:
            bad.append('InvalidHistoryNeverPrepares')
        if s.sticky and s.owner_busy:
            bad.append('LiveOwnerWorkNeverPrepares')
        return bad


MUTATIONS = ('ignore_history', 'ignore_live_work', 'infer_node_retirement_from_404',
             'reuse_wait_after_restart', 'omit_full_wait', 'accept_non401',
             'omit_agent_stop', 'omit_final_gpu_validation',
             'expiry_unlocks_native', 'admit_external_after_native')
