"""Finite extension of terminal handback for positive-proof uncertainty recovery."""
from dataclasses import dataclass, replace
from checker import Transition
from native_handback import State, NativeHandbackModel, MUTATIONS as BASE_MUTATIONS


@dataclass(frozen=True)
class RecoveryState(State):
    recovery_keys: tuple = ()
    recovery_inflight: int = -1
    untracked_live_key: bool = False
    bad_recovery_proof: bool = False


class NativeRecoveryModel(NativeHandbackModel):
    name = 'terminal_native_handback_recovery'
    bounds = {**NativeHandbackModel.bounds, 'temporary_recovery_keys': 4,
              'implementation_key_limit': 4,
              'key_states': ['identity_pending', 'active', 'delete_pending', 'committed_ack_lost', 'revoked', 'rejected401'],
              'audit_and_retirement_evidence': 'exact positive, wrong identity, or absent; pagination abstracted to bounded success/failure'}
    assumptions = NativeHandbackModel.assumptions + [
        'A positive NodeRetirement response is a same-org exact immutable UID proof from one repeatable-read snapshot, with retained tombstone/generation and no current membership or leases.',
        'Normal gateway issuance and revocation share a node lock. Delayed mint after retirement cannot revive an old identity; new enrollment has a different immutable UID.',
        'An exact same-org APIKey delete AuditEvent is immutable and commits atomically with revocation. Missing, expired or wrong events never prove deletion.',
        'All four temporary-key slots are explored, matching the implementation admission bound. Credential bytes, audit pagination details and the unbounded remote database are abstracted, not exhaustively modeled.',
        'A recovery credential file/name fingerprint is durably recorded before the first authenticated read; UID/org discovery completes that obligation. Operator secrets outside this managed protocol remain outside scope.',
        'No fairness or completion claim: unavailable proof, exhausted bounded scan/key capacity, or network failure may leave the host quarantined forever.'
    ]
    properties = NativeHandbackModel.properties + ['EveryIntroducedKeyRetiredBeforeReady', 'RecoveryEvidenceExact']

    def initial(self):
        return RecoveryState()

    def successors(self, s, mutation):
        for transition in super().successors(s, mutation):
            target = transition.target
            if transition.action == 'Crash':
                target = replace(target, recovery_inflight=-1)
            if s.stage == 'key_ack' and transition.action in {'MonotonicWaitTick', 'Authenticated401', 'Treat403AsRevoked'}:
                if any(key not in {'revoked', 'rejected401'} for key in s.recovery_keys) and mutation != 'omit_recovery_retirement':
                    continue
                if transition.action == 'Authenticated401' and mutation != 'omit_recovery_401':
                    target = replace(target, recovery_keys=tuple('rejected401' if key == 'revoked' else key for key in s.recovery_keys))
            yield Transition(transition.action, target)
        if not s.running or not s.sticky:
            return
        if s.stage in {'prepared', 'node_pending', 'node_ack', 'key_pending', 'key_ack'}:
            if len(s.recovery_keys) < 4:
                yield Transition('PersistUnresolvedRecoveryFileObligation', replace(s,
                    recovery_keys=s.recovery_keys + ('identity_pending',), wait=0, fresh_wait=0))
            if mutation == 'omit_recovery_key_tracking':
                yield Transition('AuthenticateUntrackedRecoveryCredential', replace(s, untracked_live_key=True))
            if mutation == 'accept_foreign_recovery_actor':
                yield Transition('AcceptWrongOrgRecoveryActor', replace(s, bad_recovery_proof=True))
        if s.stage == 'node_pending' and s.uncertain:
            if s.node_retired:
                yield Transition('PersistExactNodeRetirementProof', replace(s, stage='node_ack', node_ack=True, uncertain=False))
            else:
                yield Transition('RetryExactLiveUIDWithFreshRV', replace(s, node_retired=True))
            if mutation == 'accept_wrong_node_proof':
                yield Transition('TreatForeignNodeProofAsExact', replace(s, stage='node_ack', node_ack=True,
                                 uncertain=False, bad_recovery_proof=True))
        if s.stage == 'key_pending' and s.uncertain:
            if s.key_retired and 'active' in s.recovery_keys:
                yield Transition('PersistExactKeyAuditProof', replace(s, stage='key_ack', key_ack=True, uncertain=False))
            elif not s.key_retired:
                yield Transition('RetryExactLiveKeyDeletion', replace(s, key_retired=True))
            if mutation == 'infer_key_revocation_from_404':
                yield Transition('TreatMissingKeyAsRevoked', replace(s, stage='key_ack', key_ack=True,
                                 uncertain=False, bad_recovery_proof=True))
        if s.stage in {'prepared', 'node_pending', 'node_ack', 'key_pending', 'key_ack'}:
            for index, status in enumerate(s.recovery_keys):
                if status == 'identity_pending':
                    keys = list(s.recovery_keys)
                    keys[index] = 'active'
                    yield Transition(f'VerifyExactRecoveryIdentity{index}', replace(s, recovery_keys=tuple(keys)))
        if s.stage == 'key_ack':
            for index, status in enumerate(s.recovery_keys):
                def changed(new_status, **extra):
                    keys = list(s.recovery_keys)
                    keys[index] = new_status
                    return replace(s, recovery_keys=tuple(keys), **extra)
                other_actor = any(i != index and key == 'active' for i, key in enumerate(s.recovery_keys))
                if status == 'active':
                    yield Transition(f'PersistRecoveryDeleteIntent{index}', changed('delete_pending', recovery_inflight=index))
                if status == 'delete_pending' and (s.recovery_inflight == index or other_actor):
                    yield Transition(f'CommitRecoveryKeyDelete{index}', changed('committed_ack_lost'))
                if status == 'committed_ack_lost':
                    if s.recovery_inflight == index or other_actor:
                        yield Transition(f'PersistRecoveryAckOrExactAudit{index}', changed('revoked', recovery_inflight=-1, wait=0, fresh_wait=0))
                    if mutation == 'forget_unknown_recovery_delete':
                        yield Transition(f'ForgetUnknownRecoveryKey{index}', replace(s,
                            recovery_keys=s.recovery_keys[:index] + s.recovery_keys[index+1:],
                            untracked_live_key=True, recovery_inflight=-1))

    def violations(self, s):
        errors = super().violations(s)
        if s.stage == 'ready' and (s.untracked_live_key or any(key != 'rejected401' for key in s.recovery_keys)):
            errors.append('EveryIntroducedKeyRetiredBeforeReady')
        if s.bad_recovery_proof:
            errors.append('RecoveryEvidenceExact')
        return errors


MUTATIONS = BASE_MUTATIONS + ('omit_recovery_key_tracking', 'accept_foreign_recovery_actor',
    'accept_wrong_node_proof', 'infer_key_revocation_from_404', 'forget_unknown_recovery_delete',
    'omit_recovery_retirement', 'omit_recovery_401')
