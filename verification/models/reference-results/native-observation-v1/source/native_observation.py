"""Schema3 participation-history extension of the existing bounded native model.

No remote identity, SQLite durability, systemd or GPU implementation is proved.
The original four-key recovery and cleanup transition machines are reused.
"""
from dataclasses import dataclass, replace
from checker import Transition
from native_handback_recovery import RecoveryState, NativeRecoveryModel


@dataclass(frozen=True)
class ObservationState(RecoveryState):
    initialized: bool = False
    schema: int = 2
    participation: str = 'unknown'
    connected: bool = False
    policy_enabled: bool = False
    mutable_active: bool = False
    ever_committed: bool = False
    external_history: bool = False
    consent_known: bool = False
    nonaccepting_snapshot: bool = False
    native_route: str = ''
    node_delete_ack: bool = False
    affirmative_retirement: bool = False
    unauthorized_admission: bool = False
    legacy_reader_admitted: bool = False


ORIGINS = ('fresh', 'legacy_no_consent', 'legacy_with_consent', 'ever_enabled')


class NativeObservationModel(NativeRecoveryModel):
    name = 'terminal_native_observation_schema3'
    bounds = {**NativeRecoveryModel.bounds,
        'schema_versions': [2, 3], 'history_values': ['never_enabled', 'ever_enabled', 'unknown'],
        'origins': list(ORIGINS), 'policy_threads': 'one serialized SQLite writer; both enable/disconnect orders explored',
        'external_history': 'zero versus at least one historical claim; no unbounded allocation count',
        'observation_snapshot': 'exact live Node identity plus nonaccepting/no-current-consent, or missing',
        'retirement_evidence': 'same-org exact immutable UID/generation positive, DELETE acknowledgement, wrong proof or absence'}
    assumptions = NativeRecoveryModel.assumptions + [
        'The model origin is an oracle for genuine continuously tracked first connection versus legacy/history-bearing state; implementation must prove that classification from durable records.',
        'Schema3/history/policy writes inside a SQLite transaction commit atomically; crash does not split a committed transaction. The omission mutants intentionally violate this contract.',
        'The whole-host lease and dedicated-key validity preconditions of the existing native model are retained. Historical external claims are summarized after completion, not simultaneous with that exclusive lease.',
        'Observation connection status does not itself grant allocation authority. A policy enable is an explicit accepted-consent operation, never an effect of metric observation.',
        'The new no-consent route requires affirmative exact NodeRetirement even after an acknowledged normal DELETE. This proof is an authenticated abstract input, not a model verification of the platform endpoint.',
        'No equivalence/refinement proof connects this model to Python, SQLite, remote services or hardware. Model safety is separate from current implementation conformance.'
    ]
    properties = NativeRecoveryModel.properties + [
        'Schema3FencesNewHistory', 'NeverHistoryRequiresFreshOrigin', 'EverEnabledHistoryIsSticky',
        'ObservationNeverAuthorizesAllocation', 'NeverShortcutRequiresAllObservationGates',
        'ConsentRouteStillRequiresRevocation', 'NeverRouteNeedsAffirmativeNodeRetirement',
        'NativeIntentBlocksPolicyReenable']

    def __init__(self, origin='fresh'):
        if origin not in ORIGINS: raise ValueError('unknown finite origin')
        self.origin = origin
        self.name += ':' + origin
        self.bounds = {**self.bounds, 'selected_origin': origin}

    def initial(self):
        return ObservationState()

    def never_eligible(self, s, mutation=None):
        history = s.participation == 'never_enabled' or mutation == 'unknown_is_never' and s.participation == 'unknown'
        return (history and s.history_valid and s.initial_clean and s.node_exact and s.key_exact
            and not s.owner_busy and not s.connected and not s.policy_enabled and not s.consent_known
            and (not s.external_history or mutation == 'ignore_external_history')
            and (s.nonaccepting_snapshot or mutation == 'omit_nonaccepting_snapshot'))

    def successors(self, s, mutation):
        if not s.initialized:
            history = 'never_enabled' if self.origin == 'fresh' else 'ever_enabled' if self.origin == 'ever_enabled' else 'unknown'
            if mutation == 'initialize_legacy_never': history = 'never_enabled'
            yield Transition('AtomicInitializeTrackedObservation', replace(s, initialized=True,
                schema=2 if mutation == 'omit_schema3' else 3, participation=history, connected=True,
                ever_committed=self.origin == 'ever_enabled',
                consent_known=self.origin in {'legacy_with_consent', 'ever_enabled'}))
            return
        for transition in super().successors(s, mutation):
            target = transition.target
            if transition.action == 'RevokeExactConsent' and not s.consent_known:
                continue
            if transition.action == 'PersistNativeIntent':
                if s.connected or s.policy_enabled or not s.consent_known:
                    continue
                target = replace(target, native_route='consent')
            if transition.action == 'Restart' and mutation == 'restart_forgets_history' and s.ever_committed:
                target = replace(target, participation='never_enabled')
            if s.native_route == 'never' and transition.action == 'PersistExactNodeAck':
                if mutation == 'delete_ack_is_retirement':
                    target = replace(target, affirmative_retirement=False)
                else:
                    target = replace(target, stage='node_pending', node_ack=False, node_delete_ack=True)
            if s.native_route == 'never' and transition.action == 'PersistExactNodeRetirementProof':
                target = replace(target, affirmative_retirement=True)
            yield Transition(transition.action, target)
        if not s.running:
            return
        if mutation == 'allow_schema2_reader':
            yield Transition('OldReaderMutatesSchema3', replace(s, legacy_reader_admitted=True))
        else:
            yield Transition('OldReaderRefusesSchema3', s)
        if s.sticky:
            if mutation == 'enable_after_native_intent':
                yield Transition('DirectEnableAfterNativeIntent', replace(s, policy_enabled=True))
        elif s.stage == 'idle':
            yield Transition('DisconnectWithoutForgettingHistory', replace(s, connected=False,
                policy_enabled=False, mutable_active=False,
                participation='never_enabled' if mutation == 'disable_clears_history' else s.participation))
            yield Transition('ReconnectObservationWithoutHistoryReset', replace(s, connected=True,
                policy_enabled=False, mutable_active=False, nonaccepting_snapshot=False))
            yield Transition('MutableConnectionActiveIsNotPermission', replace(s, mutable_active=True))
            yield Transition('ExplicitAcceptedConsentEnable', replace(s, consent_known=True,
                participation=s.participation if mutation == 'enable_omits_history' else 'ever_enabled',
                ever_committed=True, schema=3, policy_enabled=True, connected=True,
                mutable_active=True, consent_revoked=False, nonaccepting_snapshot=False))
            if s.policy_enabled:
                # A completed earlier claim is a sticky history fact; the model's
                # held whole-host native lease precondition excludes active overlap.
                yield Transition('RetainCompletedExternalClaimHistory', replace(s, external_history=True))
            if s.mutable_active and not s.policy_enabled:
                if mutation == 'mutable_active_admits':
                    yield Transition('ClaimUsingConnectionActiveOnly', replace(s, unauthorized_admission=True))
                else:
                    yield Transition('ClaimDeniedWithoutCurrentPolicy', s)
            if s.node_exact and not s.consent_known and not s.policy_enabled:
                yield Transition('VerifyExactNonacceptingNodeSharing', replace(s, nonaccepting_snapshot=True))
            if self.never_eligible(s, mutation):
                yield Transition('PersistNeverParticipatedNativeIntent', replace(s, stage='prepared',
                    sticky=True, native_route='never'))
            if mutation == 'bypass_consent_revoke' and s.consent_known and not s.connected and not s.policy_enabled and s.initial_clean and s.history_valid and not s.owner_busy and s.node_exact and s.key_exact:
                yield Transition('PersistConsentRouteWithoutRevocation', replace(s, stage='prepared', sticky=True, native_route='consent'))
            if mutation == 'ignore_external_history' and s.participation == 'never_enabled':
                yield Transition('RevealContradictoryHistoricalClaim', replace(s, external_history=True))
        if s.native_route == 'never' and s.stage == 'node_pending' and s.node_retired:
            yield Transition('PersistAffirmativeExactNodeRetirement', replace(s, stage='node_ack',
                node_ack=True, affirmative_retirement=True, uncertain=False))
        if s.native_route == 'never' and s.stage == 'node_pending' and mutation == 'accept_wrong_retirement':
            yield Transition('AcceptForeignOrAbsentRetirement', replace(s, stage='node_ack',
                node_ack=True, affirmative_retirement=False, uncertain=False))

    def violations(self, s):
        errors = super().violations(s)
        if s.native_route == 'never' and s.stage == 'ready':
            # Replace only the consent-specific premise, not any original cleanup,
            # identity, wait, credential or four-key retirement obligation.
            if 'ReadyRequiresExactRemoteRetirementAndCleanup' in errors:
                errors.remove('ReadyRequiresExactRemoteRetirementAndCleanup')
            if not all((s.held, s.sticky, s.history_valid, s.node_exact, s.node_retired,
                s.node_ack, s.key_exact, s.key_retired, s.key_ack, s.initial_clean,
                s.wait_proof, s.rejected_401, s.agent_inactive, s.files_removed,
                s.credential_matches, s.final_clean, s.gpu_valid)):
                errors.append('ReadyRequiresExactRemoteRetirementAndCleanup')
        if s.initialized and (s.schema != 3 or s.legacy_reader_admitted):
            errors.append('Schema3FencesNewHistory')
        if s.participation == 'never_enabled' and self.origin != 'fresh':
            errors.append('NeverHistoryRequiresFreshOrigin')
        if s.ever_committed and s.participation != 'ever_enabled':
            errors.append('EverEnabledHistoryIsSticky')
        if s.unauthorized_admission:
            errors.append('ObservationNeverAuthorizesAllocation')
        if s.sticky and s.native_route == 'never' and not self.never_eligible(s):
            errors.append('NeverShortcutRequiresAllObservationGates')
        if s.sticky and s.native_route == 'consent' and not (s.consent_known and s.consent_revoked):
            errors.append('ConsentRouteStillRequiresRevocation')
        if s.native_route == 'never' and s.node_ack and not s.affirmative_retirement:
            errors.append('NeverRouteNeedsAffirmativeNodeRetirement')
        if s.sticky and s.policy_enabled:
            errors.append('NativeIntentBlocksPolicyReenable')
        return errors


MUTATIONS = {
    'omit_schema3': ('fresh', 'Schema3FencesNewHistory'),
    'initialize_legacy_never': ('legacy_no_consent', 'NeverHistoryRequiresFreshOrigin'),
    'disable_clears_history': ('fresh', 'EverEnabledHistoryIsSticky'),
    'enable_omits_history': ('fresh', 'EverEnabledHistoryIsSticky'),
    'restart_forgets_history': ('fresh', 'EverEnabledHistoryIsSticky'),
    'mutable_active_admits': ('fresh', 'ObservationNeverAuthorizesAllocation'),
    'unknown_is_never': ('legacy_no_consent', 'NeverShortcutRequiresAllObservationGates'),
    'ignore_external_history': ('fresh', 'NeverShortcutRequiresAllObservationGates'),
    'omit_nonaccepting_snapshot': ('fresh', 'NeverShortcutRequiresAllObservationGates'),
    'delete_ack_is_retirement': ('fresh', 'NeverRouteNeedsAffirmativeNodeRetirement'),
    'accept_wrong_retirement': ('fresh', 'NeverRouteNeedsAffirmativeNodeRetirement'),
    'allow_schema2_reader': ('fresh', 'Schema3FencesNewHistory'),
    'enable_after_native_intent': ('fresh', 'NativeIntentBlocksPolicyReenable'),
    'bypass_consent_revoke': ('legacy_with_consent', 'ConsentRouteStillRequiresRevocation'),
    # Recheck the inherited safety obligations specifically along the new
    # no-consent route; the runner requires a witness that took that route.
    'omit_agent_stop': ('fresh', 'ReadyRequiresExactRemoteRetirementAndCleanup'),
    'omit_final_gpu_validation': ('fresh', 'ReadyRequiresExactRemoteRetirementAndCleanup'),
    'omit_full_wait': ('fresh', 'RestartCannotReuseMonotonicWait'),
    'omit_recovery_retirement': ('fresh', 'EveryIntroducedKeyRetiredBeforeReady'),
    'omit_recovery_401': ('fresh', 'EveryIntroducedKeyRetiredBeforeReady'),
    'omit_recovery_key_tracking': ('fresh', 'EveryIntroducedKeyRetiredBeforeReady'),
}

INHERITED_NEVER_ROUTE_MUTANTS = {'omit_agent_stop', 'omit_final_gpu_validation', 'omit_full_wait',
    'omit_recovery_retirement', 'omit_recovery_401', 'omit_recovery_key_tracking'}
