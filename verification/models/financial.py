"""Finite cash-payable ledger and processor reconciliation, with symbolic amounts.

Amounts are synthetic minor-unit tokens for arithmetic exploration; they are not
Nodus prices, payout shares, commercial terms or processor execution evidence.
"""
from dataclasses import dataclass, replace
from checker import Transition


def put(values,index,value):
    return tuple(value if i==index else old for i,old in enumerate(values))


@dataclass(frozen=True)
class State:
    worker_up: bool=True
    qualified_usage: bool=False
    charge_intent: bool=False
    charge_outcome: str='none'
    remote_charge_count: int=0
    charge_observed: bool=False
    authoritative_revision: int=-1
    settled_revision: int=-1
    highest_seen_revision: int=-1
    settled_target: int=0
    payable: int=0
    pending: int=0
    transferred_booked: int=0
    reserve_reads: tuple=(-1,-1)
    payout_amounts: tuple=(0,0)
    attempt_age: tuple=(0,0)
    remote_transfer_counts: tuple=(0,0)
    transfer_booked: tuple=(False,False)
    bank_truth: tuple=('none','none')
    bank_local: tuple=('none','none')
    bank_final_seen: tuple=(False,False)
    reservation_breach: bool=False


class FinancialModel:
    name='cash_financial_replay'
    bounds={'qualified_usage_lineages':1,'charge_business_ids':1,'settlement_revisions':3,
            'payout_business_ids':2,'worker_processes':'one active, arbitrary crash/restart',
            'symbolic_target_values':[2,1,0],'payout_amount_choices':[1,2],
            'currencies':1,'retry_age_classes':['not_attempted','within_same_key_window','expired_reconcile_only'],
            'delivery':'Any previously published settlement revision can be redelivered in any order indefinitely.'}
    assumptions=[
        'Actual accepted commercial terms freeze the settlement function; symbolic targets 2,1,0 represent earnings then two corrections, not prices or payout percentages.',
        'Charge and payout business identities persist across crashes; processor idempotency is an explicit external contract to verify separately.',
        'Settlement revision and its ledger delta commit atomically; actual database transaction enforcement requires conformance.',
        'Cash payable is separate from credits. Negative payable after post-transfer refund is allowed and blocks new payout reservation.',
        'Transfer confirmation and bank payout are separate. Failed bank payout does not authorize a second transfer.',
        'Within-window retries reuse the same processor key. Expired/ambiguous attempts reconcile or remain frozen; no fresh key is created.',
        'One currency and exact integer token arithmetic; rounding/FX and real micros-to-cents behavior require separate implementation tests.',
        'No fairness or eventual processor success/delivery assumed. This models processor effects; it does not call a processor.'
    ]
    properties=['I_ChargeIdempotency','I_SettlementRevisionMonotonic','I_BalanceConservation',
                'I_NoOverPayoutReservation','I_TransferIdempotency','I_QualifiedUsageLineage',
                'I_HonestBankPayoutState','I_NoDuplicateTransferForFailedBankPayout']

    def initial(self):
        return State()

    def successors(self,s,mutation):
        if s.worker_up:
            yield Transition('CrashWorker',replace(s,worker_up=False))
        else:
            yield Transition('RestartWorker',replace(s,worker_up=True))
        if not s.worker_up:
            return
        if not s.qualified_usage:
            yield Transition('FinalizeQualifiedUsage',replace(s,qualified_usage=True))
        if s.qualified_usage and not s.charge_intent:
            yield Transition('CreateChargeIntent',replace(s,charge_intent=True))
        if s.charge_intent:
            if s.charge_outcome=='none':
                yield Transition('ProcessorChargeAcceptedResponseUnknown',replace(s,charge_outcome='succeeded',remote_charge_count=1,authoritative_revision=0))
                yield Transition('ProcessorChargeFailed',replace(s,charge_outcome='failed'))
            elif s.charge_outcome=='succeeded':
                count=s.remote_charge_count+1 if mutation=='new_charge_key_on_retry' else s.remote_charge_count
                if count<=2:
                    yield Transition('RetryChargeSameBusinessIdentity',replace(s,remote_charge_count=count))
                yield Transition('ReconcileCharge',replace(s,charge_observed=True))
        if 0<=s.authoritative_revision<2:
            yield Transition('AuthoritativeRefundCorrection',replace(s,authoritative_revision=s.authoritative_revision+1))
        for revision in range(s.authoritative_revision+1):
            if not s.charge_observed:
                continue
            target=2-revision
            highest=max(s.highest_seen_revision,revision)
            if revision>s.settled_revision:
                delta=target-s.settled_target
                yield Transition(f'ApplySettlementRevision:{revision}',replace(s,settled_revision=revision,highest_seen_revision=highest,settled_target=target,payable=s.payable+delta))
            elif mutation=='duplicate_earnings_post' and target>0:
                yield Transition(f'ReplaySettlementDoublePost:{revision}',replace(s,payable=s.payable+target,highest_seen_revision=highest))
            elif mutation=='accept_stale_settlement' and revision<s.settled_revision:
                yield Transition(f'ApplyStaleSettlementRevision:{revision}',replace(s,settled_revision=revision,highest_seen_revision=highest,settled_target=target,payable=s.payable+target-s.settled_target))
            else:
                yield Transition(f'IgnoreSettlementReplay:{revision}',s)
        for i in range(2):
            amount=s.payout_amounts[i]
            if amount==0:
                # Models a stale preflight read followed by the actual atomic
                # reserve. Normal admission uses current payable under lock.
                if s.payable>0:
                    yield Transition(f'ReadPayable:{i}',replace(s,reserve_reads=put(s.reserve_reads,i,s.payable)))
                for choice in (1,2):
                    if s.reserve_reads[i]<choice:
                        continue
                    if s.payable<choice and mutation!='non_atomic_payout_reserve':
                        continue
                    yield Transition(f'ReservePayout:{i}:{choice}',replace(s,payout_amounts=put(s.payout_amounts,i,choice),payable=s.payable-choice,pending=s.pending+choice,reservation_breach=s.reservation_breach or s.payable<choice))
                continue
            age=s.attempt_age[i]
            count=s.remote_transfer_counts[i]
            if age<2 and (s.payable>=0 or count>0):
                # Timestamp/attempt identity persisted before the call. Either
                # provider effect or no effect may occur before a lost reply.
                yield Transition(f'TransferNetworkFailureNoEffect:{i}',replace(s,attempt_age=put(s.attempt_age,i,1)))
                next_count=1 if count==0 else count
                yield Transition(f'ProcessorTransferAcceptedResponseUnknown:{i}',replace(s,attempt_age=put(s.attempt_age,i,1),remote_transfer_counts=put(s.remote_transfer_counts,i,next_count),bank_truth=put(s.bank_truth,i,'pending' if s.bank_truth[i]=='none' else s.bank_truth[i])))
                if age==1:
                    yield Transition(f'ExpireRetryWindow:{i}',replace(s,attempt_age=put(s.attempt_age,i,2)))
            elif mutation=='fresh_key_after_retry_expiry' and count==1:
                yield Transition(f'UnsafeFreshKeyAfterExpiry:{i}',replace(s,remote_transfer_counts=put(s.remote_transfer_counts,i,2)))
            if count==1 and not s.transfer_booked[i]:
                yield Transition(f'ReconcileTransferExactlyOnce:{i}',replace(s,transfer_booked=put(s.transfer_booked,i,True),pending=s.pending-amount,transferred_booked=s.transferred_booked+amount))
            elif count==1 and s.transfer_booked[i]:
                yield Transition(f'ReplayTransferConfirmationIgnored:{i}',s)
            if s.bank_truth[i]=='pending':
                yield Transition(f'BankPayoutSucceeded:{i}',replace(s,bank_truth=put(s.bank_truth,i,'paid')))
                yield Transition(f'BankPayoutFailedFundsRemainConnected:{i}',replace(s,bank_truth=put(s.bank_truth,i,'failed')))
            if s.bank_truth[i]!='none' and s.transfer_booked[i]:
                # Reconciliation queries the processor's current outcome;
                # stale pending deliveries cannot overwrite a final result.
                yield Transition(f'ReconcileBankOutcome:{i}',replace(s,bank_local=put(s.bank_local,i,s.bank_truth[i]),bank_final_seen=put(s.bank_final_seen,i,s.bank_truth[i] in ('paid','failed'))))
                if mutation=='stale_bank_event_regresses' and s.bank_final_seen[i]:
                    yield Transition(f'ApplyStaleBankPending:{i}',replace(s,bank_local=put(s.bank_local,i,'pending')))
                else:
                    yield Transition(f'IgnoreStaleBankPending:{i}',s)
            if mutation=='retransfer_failed_bank_payout' and s.bank_local[i]=='failed':
                yield Transition(f'UnsafeTransferAfterBankFailure:{i}',replace(s,remote_transfer_counts=put(s.remote_transfer_counts,i,2)))

    def violations(self,s):
        bad=[]
        if s.remote_charge_count>1:
            bad.append('I_ChargeIdempotency')
        if s.settled_revision!=s.highest_seen_revision:
            bad.append('I_SettlementRevisionMonotonic')
        if s.payable+s.pending+s.transferred_booked!=s.settled_target:
            bad.append('I_BalanceConservation')
        if s.reservation_breach:
            bad.append('I_NoOverPayoutReservation')
        if any(count>1 for count in s.remote_transfer_counts):
            bad.append('I_TransferIdempotency')
        if s.settled_revision>=0 and not (s.qualified_usage and s.charge_intent and s.charge_outcome=='succeeded' and s.charge_observed):
            bad.append('I_QualifiedUsageLineage')
        for i in range(2):
            if s.bank_local[i]=='paid' and (s.bank_truth[i]!='paid' or not s.transfer_booked[i]):
                bad.append('I_HonestBankPayoutState')
            if s.bank_final_seen[i] and s.bank_local[i] not in ('paid','failed'):
                bad.append('I_HonestBankPayoutState')
        return list(dict.fromkeys(bad))
