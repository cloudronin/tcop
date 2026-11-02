"""Receiver-local study intake; generic TCX validation semantics stay unchanged.

The existing signed v0.1 metadata carries interaction_id, receipt reference
and session_id. No new TCX field or wire schema is introduced. A receipt
enters the local registry only through the receiver's acquisition controller.
"""
from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass
from fractions import Fraction
from threading import RLock
import re
from typing import Any

from .canonical import canonical_bytes, unsigned_envelope
from .identity import verify_signature
from .time import parse_rfc3339
from .validation import ObservationValidator
from .witness import receipt_hash, verify_interaction_receipt
from .external_foundation_seals import require


@dataclass(frozen=True)
class ValidatedTCX:
    observation_id: str
    nonce: str
    sandbox_id: str
    generation: str
    ready_at_ms: float
    selected: tuple[str, str]
    _issuer: object


@dataclass(frozen=True)
class IntakeResult:
    accepted: bool
    code: str | None
    event: dict[str, Any]
    ticket: ValidatedTCX | None


class ReceiverIntake:
    def __init__(self, validator: ObservationValidator, *, receiver_id: str, sandbox_id: str,
                 generation: str, subject_id: str, session_id: str, clock_origin_seconds: int, tick_duration_ns: int = 1000000, ready_clock=None):
        require(isinstance(validator,ObservationValidator) and validator.enforce_scope and validator.enforce_expiration,
                'study intake requires the strict v0.1 validator with authority and expiry enabled')
        self.validator=validator
        self.receiver_id=receiver_id;self.sandbox_id=sandbox_id;self.generation=generation
        self.subject_id=subject_id;self.session_id=session_id;self.origin=clock_origin_seconds
        require(type(tick_duration_ns) is int and tick_duration_ns>0,"positive exact trace quantum required")
        self.tick_duration_ns=tick_duration_ns;self.ready_clock=ready_clock
        self._lock=RLock();self._issuer=object();self._receipts={};self._tickets={};self._claimed=set();self._delivery=0

    def register_receipt(self, receipt, *, receiver_id, sandbox_id, generation, session_id):
        """Trusted acquisition entry point, never called from observation metadata."""
        r=deepcopy(receipt)
        ok,_=verify_interaction_receipt(r,self.validator.registry)
        require(ok,'cannot register an unverified receipt')
        with self._lock:
            self._receipts[receipt_hash(r)]=(r,receiver_id,sandbox_id,generation,session_id)

    def claim(self,ticket: ValidatedTCX) -> None:
        """Reserve the single write, including uncertain/failed transport attempts."""
        with self._lock:
            require(isinstance(ticket,ValidatedTCX) and ticket._issuer is self._issuer
                    and self._tickets.get(ticket.observation_id) is ticket
                    and ticket.observation_id not in self._claimed,'TCX was not accepted here or already submitted')
            self._claimed.add(ticket.observation_id)

    def receive(self, observation, *, now, t: int, selected, authority) -> IntakeResult:
        # Lock covers validation, correlation and both replay tokens. A rejected
        # observation never calls either replay commit operation.
        o=deepcopy(observation)
        with self._lock:
            require(type(t) is int and t>=0,'exact nonnegative trace tick required')
            require(Fraction(str(now-self.origin))*10**9==t*self.tick_duration_ns,'wall clock must map exactly to the common trace quantum')
            self._delivery+=1
            observer=o.get('observer',{});subject=o.get('subject',{});identity=self.validator.registry.resolve(observer.get('id'),observer.get('key_id'))
            authorized=bool(identity and not identity.revoked and identity.trust_domain==observer.get('trust_domain')
                            and self.validator.registry.validate_authority_chain(identity.observer_id)
                            and isinstance(o.get('scope'),list) and bool(o['scope'])
                            and all(identity.allows(scope,o.get('observation_type','')) for scope in o['scope']))
            try:
                signature_valid=bool(identity and o.get('signature',{}).get('algorithm')=='ed25519'
                    and verify_signature(identity,canonical_bytes(unsigned_envelope(o)),o['signature'].get('value','')))
            except (TypeError,ValueError):signature_valid=False
            try:
                verdict=self.validator.validate(o,now)
                code=None if verdict.accepted else verdict.code
            except (KeyError,ValueError,TypeError,AttributeError):code='schema_invalid'
            metadata=o.get('metadata',{})
            local=self._receipts.get(metadata.get('interaction_receipt_hash')) if isinstance(metadata,dict) else None
            interaction=metadata.get('interaction_id') if isinstance(metadata,dict) else None
            receipt=local[0] if local else None
            verified=bool(receipt and verify_interaction_receipt(receipt,self.validator.registry)[0])
            owned=bool(local and local[1:]==(self.receiver_id,self.sandbox_id,self.generation,self.session_id)
                and metadata.get('session_id')==self.session_id and subject.get('id')==self.subject_id
                and receipt.get('subject_id')==self.subject_id and receipt.get('observer_id')==observer.get('id'))
            nonce=o.get('nonce');oid=o.get('observation_id')
            if code is None and (not isinstance(nonce,str) or re.fullmatch(r'[A-Za-z0-9_.:/-]{1,128}',nonce) is None):code='nonce_required'
            if code is None and (not isinstance(oid,str) or re.fullmatch(r'[A-Za-z0-9_.:/-]{1,128}',oid) is None):code='observation_id_invalid'
            if code is None and (oid in self.validator.replay.observation_ids or nonce in self.validator.replay.nonces):code='replay_detected'
            if code is None and not (verified and owned and interaction and interaction==receipt.get('interaction_id')):code='receipt_correlation_invalid'
            # Selection comes from the receiver-local fixed table, never TCX data.
            if code is None and not (isinstance(selected,list) and len(selected)==2 and selected[0] in {'deny_egress','revoke_credential','freeze'} and isinstance(selected[1],str) and selected[1]):code='selection_invalid'
            if self.ready_clock is not None:
                ready_now,ready_t=self.ready_clock()
                require(type(ready_t) is int and ready_t>=t and Fraction(str(ready_now-self.origin))*10**9==ready_t*self.tick_duration_ns,'ready clock must preserve the exact common tick')
                now,t=ready_now,ready_t
                if code is None and parse_rfc3339(o['expires_at'])<now:code='expired'
            try:
                ticks=Fraction((parse_rfc3339(o['expires_at'])-self.origin)*10**9,self.tick_duration_ns)
                expires=ticks.numerator if ticks.denominator==1 else None
                if code is None and expires is None:code='clock_not_representable'
            except (KeyError,ValueError,TypeError):expires=None
            ticket=None
            if code is None:
                require(self.validator.replay.use_challenge_nonce(nonce),'nonce changed during atomic intake')
                self.validator.commit(o)
                ticket=ValidatedTCX(oid,nonce,self.sandbox_id,self.generation,t*self.tick_duration_ns/1000000,tuple(selected),self._issuer)
                self._tickets[oid]=ticket
            event={'type':'receive','t':t,'authority':deepcopy(authority),'message':f'delivery-{self._delivery}',
                'observation_id':oid,'nonce':nonce,'signature_valid':signature_valid,'peer_authorized':authorized,
                'expires_at':expires,'interaction_id':interaction,'receipt_interaction_id':receipt.get('interaction_id') if receipt else None,
                'receipt_verified':verified,'receipt_receiver_local':owned,'decision':'accepted' if code is None else 'rejected',
                'selected':deepcopy(selected) if code is None else None}
            return IntakeResult(code is None,code,event,ticket)
