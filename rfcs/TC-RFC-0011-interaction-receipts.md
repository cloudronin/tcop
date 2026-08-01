# TC-RFC-0011: Interaction receipts (Draft)

An interaction receipt binds an observer, subject, virtual time window,
capability, and hashes of the request and response. It is signed by the
observer and may include a subject acknowledgement. An acknowledgement proves
only that the identified interaction occurred; it is neither a trust vote nor
agreement with the observer's interpretation.

The default v0.2 resolver requires a valid receipt before independent evidence
can contribute corroboration. A receipt refusal is retained as unilateral
transport evidence and is explicitly recorded.
