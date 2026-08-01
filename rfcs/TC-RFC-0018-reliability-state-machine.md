# TC-RFC-0018: Reliability state machine, probation, and hysteresis (Draft)

Recovery from suspicious, restricted, or quarantined status SHALL enter
probation, not normal. Minimum dwell periods, asymmetric entry/recovery rules,
and a fixed-point virtual-time probation ramp prevent immediate restoration.
New credible negative evidence can reverse probation. Silence is not positive
evidence and confidence decays toward uncertainty.

Same-time inputs SHALL be evaluated using a frozen pre-batch ledger and
atomically committed afterwards. CT-046–CT-051, CT-059, and B-032/B-037 test
these requirements.
