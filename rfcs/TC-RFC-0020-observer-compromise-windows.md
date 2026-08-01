# TC-RFC-0020: Observer compromise windows and historical evidence (Draft)

Historical evidence remains immutable and retains its original local weighting
projection by default. A resolver MAY discount an historical observation only
when a compromise record names both that observation and an inclusive,
explicitly evidenced interval containing its issue time.

No later compromise automatically collapses all earlier reports. CT-055–CT-057
and B-040/B-041 exercise prospective and bounded retrospective treatment.
