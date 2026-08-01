# TC-RFC-0024: Source-novel staged confirmation (Draft)

A provisional requirement SHALL be created from a frozen batch snapshot and
SHALL name its initial observation and control-group sets. The creating batch
cannot satisfy that requirement. By default, later confirmation MUST be an
authorized direct-local observation, failed independent patrol, or qualifying
threat observation from a control group absent from the initial set.

Relays, repeats, and a later interaction from the original group SHALL NOT be
considered novel confirmation in the default profile. The receiver SHALL record
both accepted and rejected confirmation candidates with their reason codes.

CT-075 through CT-079 and CT-089 exercise this rule.
