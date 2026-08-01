# TCOP USENIX 2027 Source Verification

All source roots were independently recomputed with the TCOP canonical root-digest algorithm.

| Artifact | Expected digest | Computed digest | Complete | Replayable | Pass |
|---|---|---|---:|---:|---:|
| live-agent-validation-final | 546f3547b727d08d452e7687191589e35839888285c622e8e639bdc6843d1b6b | 546f3547b727d08d452e7687191589e35839888285c622e8e639bdc6843d1b6b | True | True | True |
| agent-validation-scripted-parent | cfc5396a651d062699a7e4374b9813380e3677abc593e2a8a4d46848406eb11f | cfc5396a651d062699a7e4374b9813380e3677abc593e2a8a4d46848406eb11f | False | True | True |
| missing-evidence-round-admitted | 0ab19a9878f3853ab20558c9a4a94c697c0e30e17a97edf0f20756f0c5eb8e99 | 0ab19a9878f3853ab20558c9a4a94c697c0e30e17a97edf0f20756f0c5eb8e99 | True | True | True |
| federated-domain-parent | 194e46000494eeda6f3966ecf1d74c22e532a40d685014b57d8fc5986b324a50 | 194e46000494eeda6f3966ecf1d74c22e532a40d685014b57d8fc5986b324a50 | True | True | True |

The missing cd26169 source is explicitly documented as superseded by the source-artifact amendment; no silent substitution occurred.

## Frozen strategies

| Strategy | Profile | Full digest | Certified |
|---|---|---|---:|
| containment-first | P2 | 60a4c97851d19c6bcf09d24a063b480e9a29a49dca7e0665ead9013eaf8d2691 | True |
| balanced | V05_CONSOLIDATION_REDUCED | 4b2dfb385d71ee4ef3e8c598cf7cac4da80fdb62ed8d22d7ad241918c9e69890 | True |
| utility-preserving | F-10110000 | 7cf402995d0b4c0e6473aaad4cca7b420abcccf35b7844b65935d07ee9db8940 | True |
| forensic-oriented | P7 | e30ded1303d08c6067a5030d9e1741183bf30af96d218c2143bc1e21db237d96 | True |

## Amendment lineage

| Step | Digest | Predecessor match | Reason |
|---|---|---:|---|
| base-live | e5cf49806b7049d6b66018ba41b618d0be4ce9505e8be17b62fe932e008d8519 | True | sealed initial provider failure |
| 001 | 698ca3c116af6f8bcc74028731fb79543286d162bbc3abef01b13e0ee740aba5 | True | provider completion-token field |
| 002 | f9bccfcaeff8b9e256c679b5b6938bc3cfd3fd895e3a9a1129c93498d5df1652 | True | provider reasoning mode |
| 003 | cebc669a7a3cb8566d512d3be5c48d759c1676b461950ff9fbb0a10b2a967e96 | True | RA-03 eligibility alignment |
| 004 | 24a20e9c48a2061874503ed56b54f68d1de92bc6a6800a42fb5398170fbd17bd | True | completion-gate ordering |
| 005 | 2b1f92ff4481f6f3cb9a591c4ae77a3325757c4063d7c42439782e0474845f64 | True | derived RA-03 utility reconciliation |
| 006 | 546f3547b727d08d452e7687191589e35839888285c622e8e639bdc6843d1b6b | True | physical tcopd-a relay replay |
