Public Linux AMD64 CUDA readiness probe for the normal signed node installer.

`probe.json` records the immutable image digest, source commit, pinned build inputs and successful
anonymous pull. Pass that exact digest with `--probe-image`; preserve the normal driver, CDI,
runtime, local-allocation and signature checks. No registry credential is needed by the operator.

Only the Nodus probe source/binary and its Debian runtime are distributed. CUDA development headers
and link-time stubs remain in the build stage; the host supplies the NVIDIA driver through CDI.

This publication proves source/build/anonymous-download binding only. It does not qualify a GPU,
CUDA workload, capacity lending, model serving, native return or physical bare metal. Existing
standalone package releases are unchanged; this prerelease is not marked latest.
