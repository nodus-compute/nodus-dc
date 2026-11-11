# Public CUDA readiness probe

This small Nodus-owned program uses the CUDA driver API to verify the visible GPU count, physical
UUIDs and a 1 MiB device-memory fill/copy on each device. It uses the existing `NODUS_PROBE_GPUS` and
`NODUS_PROBE_UUIDS` protocol. It is not a model-serving benchmark or a GPU, lending or native-return
qualification by itself.

The probe source is Apache-2.0, like this repository. The pinned CUDA development image provides
headers and a link-time stub during compilation; neither is copied into the final image. The final
Debian image retains its package notices. NVIDIA driver libraries are supplied by the host's normal
Container Toolkit/CDI installation. This image is Linux AMD64 only.

## Operator installation

Use the public `cuda-probe-v1` prerelease descriptor at
`https://github.com/nodus-compute/nodus-dc/releases/download/cuda-probe-v1/probe.json`.
If that release is absent or its descriptor does not confirm an anonymous pull, publication is not
complete: do not substitute a private registry credential or an unverified image.

Download the descriptor to a file and extract its immutable reference:

```sh
curl --fail --location --proto '=https' --proto-redir '=https' \
  --output probe.json \
  https://github.com/nodus-compute/nodus-dc/releases/download/cuda-probe-v1/probe.json
PROBE_IMAGE=$(python3 - <<'PY'
import json, re
d = json.load(open('probe.json'))
assert d['schemaVersion'] == 1 and d['anonymousPullVerified'] is True
assert d['image'] == 'ghcr.io/nodus-compute/nodus-dc-probe'
assert d['platform'] == 'linux/amd64'
assert re.fullmatch(r'sha256:[0-9a-f]{64}', d['digest'])
print(d['image'] + '@' + d['digest'])
PY
)
```

Pass `--probe-image "$PROBE_IMAGE"` to the ordinary signed node installer together with the existing
local-authority URL and private token-file arguments. Preserve its signature, driver, runtime, CDI
and allocation-authority checks. This replaces only the image's download location; it does not change
enrollment, consent, readiness or cleanup. The node performs the CUDA probe under its normal local
reservation. Do not run a separate GPU container alongside owner workloads to bypass that reservation.

## Publication and verification

The manual `Publish CUDA readiness probe` workflow runs only from this public repository's `main`.
It builds the allowlisted probe context from the digests in `build-inputs.json`, pushes by content
digest, then pulls that exact digest with an empty Docker credential configuration. No platform
image, private source history, cloud credentials or GPU execution is involved. Only after the
anonymous pull and image-config checks pass does it create the public `cuda-probe-v1` prerelease
with `probe.json`; it never changes an existing release or the latest package release.

GitHub initially creates container packages as private, even when their source repository is public.
For the first publication, an authorized package administrator may need to set this probe package's
visibility to public in its normal GitHub settings. A failed anonymous check leaves publication
incomplete; it is never bypassed with consumer credentials. Retry only the normal publication after
that setup, retaining the first negative run. See
[GitHub's package visibility documentation](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).

The descriptor binds the source commit, source/Dockerfile/input hashes, pinned bases and resulting
image digest. Anonymous transport verification is distinct from real GPU execution, which remains
part of the host's ordinary readiness and cleanup protocol.
