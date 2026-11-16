# Nodus Datacenter

See your GPUs, manage allocations, and run inference or training on your own host.
Use it locally without a Nodus account. Connect to Nodus when you want fleet
monitoring and optional capacity sharing.

**Development prerelease · Linux · NVIDIA GPUs · Python 3.11+**

The local dashboard shows utilization, GPU memory, whole devices, MIG partitions
and held allocations. Missing or stale readings stay unavailable. Hardware and
end-to-end qualification are still in progress; see the [support matrix](docs/support-matrix.md).

## Start locally

Use a Linux GPU host with a supported NVIDIA driver, Docker and NVIDIA Container
Toolkit. Run as the trusted host operator with GPU and Docker permissions.

Download these three files from [dev14](https://github.com/nodus-compute/nodus-dc/releases/tag/v0.1.0-dev14)
into one empty directory:

- [GPU management package](https://github.com/nodus-compute/nodus-dc/releases/download/v0.1.0-dev14/nodus_datacenter-0.1.0.dev14-py3-none-any.whl)
- [Installer (`install.py`)](https://github.com/nodus-compute/nodus-dc/releases/download/v0.1.0-dev14/install.py)
- [Checksums (`SHA256SUMS`)](https://github.com/nodus-compute/nodus-dc/releases/download/v0.1.0-dev14/SHA256SUMS)

Open a Linux terminal in that directory. The paths below normally require a root
shell. Verify the downloaded files, then install and start the dashboard:

```sh
sha256sum --check --ignore-missing SHA256SUMS &&
python3 install.py install --wheel nodus_datacenter-0.1.0.dev14-py3-none-any.whl \
  --prefix /opt/nodus-dc --state-dir /var/lib/nodus-dc &&
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc serve
```

To build from source, follow [offline build and install](docs/operator-workflows.md#offline-build-and-install).

Open **http://127.0.0.1:7441/** and enter the token from the file path printed by
the daemon. For a remote host, forward port 7441 over SSH. The token stays in
page memory; **Lock view** clears it and the displayed inventory.

This starts in observation mode. It does not allocate GPUs, change drivers or
enable sharing. Use **Refresh inventory** to inspect the host. Check daemon
readiness from another terminal with:

```sh
/opt/nodus-dc/current/bin/nodus-dc --state-dir /var/lib/nodus-dc doctor
```

## Choose your next step

| I want to… | Start here |
| --- | --- |
| Run vLLM or SGLang | [Inference recipes](docs/serving-profiles.md) |
| Run training with persistent checkpoints | [Training guide](docs/training.md) |
| Allocate GPUs or configure MIG partitions | [Local allocation and partitioning](docs/operator-workflows.md#allocate-and-launch) |
| Connect a host and monitor it in Nodus | [Connection and service setup](docs/operations.md) · [Data-center dashboard](https://data-center.nodus-compute.ai) |
| Use an existing Kubernetes cluster | [Kubernetes integration](kubernetes/README.md) |
| Upgrade, recover or uninstall | [Operator workflows](docs/operator-workflows.md#recovery-and-upgrades) |

Before allocating, drain competing schedulers and explicitly select standalone
authority. Workloads use approved, preloaded, digest-pinned container images.
Partition changes require a maintenance lease. See the linked workflows for
commands and recovery behavior.

Capacity sharing is optional and separately authorized. Idle measurements alone
do not let Nodus run work. Your local workloads and external jobs share the same
allocation authority; reclaim keeps resources held until cleanup is verified.

## Support and boundaries

- Whole-GPU allocations, supported MIG partitions, and cooperating MPS clients
  have different isolation guarantees. MPS is for trusted cooperating workloads.
- Host administrators remain trusted. Host-confidential execution is not
  implemented; requests requiring it fail before allocation.
- Customer bare-metal handback, cash settlement, and production performance
  qualification remain incomplete. The dashboard does not certify those paths.

Read the [support matrix](docs/support-matrix.md), [privacy and isolation model](docs/threat-model.md),
[API reference](docs/api.md), and [dev14 changes](docs/release-dev14.md) for details.

Apache-2.0. CPU checks: `PYTHONPATH=src python3 -m unittest discover -s tests`.
