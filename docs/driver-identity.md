# Driver identity during MIG configuration

On hosts with a durable partition authority, enabling MIG first checks the loaded
driver while holding the validated local GPU configuration lease. This check works
before MIG instances exist. Missing, inconsistent or malformed driver metadata
refuses the request before hardware mutation; the lease stays reserved.

The module source-version field accepts exactly 23 or 24 hexadecimal characters.
The exact observed characters are retained in the device binding. Linux 6.8 uses
a [25-byte buffer](https://github.com/torvalds/linux/blob/v6.8/scripts/mod/modpost.h#L99),
passes [one byte less](https://github.com/torvalds/linux/blob/v6.8/scripts/mod/modpost.c#L1568)
to a [NUL-terminated formatter](https://github.com/torvalds/linux/blob/v6.8/scripts/mod/sumversion.c#L207),
and therefore emits 23 characters. Boot identity, inventory/module version,
driver banner and exact device checks remain required.

The read-only preflight also requires the kernel's character-device registrations.
It accepts either the older unified `nvidia-frontend` registration or the separate
`nvidia` and `nvidiactl` registrations with equal observed major numbers, plus
`nvidia-uvm` and `nvidia-caps`. Duplicate, mixed and incomplete layouts are refused;
device files never substitute for a missing registration. NVIDIA documents these
layouts in its [535.129.03 frontend](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/535.129.03/kernel-open/nvidia/nv-frontend.c#L346)
and [580.105.08 initialization](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/580.105.08/kernel-open/nvidia/nv.c#L900).
Full binding still checks each character device's exact major and minor.

Only `/proc/driver/nvidia-caps/mig-minors` has a 128 KiB read limit: the
[580.105.08 static tables](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/580.105.08/kernel-open/nvidia/nv-caps.c#L67)
emit 4,322 lines totaling 109,408 bytes, including absent GPUs. Other metadata
retains its 64 KiB limit. Oversized or ambiguous mappings remain refused. No
module is loaded and no device file is created by these observations.

If hardware changes but final observation fails, both the lease and configuration
are quarantined. The original plan remains recorded as uncertain, so ordinary
release cannot clear ownership from a process listing alone. Existing explicit
recovery and execution-fence requirements still apply. Disabling MIG and recovery
do not acquire an additional driver preflight requirement.

This metadata describes a driver build, not a module-load incarnation or an
attestation. These checks do not qualify a runtime, tenant isolation, connected
partition execution or host-confidential workloads.
