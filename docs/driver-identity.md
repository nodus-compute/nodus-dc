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

If hardware changes but final observation fails, both the lease and configuration
are quarantined. The original plan remains recorded as uncertain, so ordinary
release cannot clear ownership from a process listing alone. Existing explicit
recovery and execution-fence requirements still apply. Disabling MIG and recovery
do not acquire an additional driver preflight requirement.

This metadata describes a driver build, not a module-load incarnation or an
attestation. These checks do not qualify a runtime, tenant isolation, connected
partition execution or host-confidential workloads.
