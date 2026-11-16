# Local training and checkpoints

The training descriptor runs an operator-supplied PyTorch program on one exclusive GPU or one existing MIG instance. Use two independent leases and output directories to pack two independent jobs. Distributed training across partitions, automatic checkpointing, transparent migration and improved training throughput are not qualified by this adapter.

Preload a digest-pinned Linux image containing the required PyTorch version and CUDA libraries. No image, dataset or dependency is downloaded by the descriptor or runtime. The package itself still has no PyTorch dependency. Prepare dedicated code, optional data, and output directories on the host. Output directories must already exist, be owned by the daemon's UID (normally root), and have mode 0700. Supply their canonical absolute paths without symlinks. Keep them outside the authority state and installation directories.

```sh
sudo install -d -m 0700 /srv/nodus-checkpoints/job-a
sudo /opt/nodus-dc/current/bin/python -m nodus_dc.training \
  --image YOUR_PRELOADED_IMAGE@sha256:EXACT_DIGEST \
  --code-directory /srv/training-code \
  --script train.py \
  --data-directory /srv/training-data \
  --output-directory /srv/nodus-checkpoints/job-a \
  -- --checkpoint-dir /outputs > train.json
nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone reserve \
  --resource GPU_OR_MIG_EXACT_UUID --mode hardware_partition \
  --ttl-seconds 1800 --request-key train-a
nodus-dc --state-dir /var/lib/nodus-dc --allocation-authority standalone start \
  RETURNED_LEASE_ID --generation RETURNED_GENERATION --workload train.json
```

Run descriptor generation and allocation as the same operator UID as the daemon (normally root). The image's configured effective UID must also be able to write the output directory, normally UID 0 for a root-owned mode-0700 directory. The package does not change image users or loosen directory permissions. Use `exclusive_gpu` for a physical GPU. The code appears read-only at `/code`, optional data read-only at `/data`, and the explicitly authorized output directory writable at `/outputs`. Networking is disabled. The root filesystem remains read-only and the ordinary capability restrictions still apply. Programs must write checkpoints to `/outputs`; they own checkpoint frequency, format and resume behavior. For PyTorch, save the model and optimizer state, progress and any random generator or data-loader state needed by your training algorithm. Loading a checkpoint does not restore an external sampler or distributed job automatically.

The authority refuses overlapping output directories among held jobs, including quarantined jobs and clients of one MPS pool. It also refuses writable overlap with input mounts or local authority state. Successful release removes owned containers and verifies GPU cleanup; it deliberately retains checkpoint files. A later independent lease may explicitly reuse a released job's directory to resume. Never share one output directory between concurrent jobs or delete it before checking the retained results. Files are trusted operator data; this feature does not encrypt them, set a disk quota, or protect them from host administrators. Monitor free storage. A full disk or failed checkpoint must be handled by the training program.

## Reproducible checkpoint example

[`examples/training/checkpoint_training.py`](../examples/training/checkpoint_training.py) uses a small MLP, dropout and AdamW on synthetic local data. It runs an uninterrupted baseline, saves a midpoint checkpoint in another process, resumes in a fresh process, then compares exact final model, optimizer, RNG, losses and step. It also requires reduced finite loss. It loads only its own checkpoints with `weights_only=True`. This is a correctness example, not a model-convergence or performance benchmark.

Set the code directory to `examples/training`, script to `checkpoint_training.py`, and arguments to `--device cuda --steps 128`. CUDA is required and exactly one device must be visible. `--device cpu` is an explicit logic-only check. Results and three checkpoints remain in `/outputs`; the example refuses to overwrite prior results. Each worker has a 120-second timeout. `--hold-seconds N` (0–120) optionally keeps a successful process alive for bounded lifecycle observation. GPU lease expiry and release still follow the normal authority lifecycle and do not certify checkpoint validity.

Before releasing, inspect `result.json` for `passed: true`, the actual device, PyTorch version and exact checkpoint hashes. Check the actual container exit code separately; a successful `start` only means it entered the running state. Release using the returned lease ID and generation. The package does not automatically return capacity just because a batch process exits.

The example's checkpoint fields follow [PyTorch's saving/loading guidance](https://docs.pytorch.org/tutorials/beginner/saving_loading_models). MIG selection follows [NVIDIA's device guidance](https://docs.nvidia.com/datacenter/tesla/mig-user-guide/latest/getting-started-with-mig.html). Actual GPU/driver/image combinations and any throughput benefit still require the separate hardware qualification record.
