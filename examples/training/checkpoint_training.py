"""Small offline PyTorch training/checkpoint/resume correctness example.

Run in a training image with PyTorch installed. CUDA is mandatory by default;
--device cpu is an explicit local logic check, never GPU qualification.
The parent compares fresh worker processes; this is not a throughput benchmark.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

# Must precede PyTorch/CUDA initialization for deterministic CUDA GEMMs.
os.environ["CUBLAS_WORKSPACE_CONFIG"] = ":4096:8"
import torch


def atomic_save(value, destination):
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".checkpoint-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            torch.save(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, destination)
            fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            temporary.unlink(missing_ok=True)


def worker(args):
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    torch.manual_seed(17)
    if args.device == "cuda":
        if not torch.cuda.is_available() or torch.cuda.device_count() != 1:
            raise RuntimeError("this example requires exactly one visible CUDA device")
        torch.cuda.manual_seed_all(17)
    device = torch.device(args.device)
    model = torch.nn.Sequential(torch.nn.Linear(32, 64), torch.nn.ReLU(),
                                torch.nn.Dropout(0.1), torch.nn.Linear(64, 4)).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.01, weight_decay=0.01)
    generator = torch.Generator().manual_seed(41)
    inputs = torch.randn(128, 32, generator=generator).to(device)
    targets = inputs @ torch.randn(32, 4, generator=generator).to(device)
    start, losses = 0, []
    if args.phase == "resume":
        saved = torch.load(args.output / "prefix.pt", map_location=device, weights_only=True)
        model.load_state_dict(saved["model"])
        optimizer.load_state_dict(saved["optimizer"])
        start, losses = saved["step"], saved["losses"]
        torch.set_rng_state(saved["cpu_rng"].cpu())
        if args.device == "cuda":
            torch.cuda.set_rng_state(saved["cuda_rng"].cpu())
    stop = args.steps // 2 if args.phase == "prefix" else args.steps
    started = time.time()
    for _ in range(start, stop):
        optimizer.zero_grad(set_to_none=True)
        loss = torch.nn.functional.mse_loss(model(inputs), targets)
        if not torch.isfinite(loss).item():
            raise RuntimeError("nonfinite training loss")
        loss.backward()
        optimizer.step()
        losses.append(float(loss.detach().cpu()))
    if args.device == "cuda":
        torch.cuda.synchronize()
    finished = time.time()
    result = {"step": stop, "model": model.state_dict(), "optimizer": optimizer.state_dict(),
              "cpu_rng": torch.get_rng_state(),
              "cuda_rng": torch.cuda.get_rng_state() if args.device == "cuda" else None,
              "losses": losses, "training_started_at": started, "training_finished_at": finished,
              "device": args.device, "torch_version": str(torch.__version__),
              "device_name": torch.cuda.get_device_name(0) if args.device == "cuda" else "cpu",
              "visible_cuda_devices": torch.cuda.device_count() if args.device == "cuda" else 0}
    atomic_save(result, args.output / (args.phase + ".pt"))


def equal(left, right):
    if isinstance(left, torch.Tensor):
        return isinstance(right, torch.Tensor) and torch.equal(left, right)
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(equal(left[key], right[key]) for key in left)
    if isinstance(left, (list, tuple)):
        return len(left) == len(right) and all(equal(a, b) for a, b in zip(left, right))
    return left == right


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", choices=("cuda", "cpu"), default="cuda")
    parser.add_argument("--output", type=Path, default=Path("/outputs"))
    parser.add_argument("--steps", type=int, default=128)
    parser.add_argument("--hold-seconds", type=int, default=0,
                        help="remain running after success for a bounded lifecycle inspection")
    parser.add_argument("--phase", choices=("baseline", "prefix", "resume"))
    args = parser.parse_args()
    if not 32 <= args.steps <= 4096 or not 0 <= args.hold_seconds <= 120 or not args.output.is_dir():
        parser.error("steps must be 32..4096, hold-seconds 0..120, and output must exist")
    if args.phase:
        worker(args)
        return
    # Refuse overwriting results from an earlier invocation. New experiments
    # receive a new private output directory; checkpoints remain after release.
    expected = ("baseline.pt", "prefix.pt", "resume.pt", "result.json")
    if any((args.output / name).exists() for name in expected):
        parser.error("output already contains a run; choose a new output directory")
    for phase in ("baseline", "prefix", "resume"):
        subprocess.run([sys.executable, str(Path(__file__).resolve()), "--phase", phase,
                        "--device", args.device, "--output", str(args.output),
                        "--steps", str(args.steps)], check=True, timeout=120)
    baseline = torch.load(args.output / "baseline.pt", map_location="cpu", weights_only=True)
    resumed = torch.load(args.output / "resume.pt", map_location="cpu", weights_only=True)
    checks = {name + "_exact": equal(baseline[name], resumed[name])
              for name in ("model", "optimizer", "cpu_rng", "cuda_rng", "losses", "step")}
    checks["loss_reduced"] = (all(math.isfinite(v) for v in resumed["losses"])
                              and resumed["losses"][-1] < resumed["losses"][0] * 0.5)
    result = {"schema": "nodus.training-checkpoint-example/1", "passed": all(checks.values()),
              "device": args.device, "gpu_execution": args.device == "cuda", "checks": checks,
              "torch_version": resumed["torch_version"], "device_name": resumed["device_name"],
              "visible_cuda_devices": resumed["visible_cuda_devices"],
              "steps": args.steps, "initial_loss": resumed["losses"][0], "final_loss": resumed["losses"][-1],
              "training_intervals": {phase: {key: torch.load(args.output / (phase + ".pt"),
                    map_location="cpu", weights_only=True)[key]
                    for key in ("training_started_at", "training_finished_at")}
                    for phase in ("baseline", "prefix", "resume")},
              "checkpoint_sha256": {name: hashlib.sha256((args.output / name).read_bytes()).hexdigest()
                                     for name in expected[:3]},
              "performance_or_convergence_qualification": False}
    with (args.output / "result.json").open("x") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps(result, allow_nan=False), flush=True)
    if not result["passed"]:
        raise SystemExit(1)
    time.sleep(args.hold_seconds)


if __name__ == "__main__":
    main()
