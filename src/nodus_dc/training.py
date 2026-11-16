"""Build an offline single-device training workload; never allocate or launch it."""
import argparse
import json
from pathlib import Path

from .backend import IMAGE, NvidiaDockerBackend
from .errors import Error


def build_workload(image, code_directory, script, output_directory, *, arguments=(), data_directory=None):
    """Use a preloaded training image, read-only code/data and persistent /outputs.

    Each independent job uses one whole GPU or one MIG instance. This adapter
    does not add distributed training, automatic checkpointing, or migration.
    The supplied program owns its checkpoint format and resume arguments.
    """
    if not isinstance(image, str) or not IMAGE.fullmatch(image):
        raise Error("invalid_training_image", "training needs a preloaded digest-pinned image", 400)
    code = Path(code_directory).expanduser().resolve()
    relative = Path(script)
    if (not code.is_dir() or relative.is_absolute() or ".." in relative.parts
            or not (code / relative).is_file() or not (code / relative).resolve().is_relative_to(code)):
        raise Error("invalid_training_script", "script must be a file inside code_directory", 400)
    if not isinstance(arguments, (tuple, list)) or any(not isinstance(arg, str) or "\0" in arg for arg in arguments):
        raise Error("invalid_training_arguments", "training arguments must be an argv list", 400)
    workload = {
        "image": image, "entrypoint": "/usr/bin/env",
        "command": ["PYTHONUNBUFFERED=1", "python3", str(Path("/code") / relative), *arguments],
        "mounts": [{"source": str(code), "target": "/code"}],
        "output_directory": str(Path(output_directory).expanduser().absolute()),
        "network": "none", "shm_bytes": 1024**3,
    }
    if data_directory is not None:
        workload["mounts"].append({"source": str(Path(data_directory).expanduser().resolve()), "target": "/data"})
    NvidiaDockerBackend(host_id="descriptor-only").validate_workload(workload, {"mode": "exclusive_gpu"})
    return workload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--code-directory", required=True)
    parser.add_argument("--script", required=True)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--data-directory")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    try:
        workload = build_workload(args.image, args.code_directory, args.script, args.output_directory,
                                  arguments=arguments, data_directory=args.data_directory)
    except (Error, OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(workload, indent=2))


if __name__ == "__main__":
    main()
