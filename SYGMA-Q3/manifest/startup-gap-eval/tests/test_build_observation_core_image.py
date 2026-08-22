#!/usr/bin/env python3
"""Tests for immutable observation-core image publication."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


EVAL_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = EVAL_ROOT / "scripts" / "build_observation_core_image.sh"
CORE = EVAL_ROOT.parents[1] / "sygma_eBPF" / "core"
DIGEST = "sha256:" + "d" * 64
CONFIG_ID = "sha256:" + "c" * 64
MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"


class ObservationCoreImagePublicationTests(unittest.TestCase):
    def make_fake_docker(self, directory: Path) -> Path:
        fake = directory / "docker"
        fake.write_text(
            textwrap.dedent(
                r'''#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import shutil
import sys

args = sys.argv[1:]
state = pathlib.Path(os.environ["FAKE_DOCKER_STATE"])
core = pathlib.Path(os.environ["FAKE_CORE"])
state.mkdir(parents=True, exist_ok=True)
with (state / "commands.jsonl").open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\n")

digest = "sha256:" + "d" * 64
registry_digest = (
    "sha256:" + "e" * 64
    if os.environ.get("FAKE_CORE_DIGEST_MISMATCH") == "1"
    else digest
)
config_id = "sha256:" + "c" * 64
media_type = "application/vnd.oci.image.manifest.v1+json"

if args[:3] == ["buildx", "imagetools", "inspect"]:
    if not (state / "pushed").exists():
        print("manifest unknown: not found", file=sys.stderr)
        raise SystemExit(1)
    template = args[args.index("--format") + 1]
    if "MediaType" in template:
        print(f"{media_type}|{registry_digest}")
    else:
        print(registry_digest)
    raise SystemExit(0)

if args and args[0] == "build":
    (state / "built").write_text("1", encoding="utf-8")
    raise SystemExit(0)

if args[:2] == ["image", "inspect"]:
    template = args[args.index("--format") + 1]
    if ".Os" in template:
        print("linux/amd64")
    elif ".Id" in template:
        print(config_id)
    else:
        raise SystemExit(f"unsupported inspect template: {template}")
    raise SystemExit(0)

if args[:2] == ["container", "create"]:
    print("core-container")
    raise SystemExit(0)

if args[:2] == ["container", "cp"]:
    shutil.copy2(core, pathlib.Path(args[3]))
    raise SystemExit(0)

if args[:2] == ["container", "rm"]:
    raise SystemExit(0)

if args and args[0] == "run":
    print(f"{hashlib.sha256(core.read_bytes()).hexdigest()}  /usr/daemon/core")
    raise SystemExit(0)

if args[:2] == ["image", "push"]:
    (state / "pushed").write_text(args[-1], encoding="utf-8")
    print(f"{args[-1]}: digest: {digest} size: 1234")
    raise SystemExit(0)

if args[:2] == ["image", "pull"]:
    print(f"pulled {args[-1]}")
    raise SystemExit(0)

print(f"unsupported fake docker command: {args!r}", file=sys.stderr)
raise SystemExit(1)
'''
            ),
            encoding="utf-8",
        )
        fake.chmod(0o755)
        return fake

    def run_publication(
        self, root: Path, *, mismatch: bool = False
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        fake = self.make_fake_docker(root)
        state = root / "state"
        output = root / "publication"
        environment = os.environ.copy()
        environment.update(
            {
                "DOCKER_BIN": str(fake),
                "FAKE_DOCKER_STATE": str(state),
                "FAKE_CORE": str(CORE),
            }
        )
        if mismatch:
            environment["FAKE_CORE_DIGEST_MISMATCH"] = "1"
        completed = subprocess.run(
            [
                "bash",
                str(SCRIPT),
                "--image",
                "localhost/sygma-q3/sygma-core-observation:test-core",
                "--output-dir",
                str(output),
            ],
            cwd=EVAL_ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return completed, output, state

    def test_default_destination_is_local_artifact(self) -> None:
        completed = subprocess.run(
            ["bash", str(SCRIPT), "--dry-run", "--image-tag", "test-tag"],
            cwd=EVAL_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            "output_image=localhost/sygma-q3/"
            "sygma-core-observation:test-tag\n",
            completed.stdout,
        )

    def test_push_round_trip_commits_immutable_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed, output, state = self.run_publication(Path(temporary))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("state=COMPLETE", (output / "STATUS").read_text())
            environment = (output / "core-image.env").read_text()
            self.assertIn(
                "export SYGMA_CORE_IMAGE="
                "localhost/sygma-q3/sygma-core-observation@"
                f"{DIGEST}\n",
                environment,
            )
            expected_hash = hashlib.sha256(CORE.read_bytes()).hexdigest()
            self.assertIn(
                f"export SYGMA_CORE_BINARY_SHA256=sha256:{expected_hash}\n",
                environment,
            )
            commands = [
                json.loads(line)
                for line in (state / "commands.jsonl").read_text().splitlines()
            ]
            self.assertTrue(any(command[:2] == ["image", "push"] for command in commands))
            self.assertTrue(any(command[:2] == ["image", "pull"] for command in commands))

    def test_registry_digest_mismatch_never_commits_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed, output, _ = self.run_publication(
                Path(temporary), mismatch=True
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("push-reported digest", completed.stderr)
            self.assertIn("state=FAILED", (output / "STATUS").read_text())
            self.assertFalse((output / "core-image.env").exists())


if __name__ == "__main__":
    unittest.main()
