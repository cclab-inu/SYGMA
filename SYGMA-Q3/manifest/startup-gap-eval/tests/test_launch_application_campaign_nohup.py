#!/usr/bin/env python3
"""Preflight tests for the short nohup campaign launcher."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


EVAL_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = EVAL_ROOT / "scripts" / "launch_application_campaign_nohup.sh"
AUDITED_CORE = EVAL_ROOT / "build" / "sygma-core-current"
CORE_DIGEST = "sha256:" + "a" * 64
IMAGE_DIGEST = "sha256:" + "b" * 64


class NohupLauncherPreflightTests(unittest.TestCase):
    def make_publication(self, root: Path) -> Path:
        publication = root / "published"
        publication.mkdir()
        (publication / "STATUS").write_text("state=COMPLETE\n", encoding="utf-8")
        (publication / "campaign-images.env").write_text(
            "\n".join(
                [
                    f"export OBSERVER_IMAGE=example.invalid/observer@{IMAGE_DIGEST}",
                    f"export NGINX_IMAGE=example.invalid/nginx@{IMAGE_DIGEST}",
                    f"export REDIS_IMAGE=example.invalid/redis@{IMAGE_DIGEST}",
                    f"export HTTPD_IMAGE=example.invalid/httpd@{IMAGE_DIGEST}",
                    f"export MYSQL_IMAGE=example.invalid/mysql@{IMAGE_DIGEST}",
                    "export IMAGE_PULL_POLICY=Never",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return publication

    def make_fake_kubectl(
        self,
        root: Path,
        *,
        missing_map: bool = False,
        readiness_log: str = "SYGMA observation mode ready (145 dedicated policy-entry probes)",
    ) -> Path:
        fake = root / "kubectl"
        fake.write_text(
            textwrap.dedent(
                f'''#!/usr/bin/env python3
import hashlib
import json
import pathlib
import sys

args = sys.argv[1:]
with pathlib.Path({str(root / "kubectl.jsonl")!r}).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\\n")

core_digest = {CORE_DIGEST!r}
if args[:2] == ["rollout", "status"]:
    print("daemon set successfully rolled out")
elif args[:2] == ["get", "daemonset"]:
    print(f"example.invalid/sygma-core@{{core_digest}}", end="")
elif args[:2] == ["get", "pods"]:
    print("core-pod", end="")
elif args[:3] == ["get", "pod", "core-pod"]:
    template = args[args.index("-o") + 1]
    if "spec.nodeName" in template:
        print("master", end="")
    elif "imageID" in template:
        print(f"example.invalid/sygma-core@{{core_digest}}", end="")
    else:
        raise SystemExit(f"unsupported pod template: {{template}}")
elif args and args[0] == "logs":
    print({readiness_log!r})
elif args and args[0] == "exec":
    if "sha256sum" in args:
        core = pathlib.Path({str(AUDITED_CORE)!r})
        print(f"{{hashlib.sha256(core.read_bytes()).hexdigest()}}  /usr/daemon/core")
    else:
        raise SystemExit({1 if missing_map else 0})
else:
    raise SystemExit(f"unsupported kubectl command: {{args!r}}")
'''
            ),
            encoding="utf-8",
        )
        fake.chmod(0o755)
        return fake

    def run_preflight(
        self,
        root: Path,
        *,
        missing_map: bool = False,
        readiness_log: str = "SYGMA observation mode ready (145 dedicated policy-entry probes)",
    ) -> subprocess.CompletedProcess[str]:
        publication = self.make_publication(root)
        fake = self.make_fake_kubectl(
            root,
            missing_map=missing_map,
            readiness_log=readiness_log,
        )
        host_root = root / "host"
        installed = {
            EVAL_ROOT / "build" / "sygma-hook":
                host_root / "usr/local/bin/sygma-hook",
            EVAL_ROOT / "build" / "sygma-tracer-current":
                host_root / "usr/local/bin/sygma-tracer",
            EVAL_ROOT / "build" / "sygma-wrapper-current":
                host_root / "opt/sygma/wrapper",
            EVAL_ROOT / "build" / "sygma-nri-current":
                host_root / "opt/nri/plugins/00-sygma",
        }
        for source, destination in installed.items():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        environment = os.environ.copy()
        environment.update(
            {
                "KUBECTL_BIN": str(fake),
                "CAMPAIGN_ID": "preflight-test",
                "SYGMA_HOST_ROOT": str(host_root),
            }
        )
        return subprocess.run(
            [
                "bash",
                str(SCRIPT),
                "--publication-dir",
                str(publication),
                "--preflight-only",
            ],
            cwd=EVAL_ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_matching_core_and_maps_pass_before_nohup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed = self.run_preflight(Path(temporary))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("host component hashes PASS", completed.stdout)
            self.assertNotIn("STARTED", completed.stdout)

    def test_missing_map_fails_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed = self.run_preflight(Path(temporary), missing_map=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertNotIn("STARTED", completed.stdout)

    def test_post_ready_activity_survives_rotated_startup_log(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed = self.run_preflight(
                Path(temporary),
                readiness_log="145 dedicated policy-entry probes attached",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("post-ready activity observed", completed.stdout)


if __name__ == "__main__":
    unittest.main()
