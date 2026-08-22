#!/usr/bin/env python3
from pathlib import Path
import json
import os
import subprocess
import tempfile
import textwrap
import unittest


EVAL_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = EVAL_ROOT / "scripts" / "publish_application_images.sh"
OBSERVER = (
    "localhost/sygma-q3/sygma-installer@sha256:"
    "1a5f97b582b448ba16811c028b63b39bcaef3445576e872119fcd464bb0af6b9"
)


class ApplicationImagePublicationTests(unittest.TestCase):
    def run_dry(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "bash",
                str(SCRIPT),
                "--image-set-id",
                "atomicity-test",
                "--observer-image",
                OBSERVER,
                "--dry-run",
                *extra,
            ],
            cwd=EVAL_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def make_fake_docker(self, directory: Path) -> Path:
        fake = directory / "docker"
        fake.write_text(
            textwrap.dedent(
                r'''#!/usr/bin/env python3
import json
import os
import pathlib
import shutil
import sys

args = sys.argv[1:]
state = pathlib.Path(os.environ["FAKE_DOCKER_STATE"])
eval_root = pathlib.Path(os.environ["FAKE_EVAL_ROOT"])
state.mkdir(parents=True, exist_ok=True)
with (state / "commands.log").open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\n")

apps = ("nginx", "redis", "httpd", "mysql")
ids = {
    "nginx": "sha256:19f018fc2ad78f40a2aa698a966e3fc88ad89a8d2f40ffcf5ca47674f5c7c194",
    "redis": "sha256:c663dc1ca7c8625fda6ed794dbdf75505a8526493b10ad1cd8f7cd3aba76dbfe",
    "httpd": "sha256:529c0838dc7d66f00c2fca7b46280040bf9cbe149d7cc4ddf4594a7e265da3ef",
    "mysql": "sha256:bd1bfc1bacefbc6462155462ca07c6d4e4ef910bfceac011e14656b2c67e0d46",
}
digest_chars = {"nginx": "1", "redis": "2", "httpd": "3", "mysql": "4"}
entrypoints = {
    "nginx": '["/opt/gap/gap-launch","--application","nginx","--","/docker-entrypoint.sh"]',
    "redis": '["/opt/gap/gap-launch","--application","redis","--","docker-entrypoint.sh"]',
    "httpd": '["/opt/gap/gap-launch","--application","httpd","--"]',
    "mysql": '["/opt/gap/gap-launch","--application","mysql","--","docker-entrypoint.sh"]',
}
commands = {
    "nginx": '["nginx","-g","daemon off;"]',
    "redis": '["redis-server"]',
    "httpd": '["httpd-foreground"]',
    "mysql": '["mysqld"]',
}
media = "application/vnd.docker.distribution.manifest.v2+json"
observer_digest = "sha256:1a5f97b582b448ba16811c028b63b39bcaef3445576e872119fcd464bb0af6b9"
observer_id = "sha256:cbd7738a999e0190f5729cfa2c5cb5ec63fccd3f581dce2b5c606615d51fdf58"


def app_for(reference):
    for app in apps:
        if f"sygma-gap-{app}" in reference or f"/{app}:" in reference or f"/{app}@" in reference:
            return app
    return None


def digest_for(app, registry=False):
    char = digest_chars[app]
    if registry and os.environ.get("FAKE_DIGEST_MISMATCH_APP") == app:
        char = "e"
    return "sha256:" + char * 64


if args[:3] == ["buildx", "imagetools", "inspect"]:
    reference = args[3]
    template = args[args.index("--format") + 1]
    if "sygma-installer@" in reference:
        digest = observer_digest
    else:
        app = app_for(reference)
        if app is None or not (state / f"pushed-{app}").exists():
            print("manifest unknown: not found", file=sys.stderr)
            raise SystemExit(1)
        digest = digest_for(app, registry=True)
    if "printf" in template:
        print(f"{media}|{digest}")
    else:
        print(digest)
    raise SystemExit(0)

if args[:2] == ["image", "tag"]:
    app = app_for(args[2])
    if app is None:
        raise SystemExit(1)
    (state / f"tagged-{app}").write_text(args[3], encoding="utf-8")
    raise SystemExit(0)

if args[:2] == ["image", "push"]:
    reference = args[-1]
    app = app_for(reference)
    if app is None or any(not (state / f"tagged-{name}").exists() for name in apps):
        print("push began before all four images were tagged", file=sys.stderr)
        raise SystemExit(1)
    (state / f"pushed-{app}").write_text(reference, encoding="utf-8")
    print(f"{reference}: digest: {digest_for(app)} size: 1234")
    raise SystemExit(0)

if args[:2] == ["image", "pull"]:
    print(f"pulled {args[-1]}")
    raise SystemExit(0)

if args[:2] == ["image", "inspect"]:
    reference = args[-1]
    app = app_for(reference)
    is_base = "/library/" in reference and "@sha256:" in reference
    is_observer = "sygma-installer@" in reference
    is_destination = "localhost/sygma-q3/sygma-gap-" in reference
    if is_destination and "@sha256:" not in reference and not (state / f"tagged-{app}").exists():
        raise SystemExit(1)
    if "--format" not in args:
        print("[]")
        raise SystemExit(0)
    template = args[args.index("--format") + 1]
    if "RepoDigests" in template:
        print(f"localhost/sygma-q3/sygma-gap-{app}@{digest_for(app)}")
    elif ".Os" in template:
        print("linux/amd64")
    elif ".Config.Entrypoint" in template:
        print(entrypoints[app])
    elif ".Config.Cmd" in template:
        print(commands[app])
    elif ".RootFS.Layers" in template:
        base_layer = "sha256:" + digest_chars[app] * 64
        if is_base:
            print(json.dumps([base_layer], separators=(",", ":")))
        else:
            print(json.dumps([base_layer, "sha256:" + "f" * 64], separators=(",", ":")))
    elif ".Id" in template:
        print(observer_id if is_observer else ids[app])
    else:
        raise SystemExit(f"unsupported inspect template: {template}")
    raise SystemExit(0)

if args[:2] == ["container", "create"]:
    app = app_for(args[2])
    print(f"cid-{app}")
    raise SystemExit(0)

if args[:2] == ["container", "cp"]:
    app = args[2].split(":", 1)[0].removeprefix("cid-")
    shutil.copy2(eval_root / "build" / "gap-probe", pathlib.Path(args[3]))
    raise SystemExit(0)

if args[:2] == ["container", "rm"]:
    raise SystemExit(0)

print(f"unsupported fake docker command: {args!r}", file=sys.stderr)
raise SystemExit(1)
'''
            ),
            encoding="utf-8",
        )
        fake.chmod(0o755)
        return fake

    def run_mock_publication(
        self, root: Path, *, mismatch_app: str | None = None
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        state = root / "state"
        output = root / "published"
        fake = self.make_fake_docker(root)
        environment = os.environ.copy()
        environment.update(
            {
                "DOCKER_BIN": str(fake),
                "FAKE_DOCKER_STATE": str(state),
                "FAKE_EVAL_ROOT": str(EVAL_ROOT),
                "LOCK_FILE": str(root / "publication.lock"),
            }
        )
        if mismatch_app is not None:
            environment["FAKE_DIGEST_MISMATCH_APP"] = mismatch_app
        completed = subprocess.run(
            [
                "bash",
                str(SCRIPT),
                "--image-set-id",
                "integration-test",
                "--observer-image",
                OBSERVER,
                "--output-dir",
                str(output),
                "--applications",
                "nginx redis httpd mysql",
            ],
            cwd=EVAL_ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return completed, output, state

    def test_existing_mode_maps_all_attached_images(self) -> None:
        completed = self.run_dry("--applications", "nginx redis httpd mysql")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("mode=existing\n", completed.stdout)
        expected = {
            "nginx": "sygma-startup-gap-eval/nginx:packaging-check-v2-20260802",
            "redis": "sygma-startup-gap-eval/redis:packaging-check-20260802",
            "httpd": "sygma-startup-gap-eval/httpd:packaging-check-20260802",
            "mysql": "sygma-startup-gap-eval/mysql:packaging-check-20260802",
        }
        for application, source in expected.items():
            with self.subTest(application=application):
                self.assertIn(
                    f"{application} source={source} "
                    f"destination=localhost/sygma-q3/"
                    f"sygma-gap-{application}:atomicity-test\n",
                    completed.stdout,
                )

    def test_rebuild_mode_uses_fresh_destination_images(self) -> None:
        completed = self.run_dry("--rebuild")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("mode=rebuild\n", completed.stdout)
        for application in ("nginx", "redis", "httpd", "mysql"):
            destination = (
                f"localhost/sygma-q3/sygma-gap-{application}:atomicity-test"
            )
            self.assertIn(
                f"{application} source={destination} destination={destination}\n",
                completed.stdout,
            )

    def test_rejects_mutable_observer_and_ambiguous_registry(self) -> None:
        mutable = subprocess.run(
            [
                "bash",
                str(SCRIPT),
                "--repository-prefix",
                "localhost/sygma-q3",
                "--image-set-id",
                "atomicity-test",
                "--observer-image",
                "localhost/sygma-q3/installer:artifact-v1",
                "--dry-run",
            ],
            cwd=EVAL_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(mutable.returncode, 2)
        self.assertIn("immutable lowercase sha256", mutable.stderr)

        ambiguous = subprocess.run(
            [
                "bash",
                str(SCRIPT),
                "--repository-prefix",
                "team/sygma-q3",
                "--image-set-id",
                "atomicity-test",
                "--observer-image",
                OBSERVER,
                "--dry-run",
            ],
            cwd=EVAL_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(ambiguous.returncode, 2)
        self.assertIn("explicit registry host", ambiguous.stderr)

    def test_rebuild_rejects_source_override(self) -> None:
        completed = self.run_dry(
            "--rebuild", "--nginx-source", "local/custom-nginx:test"
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("cannot be combined", completed.stderr)

    def test_custom_existing_source_requires_matching_config_digest(self) -> None:
        completed = self.run_dry(
            "--nginx-source", "local/custom-nginx:test"
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("must be supplied together", completed.stderr)

    def test_script_contains_fail_closed_publication_contract(self) -> None:
        contents = SCRIPT.read_text(encoding="utf-8")
        for application in ("nginx", "redis", "httpd", "mysql"):
            self.assertIn(f"[{application}]=", contents)

        self.assertIn("--platform linux/amd64", contents)
        self.assertIn("buildx imagetools inspect", contents)
        self.assertIn("non-single-platform media type", contents)
        self.assertIn("registry round trip changed the image config ID", contents)
        self.assertIn("push-reported digest", contents)
        self.assertIn("source image config digest differs", contents)
        self.assertIn("local RepoDigests does not cross-reference", contents)
        self.assertIn("destination tag already exists locally", contents)
        self.assertIn("destination tag already exists in the registry", contents)
        self.assertIn("push-receipts.tsv", contents)
        self.assertIn("campaign-images.env", contents)
        self.assertIn("publication.json", contents)
        self.assertIn("--allow-unconfirmed-remote-absence", contents)
        self.assertNotIn("docker login", contents)
        self.assertNotIn("image rm", contents)
        self.assertNotIn("manifest inspect", contents)

        build_phase = contents.index(
            "# Complete every local build/verification before the first registry push."
        )
        push_phase = contents.index(
            '"${docker_bin}" image push --platform linux/amd64'
        )
        env_phase = contents.index(
            'environment_tmp="$(mktemp "${output_dir}/.campaign-images.env.XXXXXX")"'
        )
        provenance_commit = contents.index(
            'mv -- "${provenance_tmp}" "${output_dir}/publication.json"'
        )
        environment_commit = contents.index(
            'mv -- "${environment_tmp}" "${output_dir}/campaign-images.env"'
        )
        self.assertLess(build_phase, push_phase)
        self.assertLess(push_phase, env_phase)
        self.assertLess(provenance_commit, environment_commit)

    def test_mock_registry_round_trip_commits_env_last(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed, output, state = self.run_mock_publication(Path(temporary))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("state=COMPLETE", (output / "STATUS").read_text())
            environment = (output / "campaign-images.env").read_text()
            for application, char in zip(
                ("nginx", "redis", "httpd", "mysql"), "1234"
            ):
                variable = f"{application.upper()}_IMAGE"
                expected = (
                    f"localhost/sygma-q3/sygma-gap-{application}@"
                    f"sha256:{char * 64}"
                )
                self.assertIn(f"export {variable}={expected}\n", environment)

            provenance = json.loads((output / "publication.json").read_text())
            self.assertEqual(set(provenance["applications"]), {
                "nginx", "redis", "httpd", "mysql"
            })
            receipts = (output / "push-receipts.tsv").read_text()
            self.assertEqual(receipts.count("push_command_succeeded"), 4)
            self.assertEqual(receipts.count("roundtrip_verified"), 4)

            commands = [
                json.loads(line)
                for line in (state / "commands.log").read_text().splitlines()
            ]
            tag_indexes = [
                index for index, command in enumerate(commands)
                if command[:2] == ["image", "tag"]
            ]
            push_indexes = [
                index for index, command in enumerate(commands)
                if command[:2] == ["image", "push"]
            ]
            self.assertEqual(len(tag_indexes), 4)
            self.assertEqual(len(push_indexes), 4)
            self.assertLess(max(tag_indexes), min(push_indexes))

    def test_mock_digest_mismatch_keeps_receipt_but_never_commits_env(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed, output, _ = self.run_mock_publication(
                Path(temporary), mismatch_app="redis"
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("push-reported digest", completed.stderr)
            self.assertIn("state=FAILED", (output / "STATUS").read_text())
            self.assertFalse((output / "campaign-images.env").exists())
            self.assertFalse((output / "publication.json").exists())
            receipts = (output / "push-receipts.tsv").read_text()
            self.assertEqual(receipts.count("push_command_succeeded"), 2)
            self.assertEqual(receipts.count("roundtrip_verified"), 1)


if __name__ == "__main__":
    unittest.main()
