#!/usr/bin/env python3
from pathlib import Path
import re
import unittest


EVAL_ROOT = Path(__file__).resolve().parents[1]

BASES = {
    "nginx": "docker.io/library/nginx@sha256:c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2",
    "redis": "docker.io/library/redis@sha256:a7cee7c8178ff9b5297cb109e6240f5072cdaaafd775ce6b586c3c704b06458e",
    "httpd": "docker.io/library/httpd@sha256:374766f5bc5977c9b72fdb8ae3ed05b7fc89060e7edc88fcbf142d6988e58eeb",
    "mysql": "docker.io/library/mysql@sha256:c6812f0dcd978b589d9d3b90c20bd5e4a799deab4fd492985e0a076c5be1ee40",
}

ENTRYPOINTS = {
    "nginx": '["/opt/gap/gap-launch", "--application", "nginx", "--", "/docker-entrypoint.sh"]',
    "redis": '["/opt/gap/gap-launch", "--application", "redis", "--", "docker-entrypoint.sh"]',
    "httpd": '["/opt/gap/gap-launch", "--application", "httpd", "--"]',
    "mysql": '["/opt/gap/gap-launch", "--application", "mysql", "--", "docker-entrypoint.sh"]',
}

COMMANDS = {
    "nginx": '["nginx", "-g", "daemon off;"]',
    "redis": '["redis-server"]',
    "httpd": '["httpd-foreground"]',
    "mysql": '["mysqld"]',
}


class ApplicationImagePackagingTests(unittest.TestCase):
    def test_dockerfiles_pin_bases_and_wrap_inherited_commands(self) -> None:
        for application, base in BASES.items():
            with self.subTest(application=application):
                dockerfile = EVAL_ROOT / "images" / f"Dockerfile.{application}"
                contents = dockerfile.read_text(encoding="utf-8")
                self.assertIn(f"ARG BASE_IMAGE={base}\n", contents)
                self.assertIn("FROM ${BASE_IMAGE}\n", contents)
                self.assertIn(
                    "COPY --chmod=0755 build/gap-probe /opt/gap/gap-launch\n",
                    contents,
                )
                self.assertIn(f"ENTRYPOINT {ENTRYPOINTS[application]}\n", contents)
                self.assertRegex(
                    contents,
                    re.compile(
                        rf"^CMD {re.escape(COMMANDS[application])}$",
                        re.MULTILINE,
                    ),
                )

    def test_build_helper_has_all_digest_defaults(self) -> None:
        helper = (
            EVAL_ROOT / "scripts" / "build_application_image.sh"
        ).read_text(encoding="utf-8")
        for application, base in BASES.items():
            with self.subTest(application=application):
                self.assertIn(f'[{application}]="{base}"', helper)

        self.assertIn("--pull=false", helper)
        self.assertNotIn("docker push", helper)
        self.assertNotIn("ctr ", helper)
        self.assertNotIn("kubectl ", helper)


if __name__ == "__main__":
    unittest.main()
