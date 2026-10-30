"""Offline, non-exploit tests for CVE-2026-98432 tools."""
from __future__ import annotations

import contextlib
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cve98432 as mod


def fixture(root: Path, first: str = "old", second: str = "old",
            header: bool = True) -> None:
    (root / "net/ipv4").mkdir(parents=True, exist_ok=True)
    (root / "include/net").mkdir(parents=True, exist_ok=True)
    rcu = "struct rcu_head rcu;" if header else "int unrelated;"
    (root / "include/net/inet_sock.h").write_text(
        f"struct ip_options_rcu {{\n    {rcu}\n    struct ip_options opt;\n}};\n",
        encoding="utf-8", newline="\n",
    )

    def expression(pointer: str, mode: str) -> str:
        if mode == "old":
            return f"kfree(rcu_dereference_protected({pointer}, 1));"
        if mode == "new":
            return f"kfree_rcu(rcu_dereference_protected({pointer}, 1), rcu);"
        if mode == "missing":
            return "safe_alternative_release(ptr);"
        raise ValueError(mode)

    (root / "net/ipv4/af_inet.c").write_text(
        "void inet_sock_destruct(struct sock *sk)\n"
        "{\n    /* kfree(rcu_dereference_protected(inet->inet_opt, 1)); */\n"
        f"    {expression('inet->inet_opt', first)}\n"
        "    dst_release(sk->sk_dst_cache);\n}\n",
        encoding="utf-8", newline="\n",
    )
    (root / "net/ipv4/tcp_ipv4.c").write_text(
        "static void tcp_v4_reqsk_destructor(struct request_sock *req)\n"
        "{\n"
        f"    {expression('inet_rsk(req)->ireq_opt', second)}\n"
        "}\n",
        encoding="utf-8", newline="\n",
    )


class AnalyzerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_vulnerable_source_report(self) -> None:
        fixture(self.root)
        report, originals = mod.inspect_source(self.root)
        self.assertEqual(report["status"], "vulnerable_cleanup_pattern_present")
        self.assertTrue(report["rcu_member_present"])
        self.assertEqual(len(originals), 2)

    def test_fixed_pattern(self) -> None:
        fixture(self.root, "new", "new")
        report, _ = mod.inspect_source(self.root)
        self.assertEqual(report["status"], "upstream_fix_pattern_present")

    def test_mixed_status_is_not_fixed(self) -> None:
        fixture(self.root, "new", "old")
        self.assertEqual(mod.inspect_source(self.root)[0]["status"], "indeterminate")
        with self.assertRaises(ValueError):
            mod.prepare_patch(self.root)

    def test_unknown_does_not_become_fixed(self) -> None:
        fixture(self.root, "missing", "new")
        self.assertEqual(mod.inspect_source(self.root)[0]["status"], "indeterminate")

    def test_missing_rcu_member_blocks_patch(self) -> None:
        fixture(self.root, header=False)
        report, _ = mod.inspect_source(self.root)
        self.assertEqual(report["status"], "indeterminate")
        with self.assertRaises(ValueError):
            mod.prepare_patch(self.root)

    def test_missing_file_is_unknown(self) -> None:
        fixture(self.root)
        (self.root / "net/ipv4/tcp_ipv4.c").unlink()
        self.assertEqual(mod.inspect_source(self.root)[0]["status"], "indeterminate")

    def test_prepare_patch_is_read_only_and_scoped(self) -> None:
        fixture(self.root)
        before = {
            item[0]: (self.root / item[0]).read_bytes() for item in mod.TARGETS
        }
        diff = mod.prepare_patch(self.root)
        self.assertEqual(diff.count("+\tkfree_rcu("), 0)  # fixture uses spaces, not tabs
        self.assertEqual(diff.count("+    kfree_rcu("), 2)
        self.assertIn("--- a/net/ipv4/af_inet.c", diff)
        self.assertIn("+++ b/net/ipv4/tcp_ipv4.c", diff)
        self.assertEqual(diff.count("@@ "), 2)
        for relative, original in before.items():
            self.assertEqual((self.root / relative).read_bytes(), original)

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_generated_diff_git_apply_check(self) -> None:
        fixture(self.root)
        diff = mod.prepare_patch(self.root)
        result = subprocess.run(
            ["git", "-C", str(self.root), "apply", "--check", "-"],
            input=diff.encode("utf-8"),
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
        result = subprocess.run(
            ["git", "-C", str(self.root), "apply", "-"],
            input=diff.encode("utf-8"),
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(
            mod.inspect_source(self.root)[0]["status"],
            "upstream_fix_pattern_present",
        )

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_bundled_upstream_patch_applies_to_matching_context(self) -> None:
        fixture(self.root)
        (self.root / "net/ipv4/af_inet.c").write_text(
            "void inet_sock_destruct(struct sock *sk)\n"
            "{\n"
            "\tWARN_ON_ONCE(sk->sk_wmem_queued);\n"
            "\tWARN_ON_ONCE(sk->sk_forward_alloc);\n"
            "\n"
            "\tkfree(rcu_dereference_protected(inet->inet_opt, 1));\n"
            "\tdst_release(rcu_dereference_protected(sk->sk_dst_cache, 1));\n"
            "\tdst_release(rcu_dereference_protected(sk->sk_rx_dst, 1));\n"
            "\tpsp_sk_assoc_free(sk);\n"
            "}\n",
            encoding="utf-8", newline="\n",
        )
        (self.root / "net/ipv4/tcp_ipv4.c").write_text(
            "/* comment\n"
            " */\n"
            "static void tcp_v4_reqsk_destructor(struct request_sock *req)\n"
            "{\n"
            "\tkfree(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1));\n"
            "}\n"
            "\n"
            "#ifdef CONFIG_TCP_MD5SIG\n",
            encoding="utf-8", newline="\n",
        )
        patch_file = Path(mod.__file__).parent / "patches/linux-7.3-e3f33b0.patch"
        result = subprocess.run(
            ["git", "-C", str(self.root), "apply", "--check", str(patch_file)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_exit_codes(self) -> None:
        fixture(self.root)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(mod.main(["inspect-source", str(self.root)]), 1)
            self.assertEqual(mod.main(["prepare-patch", str(self.root)]), 0)
        fixture(self.root, "new", "new")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(mod.main(["inspect-source", str(self.root)]), 0)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(mod.main(["prepare-patch", str(self.root)]), 2)

    def test_comments_do_not_trigger_false_match(self) -> None:
        fixture(self.root, "missing", "missing")
        source_file = self.root / "net/ipv4/tcp_ipv4.c"
        source_file.write_text(
            "static void tcp_v4_reqsk_destructor(struct request_sock *req) {\n"
            " /* kfree_rcu(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1), rcu); */\n"
            " safe_alternative_release(ptr);\n}\n",
            encoding="utf-8", newline="\n",
        )
        self.assertEqual(mod.inspect_source(self.root)[0]["status"], "indeterminate")

    def test_host_does_not_claim_security_status(self) -> None:
        self.assertEqual(mod.host_report()["status"], "unknown")

    def test_nonlinux_host_does_not_claim_linux_fix(self) -> None:
        from unittest.mock import patch
        with patch.object(mod.sys, "platform", "win32"):
            report = mod.host_report()
        self.assertEqual(report["status"], "unknown")
        self.assertEqual(report["running_kernel"], "not-a-linux-kernel")


if __name__ == "__main__":
    unittest.main()
