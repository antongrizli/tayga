#!/usr/bin/env python3
"""Root-only Linux integration test using test_preflight's isolated topology.

Install the current tayga and clat-start.sh first, then run in an idle test VM.
"""
import os
from pathlib import Path
import subprocess
import tempfile

import test_preflight as preflight


def main():
    with tempfile.TemporaryDirectory(prefix="tayga-offload-fault-") as tmp:
        shim = str(Path(tmp) / "ioctl-fault.so")
        subprocess.run(["cc", "-Wall", "-Werror", "-shared", "-fPIC",
                        str(Path(__file__).with_name("offload_ioctl_fault.c")),
                        "-o", shim, "-ldl"], check=True)
        original = os.environ.copy()
        try:
            os.environ["LD_PRELOAD"] = shim
            for fault, effective in (("vnet", "off"), ("primary", "off"), ("worker", "tcp"),
                                     ("uso", "tcp"), ("uso-worker", "tcp")):
                os.environ["TAYGA_TEST_OFFLOAD_FAIL"] = fault
                preflight.test_auto_data_transfer()
                log = Path("/tmp/tayga_auto_transfer.log").read_text()
                assert f"requested=auto effective={effective}" in log, log
                assert ("USO4|USO6" in log) == (effective == "udp"), log
                assert "tun-offload auto" in Path("/run/clat.conf").read_text()
                print(f"PASS: auto fallback after {fault} failure, SHA-256 verified")

            # Explicit tcp must fail, rather than silently downgrade.
            os.environ["TAYGA_TEST_OFFLOAD_FAIL"] = "primary"
            config = Path(tmp) / "strict.conf"
            config.write_text("tun-device strict-test\nipv4-addr 192.0.0.254\n"
                              "prefix 64:ff9b::/96\nworkers 1\ntun-offload tcp\n")
            result = subprocess.run(["unshare", "-n", "/usr/sbin/tayga", "-d",
                                     "-c", str(config)], capture_output=True,
                                    text=True, timeout=10)
            assert result.returncode != 0, result
            assert "TUNSETOFFLOAD failed" in result.stdout + result.stderr, result
            print("PASS: explicit tcp fails when offload is unavailable")
        finally:
            os.environ.clear()
            os.environ.update(original)

        # Force the TUN descriptor readable and then fail the read. Verify the
        # daemon exits promptly with a nonzero status instead of polling forever.
        preflight.setup_topology()
        proc = None
        try:
            log_path = Path(tmp) / "fatal-read.log"
            with log_path.open("w") as log:
                proc = subprocess.Popen(
                    ["ip", "netns", "exec", "clatns", "env",
                     "LD_PRELOAD=" + shim, "TAYGA_TEST_TUN_READ_FAIL=1",
                     "PREF64=64:ff9b::/96", "ROUTER4=172.31.64.1",
                     "CLAT_WORKERS=1", "CLAT_OFFLOAD=off",
                     "/usr/local/sbin/clat-start.sh"],
                    stdout=log, stderr=subprocess.STDOUT)
                status = proc.wait(timeout=10)
            output = log_path.read_text()
            assert status != 0, output
            assert "TUN read failed" in output and "stopping TAYGA" in output, output
            print("PASS: fatal TUN read stops TAYGA with a nonzero exit")
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=3)
            preflight.teardown()


if __name__ == "__main__":
    main()
