"""A master - BMv2 - outstation lab built inside an unprivileged user+network namespace (`unshare -Urnm`).

Nothing here touches the host network or any real device: every interface lives in a private namespace that
disappears with the process. Run it only through `run_lab.py`, which re-executes itself under `unshare`.
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAC = {"m": "02:00:00:00:00:01", "o": "02:00:00:00:00:02"}
IP = {"m": "10.0.0.1", "o": "10.0.0.2"}
THRIFT = 9090


class Lab:
    def __init__(self, work):
        self.work = Path(work)
        if not (self.work / 'claim.json').is_file() or (self.work / 'completion.json').exists():
            raise ValueError('Lab requires a fresh, claimed evidence reservation')
        self.procs = []
        self.switch = None
        self.loop = False
        self.trace = False                      # per-packet trace logging is far too slow for timing runs

    # ---- plumbing -------------------------------------------------------------------------------------------
    def sh(self, *cmd, ns=None, check=True, **kw):
        full = (["ip", "netns", "exec", ns] if ns else []) + list(cmd)
        return subprocess.run(full, check=check, capture_output=True, text=True, **kw)

    def up(self, loop=False):
        self.loop = loop
        self.sh("mount", "-t", "tmpfs", "tmpfs", "/run")
        self.sh("ip", "link", "set", "lo", "up")
        self.sh("sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1", check=False)
        # thrift (python) resolves with AI_ADDRCONFIG, which fails with only loopback configured
        self.sh("ip", "link", "add", "dummy0", "type", "dummy")
        self.sh("ip", "addr", "add", "192.0.2.1/24", "dev", "dummy0")
        self.sh("ip", "link", "set", "dummy0", "up")
        for ns, root_end, port in (("m", "s0", 0), ("o", "s1", 1)):
            end = ns + "0"
            self.sh("ip", "netns", "add", ns)
            self.sh("ip", "link", "add", root_end, "type", "veth", "peer", "name", end)
            self.sh("ip", "link", "set", end, "netns", ns)
            self.sh("ip", "link", "set", root_end, "up")
            self.sh("sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1", ns=ns, check=False)
            self.sh("ip", "link", "set", "lo", "up", ns=ns)
            self.sh("ip", "link", "set", end, "address", MAC[ns], ns=ns)
            self.sh("ip", "addr", "add", IP[ns] + "/24", "dev", end, ns=ns)
            self.sh("ip", "link", "set", end, "up", ns=ns)
            for dev, where in ((root_end, None), (end, ns)):
                self.sh("ethtool", "-K", dev, "tx", "off", "rx", "off", "tso", "off", "gso", "off", "gro", "off", ns=where, check=False)
        if loop:      # a veth pair whose two ends are switch ports 2 and 3: a real trip through an egress queue
            self.sh("ip", "link", "add", "s2", "type", "veth", "peer", "name", "s3")
            for dev in ("s2", "s3"):
                self.sh("ip", "link", "set", dev, "up")
                self.sh("ethtool", "-K", dev, "tx", "off", "rx", "off", "tso", "off", "gso", "off", "gro", "off", check=False)
            self.sh("ip", "link", "add", "s4", "type", "veth", "peer", "name", "inj")      # injector: port 4
            for dev in ("s4", "inj"):
                self.sh("ip", "link", "set", dev, "up")
        for me, other in (("m", "o"), ("o", "m")):
            self.sh("ip", "neigh", "replace", IP[other], "lladdr", MAC[other], "dev", me + "0", "nud", "permanent", ns=me)
        return self

    def start_switch(self, json_path, *args, log="switch.log"):
        self.program = Path(json_path)
        ports = ["-i", "0@s0", "-i", "1@s1"] + (["-i", "2@s2", "-i", "3@s3", "-i", "4@s4"] if self.loop else [])
        cmd = ["simple_switch", *ports, "--thrift-port", str(THRIFT), "--notifications-addr",
               "ipc://" + str(self.work / "notifications.ipc")] + (["--log-console"] if self.trace else []) + [str(json_path)] + (["--", *args] if args else [])
        self.switch = subprocess.Popen(cmd, stdout=open(self.work / log, "w"), stderr=subprocess.STDOUT)
        self.procs.append(self.switch)
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.switch.poll() is not None:
                raise RuntimeError("simple_switch exited: " + (self.work / log).read_text()[-400:])
            try:
                socket.create_connection(("127.0.0.1", THRIFT), 0.2).close()
                return self
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("simple_switch thrift port never opened")

    def cli(self, text):
        r = subprocess.run(["simple_switch_CLI", "--thrift-ip", "127.0.0.1", "--thrift-port", str(THRIFT)], input=text, capture_output=True, text=True, timeout=30)
        (self.work / "cli.log").open("a").write(text + "\n--\n" + r.stdout + r.stderr + "\n")
        return r.stdout

    def capture(self, iface, name):
        path = self.work / name
        p = subprocess.Popen([sys.executable, "-B", str(HERE / "capture.py"), iface, str(path)], stderr=open(str(path) + ".err", "w"))
        self.procs.append(p)
        time.sleep(0.5)
        return path

    def heartbeat(self, period_us=1000):
        process = subprocess.Popen([sys.executable, "-B", str(HERE / "heartbeat.py"), "--period-us", str(period_us)],
                                   stdout=subprocess.DEVNULL, stderr=open(self.work / "heartbeat.log", "w"))
        self.procs.append(process)
        return process

    def start_outstation(self, latency_ms=1.0, force_points=0, combined=False, jitter_ms=0.0, seed=0, fallback_dir=None):
        p = subprocess.Popen(["ip", "netns", "exec", "o", sys.executable, "-B", str(HERE / "outstation.py"), "--latency-ms", str(latency_ms), "--force-points", str(force_points)] + (["--combined"] if combined else []) + ["--jitter-ms", str(jitter_ms), "--seed", str(seed), "--evidence", str(self.work / "endpoint_responses.jsonl")] + (["--fallback-dir", str(fallback_dir)] if fallback_dir else []),
                             stdout=subprocess.PIPE, text=True)
        self.procs.append(p)
        if p.stdout.readline().strip() != "READY":
            raise RuntimeError("outstation did not start")
        return p

    def run_master(self, count=5, gap_ms=50.0, budget_ms=500.0, operation="READ"):
        r = self.sh(sys.executable, "-B", str(HERE / "master.py"), "--count", str(count), "--gap-ms", str(gap_ms),
                    "--budget-ms", str(budget_ms), "--operation", operation, ns="m", timeout=60, check=False)
        if r.returncode:
            raise RuntimeError("master failed:\n" + r.stderr[-1500:])
        return json.loads(r.stdout.strip().splitlines()[-1])

    def down_captures(self):
        """Stop the captures (and only them) so their files are complete and flushed."""
        for p in self.procs:
            if "capture.py" in str(p.args) and p.poll() is None:
                p.send_signal(signal.SIGINT)
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()

    def down(self):
        for p in reversed(self.procs):
            if p.poll() is None:
                p.send_signal(signal.SIGINT if "capture.py" in str(p.args) else signal.SIGTERM)
        for p in self.procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
