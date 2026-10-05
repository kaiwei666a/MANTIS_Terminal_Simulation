"""Interactive ping output, profile validation and latency sampling."""

import ipaddress
import json
import math
import random
import shlex
import time
from typing import List, Optional, Tuple
from dataclasses import dataclass


@dataclass(frozen=True)
class PingProfile:
    address: str
    ttl: int
    latency_ms: float
    jitter_ms: float

    def sample(self) -> float:
        return round(max(0.001, random.uniform(
            self.latency_ms - self.jitter_ms,
            self.latency_ms + self.jitter_ms,
        )), 3)


def parse_ping_profile(raw: str, host: str) -> PingProfile:
    data = json.loads(raw)
    address = str(ipaddress.ip_address(data["address"]))
    try:
        address = str(ipaddress.ip_address(host))
    except ValueError:
        if host.lower().rstrip(".") == "localhost":
            address = "127.0.0.1"
    ttl = data["ttl"]
    if type(ttl) is not int or not 1 <= ttl <= 255:
        raise ValueError("Invalid ping TTL")
    values = [data["latency_ms"], data["jitter_ms"]]
    if any(type(value) not in (int, float) or not math.isfinite(value) for value in values):
        raise ValueError("Invalid ping latency")
    latency, jitter = map(float, values)
    if not 0.001 <= latency <= 60000 or not 0.001 <= jitter <= latency:
        raise ValueError("Invalid ping latency range")
    return PingProfile(address, ttl, latency, jitter)


def run_ping_interactive(command: str, *, chan, generate_profile, send, report_error) -> Tuple[str, int]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return "ping: usage error", 2
    count: Optional[int] = None
    host = ""
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {"-c", "--count"} and index + 1 < len(tokens):
            try:
                count = max(1, int(tokens[index + 1]))
            except ValueError:
                return f"ping: invalid argument: '{tokens[index + 1]}'", 2
            index += 2
            continue
        if token.startswith("-"):
            return f"ping: invalid option -- '{token.lstrip('-')[:1]}'", 2
        host = token
        index += 1
    if not host:
        return "ping: usage error: Destination address required", 2


    try:
        profile = generate_profile(host)
    except Exception as exc:
        report_error(exc)
        error = "ping: simulation temporarily unavailable"
        send(chan, error + "\r\n")
        return error, 2

    address, ttl = profile.address, profile.ttl
    lines = [f"PING {host} ({address}) 56(84) bytes of data."]
    send(chan, lines[0] + "\r\n")
    samples: List[float] = []
    sent = 0
    interrupted = False
    old_timeout = None
    started = time.monotonic()
    try:
        try:
            old_timeout = chan.gettimeout()
        except Exception:
            old_timeout = None
        chan.settimeout(0.0)
        next_reply = started
        while count is None or sent < count:
            if chan.closed or chan.eof_received:
                interrupted = True
                break
            if chan.recv_ready():
                incoming = chan.recv(1024)
                if not incoming:
                    interrupted = True
                    break
                if b"\x03" in incoming:
                    interrupted = True
                    send(chan, "^C\r\n")
                    break
            now = time.monotonic()
            if now >= next_reply:
                sent += 1
                sample = profile.sample()
                samples.append(sample)
                line = f"64 bytes from {address}: icmp_seq={sent} ttl={ttl} time={sample:.3f} ms"
                lines.append(line)
                send(chan, line + "\r\n")
                next_reply = now + 1.0
            time.sleep(0.03)
    finally:
        try:
            chan.settimeout(old_timeout)
        except Exception:
            pass

    elapsed = max(0, int((time.monotonic() - started) * 1000))
    summary = [
        f"--- {host} ping statistics ---",
        f"{sent} packets transmitted, {sent} received, 0% packet loss, time {elapsed}ms",
    ]
    if samples:
        average = sum(samples) / len(samples)
        mdev = (sum((sample - average) ** 2 for sample in samples) / len(samples)) ** 0.5
        summary.append(
            f"rtt min/avg/max/mdev = {min(samples):.3f}/{average:.3f}/"
            f"{max(samples):.3f}/{mdev:.3f} ms"
        )
    for line in summary:
        send(chan, line + "\r\n")
    lines.extend(summary)
    return "\n".join(lines), 130 if interrupted else 0
