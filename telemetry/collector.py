#!/usr/bin/env python3
# Must run on Python 3.6 (RHEL 8 default).

import json
import os
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone

from service_inventory import get_services


def run_command(command):
    try:
        # Popen/communicate instead of run(capture_output, text): Python 3.6
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        stdout, _ = process.communicate(timeout=30)

        return stdout.strip()

    except Exception as exc:
        return f"ERROR: {exc}"


def get_cpu_usage():
    with open("/proc/stat", "r") as f:
        line = f.readline().strip()

    values = list(map(int, line.split()[1:]))

    user, nice, system, idle, iowait, irq, softirq, steal = values[:8]

    idle_time = idle + iowait
    total_time = sum(values)

    return {
        "idle": idle_time,
        "total": total_time,
    }


def calculate_cpu_usage(sample1, sample2):
    idle_delta = sample2["idle"] - sample1["idle"]
    total_delta = sample2["total"] - sample1["total"]

    if total_delta <= 0:
        return 0.0

    usage = 100 * (1 - idle_delta / total_delta)

    return round(max(0.0, min(100.0, usage)), 2)


def get_memory():
    meminfo = {}

    with open("/proc/meminfo", "r") as f:
        for line in f:
            key, value = line.split(":", 1)
            value = value.strip().split()[0]
            meminfo[key] = int(value)

    total = meminfo.get("MemTotal", 0)
    available = meminfo.get("MemAvailable", 0)

    used = total - available

    usage_percent = (
        (used / total) * 100
        if total > 0
        else 0
    )

    return {
        "total_mb": round(total / 1024, 2),
        "available_mb": round(available / 1024, 2),
        "used_mb": round(used / 1024, 2),
        "usage_percent": round(usage_percent, 2),
    }


def get_load():
    with open("/proc/loadavg", "r") as f:
        values = f.read().split()

    return {
        "1m": float(values[0]),
        "5m": float(values[1]),
        "15m": float(values[2]),
    }


def get_disk():
    result = shutil.disk_usage("/")

    total = result.total
    used = result.used
    free = result.free

    usage_percent = (
        (used / total) * 100
        if total > 0
        else 0
    )

    return {
        "mount": "/",
        "total_gb": round(total / (1024 ** 3), 2),
        "used_gb": round(used / (1024 ** 3), 2),
        "free_gb": round(free / (1024 ** 3), 2),
        "usage_percent": round(usage_percent, 2),
    }


def get_network():
    interfaces = {}

    with open("/proc/net/dev", "r") as f:
        for line in f:
            if ":" not in line:
                continue

            interface, data = line.split(":", 1)
            interface = interface.strip()

            values = data.split()

            if len(values) < 16:
                continue

            interfaces[interface] = {
                "rx_bytes": int(values[0]),
                "rx_packets": int(values[1]),
                "rx_errors": int(values[2]),
                "tx_bytes": int(values[8]),
                "tx_packets": int(values[9]),
                "tx_errors": int(values[10]),
            }

    return interfaces


def get_log_counts():
    error_logs = run_command(
        "journalctl --since '30 minutes ago' -p err --no-pager 2>/dev/null"
    )

    critical_logs = run_command(
        "journalctl --since '30 minutes ago' -p crit --no-pager 2>/dev/null"
    )

    kernel_errors = run_command(
        "journalctl --since '30 minutes ago' -k -p err --no-pager 2>/dev/null"
    )

    def count_lines(value):
        if not value or value.startswith("ERROR:"):
            return 0

        return len(
            [line for line in value.splitlines() if line.strip()]
        )

    return {
        "errors": count_lines(error_logs),
        "critical": count_lines(critical_logs),
        "kernel_errors": count_lines(kernel_errors),
    }


def main():
    cpu_sample_1 = get_cpu_usage()

    time.sleep(1)

    cpu_sample_2 = get_cpu_usage()

    cpu_usage = calculate_cpu_usage(
        cpu_sample_1,
        cpu_sample_2,
    )

    telemetry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),

        "cpu": {
            "usage_percent": cpu_usage,
            "vcpus": os.cpu_count(),
        },

        "memory": get_memory(),

        "load": get_load(),

        "disk": get_disk(),

        "network": get_network(),

        "services": get_services(),

        "logs": get_log_counts(),
    }

    print(
        json.dumps(
            telemetry,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
