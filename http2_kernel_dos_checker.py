#!/usr/bin/env python3
"""
TAVARDT HTTP/2 & Linux Kernel DoS Resilience Checker
Auditor of Resilience against NoisyTCP, Rapid Reset, and Web Server Outages
TAVARDT USA
"""

import sys
import os
import json
import socket
import ssl
import argparse
from typing import Dict, Any, List

VERSION = "1.0.0"

RECOMMENDED_SYSCTL = {
    "net.ipv4.tcp_syncookies": {"expected": "1", "weight": 20, "desc": "Protection against SYN Flood and connection exhaustion"},
    "net.ipv4.tcp_timestamps": {"expected": "0", "weight": 20, "desc": "Mitigation of NoisyTCP poisoning and packet reordering"},
    "net.ipv4.tcp_sack": {"expected": "1", "weight": 15, "desc": "TCP Selective Acknowledgment (SACK)"},
    "net.ipv4.tcp_fin_timeout": {"expected": "15", "weight": 15, "desc": "Fast socket release in FIN-WAIT state"},
    "net.ipv4.tcp_max_syn_backlog": {"expected": "8192", "weight": 15, "desc": "Extended backlog queue for pending handshake requests"},
    "net.core.somaxconn": {"expected": "4096", "weight": 15, "desc": "System socket connection backlog limit"}
}

def audit_local_kernel() -> Dict[str, Any]:
    """Audits local Linux kernel network parameters against NoisyTCP vulnerability."""
    results = {
        "platform": sys.platform,
        "is_linux": sys.platform.startswith("linux"),
        "checks": [],
        "score": 100,
        "critical_alerts": []
    }

    if not results["is_linux"]:
        results["warning"] = "Kernel audit natively applicable on Linux hosts. On other operating systems, use remote network audit."
        return results

    total_weight = sum(v["weight"] for v in RECOMMENDED_SYSCTL.values())
    accumulated_score = 0

    for param, meta in RECOMMENDED_SYSCTL.items():
        proc_path = os.path.join("/proc/sys", param.replace(".", "/"))
        current_val = None
        if os.path.exists(proc_path):
            try:
                with open(proc_path, "r", encoding="utf-8") as f:
                    current_val = f.read().strip()
            except Exception:
                pass

        conforming = (current_val == meta["expected"])
        if conforming:
            accumulated_score += meta["weight"]
        else:
            results["critical_alerts"].append({
                "param": param,
                "current": current_val or "not_configured",
                "recommended": meta["expected"],
                "desc": meta["desc"]
            })

        results["checks"].append({
            "param": param,
            "current": current_val or "unavailable",
            "recommended": meta["expected"],
            "status": "COMPLIANT" if conforming else "VULNERABLE",
            "desc": meta["desc"]
        })

    results["score"] = round((accumulated_score / total_weight) * 100)
    return results

def audit_remote_host(host: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
    """Audits a remote endpoint evaluating HTTP/2 negotiation, TLS, and version leakage."""
    report = {
        "target": f"{host}:{port}",
        "http2_supported": False,
        "tls_version": None,
        "alpn_negotiated": None,
        "server_banner": None,
        "banner_leaked": False,
        "score": 100,
        "findings": []
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                report["tls_version"] = ssock.version()
                alpn = ssock.selected_alpn_protocol()
                report["alpn_negotiated"] = alpn
                report["http2_supported"] = (alpn == "h2")
    except Exception as e:
        report["connection_error"] = str(e)
        report["score"] = 30
        report["findings"].append(f"TLS connection failure with {host}:{port}: {e}")
        return report

    req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: TAVARDT-Security-Auditor/1.0\r\nConnection: close\r\n\r\n"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.sendall(req.encode())
                raw_resp = ssock.recv(4096).decode("utf-8", errors="ignore")
                for line in raw_resp.split("\r\n"):
                    if line.lower().startswith("server:"):
                        report["server_banner"] = line.split(":", 1)[1].strip()
                        report["banner_leaked"] = True
                    if line.lower().startswith("x-powered-by:"):
                        report["x_powered_by"] = line.split(":", 1)[1].strip()
                        report["banner_leaked"] = True
    except Exception:
        pass

    deductions = 0
    if not report["http2_supported"]:
        deductions += 40
        report["findings"].append("ALPN h2 not negotiated: server lacks modern multiplexing or uses cleartext h2c.")
    if report["banner_leaked"]:
        deductions += 30
        report["findings"].append(f"Active software version leak in banner: '{report.get('server_banner')}'")

    report["score"] = max(10, 100 - deductions)
    return report

def main():
    parser = argparse.ArgumentParser(
        description="TAVARDT USA HTTP/2 & NoisyTCP Linux Kernel Resilience Auditor"
    )
    parser.add_argument("--host", help="Remote host for HTTP/2 negotiation and server banner audit", default=None)
    parser.add_argument("--port", help="Remote port (default: 443)", type=int, default=443)
    parser.add_argument("--kernel", action="store_true", help="Run local Linux kernel network parameters audit")
    parser.add_argument("--json", action="store_true", help="Output results exclusively in JSON format")

    args = parser.parse_args()

    results = {
        "version": VERSION,
        "auditor": "TAVARDT USA",
        "documentation": "https://ag.tavardt.com/us/cybersecurity/",
        "web_tool": "https://tavardt-usa.github.io/http2-kernel-dos-resilience-checker-us/"
    }

    if args.kernel or (not args.host and not args.kernel):
        results["kernel_audit"] = audit_local_kernel()

    if args.host:
        results["remote_audit"] = audit_remote_host(args.host, args.port)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    print("================================================================================")
    print("      TAVARDT USA : HTTP/2 & LINUX KERNEL DOS RESILIENCE CHECKER           ")
    print("================================================================================")
    print(f"Version: {VERSION} | Jurisdiction: United States | Portal: https://ag.tavardt.com/us/cybersecurity/")
    print("--------------------------------------------------------------------------------\n")

    if "kernel_audit" in results:
        ka = results["kernel_audit"]
        print(f"[*] LINUX KERNEL AUDIT (NoisyTCP Mitigation) | Score: {ka['score']}/100")
        if not ka["is_linux"]:
            print(f"    [WARNING] {ka.get('warning')}")
        else:
            for c in ka["checks"]:
                tag = "[OK]        " if c["status"] == "COMPLIANT" else "[VULNERABLE]"
                print(f"    {tag} {c['param']}: current={c['current']} | recommended={c['recommended']}")
        print()

    if "remote_audit" in results:
        ra = results["remote_audit"]
        print(f"[*] REMOTE PROTOCOL AUDIT: {ra['target']} | Score: {ra['score']}/100")
        print(f"    HTTP/2 Supported (ALPN): 'YES' if ra['http2_supported'] else 'NO'")
        print(f"    TLS Version: {ra['tls_version'] or 'Unknown'}")
        print(f"    Server Banner Exposed: 'YES (' + str(ra['server_banner']) + ')' if ra['banner_leaked'] else 'NO (Protected)'")
        if ra["findings"]:
            print("    Identified Risk Findings:")
            for f in ra["findings"]:
                print(f"      * {f}")
        print()

    print("For technical support and perimeter hardening:")
    print(f"TAVARDT USA: https://ag.tavardt.com/us/cybersecurity/")

if __name__ == "__main__":
    main()
