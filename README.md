# HTTP/2 & Linux Kernel DoS Resilience Auditor - TAVARDT USA

> Resilience Audit against NoisyTCP, Rapid Reset (CVE-2023-44487), and Production Web Server Hardening

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Active-brightgreen)](https://tavardt-usa.github.io/http2-kernel-dos-resilience-checker-us/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: CIS Linux](https://img.shields.io/badge/Security-CIS%20Linux%20%7C%20RFC%209113-red.svg)](https://www.cisecurity.org/)

## Architecture Overview & HTTP/2 and Linux Kernel Resilience

The stability and operational resilience of enterprise web infrastructures depend directly on tight alignment between the Linux kernel TCP network stack and HTTP/2 multiplexing runtimes.

Two critical threat vectors impact unhardened systems:
1. **Linux Kernel NoisyTCP Flaw:** Crafted out-of-order TCP packet sequences with anomalous control flags force the kernel network subsystem into unconstrained buffer allocations, crashing Nginx, Apache, and SSH instances without authentication.
2. **HTTP/2 Rapid Reset Abuse (CVE-2023-44487):** High-frequency request bursts immediately cancelled via `RST_STREAM` frames rapidly exhaust server file descriptor pools and worker threads.

This repository provides both an interactive in-browser diagnostic tool and a zero-dependency Python CLI utility to audit local kernel settings and remote endpoints, generating battle-tested blueprints for `sysctl`, `nginx`, and `apache`.

## Interactive Web Application

Access the online tool and audit your server in real time:

* [https://tavardt-usa.github.io/http2-kernel-dos-resilience-checker-us/](https://tavardt-usa.github.io/http2-kernel-dos-resilience-checker-us/)

The application simulates 5 security stages, calculates an objective resilience score (0 to 100), outputs architectural risk findings, and produces instant hardening configs.

## Command-Line Scanner (Python)

The repository includes `http2_kernel_dos_checker.py`, built exclusively with standard library Python (no external dependencies):

```bash
# Audit local Linux kernel parameters against NoisyTCP
python3 http2_kernel_dos_checker.py --kernel

# Audit remote host (ALPN h2 negotiation, TLS version, and banner disclosure)
python3 http2_kernel_dos_checker.py --host your-server.com --port 443

# Output pure JSON for automated CI/CD security pipelines
python3 http2_kernel_dos_checker.py --host your-server.com --json
```

## Architectural Controls & Defensive Mitigations

* **Linux Kernel (/etc/sysctl.conf):** Configuration of `net.ipv4.tcp_syncookies = 1`, disabling `net.ipv4.tcp_timestamps = 0` to mitigate NoisyTCP exploits, socket buffer calibration (`tcp_rmem`, `tcp_wmem`), and `somaxconn = 4096`.
* **Nginx (nginx.conf):** Server banner suppression (`server_tokens off`), concurrent stream limiting (`http2_max_concurrent_streams 100`), and rate limiting zones (`limit_req_zone`) against `RST_STREAM` flooding.
* **Apache HTTP Server (httpd.conf):** Complete signature masking (`ServerTokens Prod`, `ServerSignature Off`), concurrency restriction via `mod_http2` (`H2MaxSessionStreams 100`), and connection timeouts with `mod_reqtimeout`.
* **Edge Perimeter:** Managed edge TLS termination with Cloudflare WAF and complete origin IP shielding.

## Official Portals

* **TAVARDT USA Portal:** [https://ag.tavardt.com/](https://ag.tavardt.com/)
* **Cybersecurity Services:** [https://ag.tavardt.com/cybersecurity/](https://ag.tavardt.com/cybersecurity/)
* **Security Tools Hub:** [https://tools.tavardt.com/](https://tools.tavardt.com/)
* **GitHub Organization:** [https://github.com/TAVARDT-USA](https://github.com/TAVARDT-USA)

## License

Distributed under the MIT License. See `LICENSE` for more information.
