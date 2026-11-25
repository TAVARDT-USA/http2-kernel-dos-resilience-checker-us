# HTTP/2 & Linux Kernel DoS Resilience Hardening Hub

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-usa.github.io/http2-kernel-dos-resilience-checker-us/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![RFC 7540](https://img.shields.io/badge/RFC-7540-blue.svg)](https://datatracker.ietf.org/doc/html/rfc7540)
[![RFC 9113](https://img.shields.io/badge/RFC-9113-blue.svg)](https://datatracker.ietf.org/doc/html/rfc9113)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Corporate Technical Defensive Engineering Specification and Hardening Blueprints for HTTP/2 Rapid Reset (CVE-2023-44487) and Linux Kernel Networking Stack**

***

## Online Demonstration

You can inspect the technical defensive specifications, architectural diagnostic tests, and mitigation blueprints directly in your browser:

* **[Official Web Application on GitHub Pages](https://tavardt-usa.github.io/http2-kernel-dos-resilience-checker-us/)**

> [!NOTE]
> **Technical Execution Scope:** This web hub provides defensive architecture specifications and hardening configuration blueprints. Active Linux kernel state inspection and network stack parameter audits require system privileges (root) and must be executed directly on the server host using the provided Python CLI tool (`http2_kernel_dos_checker.py`). Web pages running in browser sandboxes cannot audit host kernel parameters.

***

## Hardening Blueprints Included

1. **sysctl-hardening.conf:** Optimized `/proc/sys/net/ipv4` parameters mitigating SYN floods, NoisyTCP timestamp attacks, and orphaned socket exhaustion.
2. **nginx-http2-hardened.conf:** Hardened NGINX reverse proxy configuration enforcing strict stream concurrency limits (`http2_max_concurrent_streams 64`) and aggressive RST_STREAM rate limiting.
3. **nftables-dos-protection.conf:** Layer 4 packet filtering rules dropping anomalous TCP SYN and RST bursts prior to kernel socket allocation.
4. **docker-compose-hardened.yml:** Isolated container architecture applying resource limits (memory, CPU, ulimits) to edge web proxies.
5. **http2_kernel_dos_checker.py:** Deterministic local CLI utility running with system privileges on the server host to directly audit `/proc/sys` parameters and verify RFC compliance.

***

## Deterministic CLI Utility Usage

Run the deterministic audit script directly on the Linux server host:

```bash
# 1. Download audit script from official repository
curl -sO https://raw.githubusercontent.com/TAVARDT-USA/http2-kernel-dos-resilience-checker-us/main/http2_kernel_dos_checker.py

# 2. Inspect local Linux kernel parameters
sudo python3 http2_kernel_dos_checker.py -kernel

# 3. Output results in machine-readable JSON format
sudo python3 http2_kernel_dos_checker.py -kernel -json
```

***

## Useful Links

* **Corporate Portal:** https://ag.tavardt.com/
* **Diagnostic Suite:** https://tools.tavardt.com/
* **Technical Contact:** https://ag.tavardt.com/contact/

***

### License
Released under the MIT License.

***

© 2026 TAVARDT. All rights reserved.
