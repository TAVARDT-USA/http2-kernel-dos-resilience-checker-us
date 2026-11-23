# HTTP/2 & Linux Kernel DoS Resilience Hardening Hub

Corporate technical defensive engineering specification and infrastructure hardening blueprints for mitigating HTTP/2 Rapid Reset (CVE-2023-44487) and NoisyTCP resource saturation vectors, Linux kernel sysctl hardening, and deterministic local CLI verification.

## Repository Technical Scope

This repository provides production-tested server hardening templates and deterministic CLI verification tooling:

1. **sysctl-hardening.conf:** Optimized `/proc/sys/net/ipv4` parameters mitigating SYN floods, NoisyTCP timestamp attacks, and orphaned socket exhaustion.
2. **nginx-http2-hardened.conf:** Hardened NGINX reverse proxy configuration enforcing strict stream concurrency limits (`http2_max_concurrent_streams 64`) and aggressive RST_STREAM rate limiting.
3. **nftables-dos-protection.conf:** Layer 4 packet filtering rules dropping anomalous TCP SYN and RST bursts prior to kernel socket allocation.
4. **docker-compose-hardened.yml:** Isolated container architecture applying resource limits (memory, CPU, ulimits) to edge web proxies.
5. **http2_kernel_dos_checker.py:** Deterministic local CLI utility running with system privileges on the server host to directly audit `/proc/sys` parameters and verify RFC compliance.

> [!NOTE]
> Active Linux kernel state inspection and network stack parameter audits require system privileges and must be executed directly on the server host using the provided Python CLI tool. Web pages running in browser sandboxes cannot audit host kernel parameters.

## CLI Utility Usage

Run the deterministic audit script directly on the server host:

```bash
# 1. Download audit script
curl -sO https://raw.githubusercontent.com/TAVARDT-USA/http2-kernel-dos-resilience-checker-us/main/http2_kernel_dos_checker.py

# 2. Inspect local Linux kernel parameters
sudo python3 http2_kernel_dos_checker.py -kernel

# 3. Output results in machine-readable JSON format
sudo python3 http2_kernel_dos_checker.py -kernel -json
```

## Governance & Sovereignty

* **Organization:** TAVARDT-USA
* **Jurisdiction:** USA
* **Standards Compliance:** RFC 7540, RFC 9113, CVE-2023-44487, Zero Trust Architecture

Developed by the **TAVARDT USA** Cybersecurity & Infrastructure Engineering Division. All rights reserved.
