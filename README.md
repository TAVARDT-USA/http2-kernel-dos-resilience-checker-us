# HTTP/2 & Linux Kernel DoS Resilience Checker

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-usa.github.io/http2-kernel-dos-resilience-checker-us/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![RFC 7540](https://img.shields.io/badge/RFC-7540-blue.svg)](https://datatracker.ietf.org/doc/html/rfc7540)
[![RFC 9113](https://img.shields.io/badge/RFC-9113-blue.svg)](https://datatracker.ietf.org/doc/html/rfc9113)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

***

Automated security auditor for Linux kernel networking parameters, HTTP/2 protocol negotiation (ALPN), and Denial-of-Service resilience engineered by **TAVARDT**, aligned with NIST SP 800-53 Rev. 5, SOC 2 Type II, and CISA recommendations.

Modern web services face persistent denial-of-service threats targeting low-level protocol implementations, including NoisyTCP and HTTP/2 Rapid Reset. Without disciplined kernel socket tuning and protocol validation, origin servers suffer thread starvation and network interface exhaustion under asymmetric traffic loads.

***

## Core Capabilities and Defensive Architecture

* **Deterministic Linux Kernel Parameter Auditing**: Evaluates `/proc/sys/net/` network parameters against hardening standards to mitigate NoisyTCP, SYN flood, and connection saturation.
* **Remote HTTP/2 Protocol Verification**: Audits Application-Layer Protocol Negotiation (ALPN) over TLS to confirm strict `h2` multiplexing support on remote endpoints.
* **Information Disclosure Detection**: Identifies sensitive web server banners and framework exposure across `Server` and `X-Powered-By` response headers.
* **Zero External Dependencies**: Engineered with pure Python standard library modules (`socket`, `ssl`, `json`, `os`, `sys`), delivering ultra-fast execution with zero third-party package overhead.
* **Automated Pipeline Integration**: Emits machine-readable JSON reports via the `-json` flag for continuous compliance monitoring in CI/CD environments.

***

## Threat Vectors and Operational Impact

Operating network servers with default Linux configuration parameters leaves edge infrastructure vulnerable to severe denial-of-service attacks. The tool audits four critical threat vectors:

* **NoisyTCP and Sequence Number Poisoning**: Attackers manipulating TCP timestamps to force artificial packet reordering and CPU queue saturation.
* **TCP SYN Flood and Connection Starvation**: Exhaustion of pending connection queues due to unhardened backlog limits and missing SYN cookie protections.
* **HTTP/2 Protocol Downgrade and Cleartext Fallback**: Failure to negotiate ALPN `h2`, exposing connections to inefficient HTTP/1.1 pipeline stalls.
* **Infrastructure Fingerprinting via Banner Leaks**: Web servers broadcasting detailed software versions in headers, facilitating targeted exploitation.

***

## Installation and Execution CLI

Execute local kernel checks or remote protocol audits using standard Python commands:

```bash
# Clone the official repository
git clone https://github.com/TAVARDT-USA/http2-kernel-dos-resilience-checker-us.git

# Enter workspace directory
cd http2-kernel-dos-resilience-checker-us

# Audit local Linux kernel sysctl network parameters
python http2_kernel_dos_checker.py -kernel

# Audit remote endpoint for HTTP/2 ALPN and banner disclosure
python http2_kernel_dos_checker.py -host example.com -port 443

# Output structured JSON report for CI/CD pipelines
python http2_kernel_dos_checker.py -host example.com -json
```

***

## Frequently Asked Technical Questions

### How does tuning Linux kernel sysctl parameters mitigate NoisyTCP denial-of-service vectors?

Disabling TCP timestamps prevents sequence number prediction attacks and artificial packet reordering that saturate network stack queues. Concurrently enabling TCP SYN cookies and expanding socket backlogs ensures connection integrity during high-volume SYN flood attempts.

### Why is Application-Layer Protocol Negotiation (ALPN) verification critical for HTTP/2 security?

ALPN guarantees that client and server negotiate binary stream multiplexing securely over TLS rather than falling back to unencrypted cleartext protocols. Verifying ALPN selection confirms that modern stream controls and flow-window limits are properly established at connection setup.

### How does exposing Server and X-Powered-By banners increase server vulnerability to targeted DoS exploits?

Revealing precise web server software versions allows adversaries to weaponize known implementation-specific vulnerabilities and protocol parsing flaws against the host. Suppressing banner headers deprives automated reconnaissance tools of fingerprinting data needed to execute targeted buffer or stream attacks.

### What is the operational distinction between running a local kernel audit and a remote endpoint audit?

The local kernel audit inspects sysctl parameters directly within the Linux proc filesystem to verify OS-level network resilience. Conversely, the remote audit evaluates network-facing TLS handshakes, ALPN support, and banner leakage without requiring administrative host access.

### Can the resilience checker be automated within continuous integration and infrastructure monitoring pipelines?

The CLI tool supports structured output through the -json flag, allowing automated pipelines to inspect kernel compliance scores and remote TLS parameters. DevOps workflows can parse the resulting JSON data to halt staging deployments if critical network parameters fail hardening thresholds.

***

## Useful Links

* **Corporate Portal:** https://ag.tavardt.com/
* **Diagnostic Suite:** https://tools.tavardt.com/
* **Technical Contact:** https://ag.tavardt.com/contact/

***

### License
Released under the MIT License. See [LICENSE](LICENSE) for full details.

***

© 2026 TAVARDT. All rights reserved.
