#!/usr/bin/env python3
"""
TAVARDT HTTP/2 & Linux Kernel DoS Resilience Checker
Auditor de Resiliencia contra NoisyTCP, Rapid Reset e Queda de Servidores Web
TAVARDT Brasil - Ciberseguranca e Infraestrutura de Alta Confiabilidade
"""

import sys
import os
import json
import socket
import ssl
import argparse
from typing import Dict, Any, List

VERSION = "1.0.0"

# Parametros recomendados para mitigacao de NoisyTCP e DoS TCP no Linux
RECOMMENDED_SYSCTL = {
    "net.ipv4.tcp_syncookies": {"expected": "1", "weight": 20, "desc": "Protecao contra SYN Flood e saturacao de conexoes"},
    "net.ipv4.tcp_timestamps": {"expected": "0", "weight": 20, "desc": "Mitigacao de envenenamento e reordenacao NoisyTCP"},
    "net.ipv4.tcp_sack": {"expected": "1", "weight": 15, "desc": "Reconhecimento seletivo de pacotes TCP"},
    "net.ipv4.tcp_fin_timeout": {"expected": "15", "weight": 15, "desc": "Liberacao rapida de sockets em estado FIN-WAIT"},
    "net.ipv4.tcp_max_syn_backlog": {"expected": "8192", "weight": 15, "desc": "Fila estendida para requisicoes pendentes de handshake"},
    "net.core.somaxconn": {"expected": "4096", "weight": 15, "desc": "Limite de backlog de conexoes de sockets do sistema"}
}

def audit_local_kernel() -> Dict[str, Any]:
    """Audita os parametros de rede do kernel Linux local contra a falha NoisyTCP."""
    results = {
        "platform": sys.platform,
        "is_linux": sys.platform.startswith("linux"),
        "checks": [],
        "score": 100,
        "critical_alerts": []
    }

    if not results["is_linux"]:
        results["warning"] = "Auditoria de kernel aplicavel nativamente em hosts Linux. Em outros sistemas operacionais, utilize a auditoria remota via rede."
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
                "current": current_val or "nao_configurado",
                "recommended": meta["expected"],
                "desc": meta["desc"]
            })

        results["checks"].append({
            "param": param,
            "current": current_val or "indisponivel",
            "recommended": meta["expected"],
            "status": "CONFORME" if conforming else "VULNERAVEL",
            "desc": meta["desc"]
        })

    results["score"] = round((accumulated_score / total_weight) * 100)
    return results

def audit_remote_host(host: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
    """Audita um endpoint remoto avaliando negociacao HTTP/2, TLS e vazamento de versao."""
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

    # Tenta negociar ALPN com suporte explicito a h2
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
        report["findings"].append(f"Falha na conexao TLS com {host}:{port}: {e}")
        return report

    # Checagem de cabeçalhos HTTP
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

    # Calculo de score remoto
    deductions = 0
    if not report["http2_supported"]:
        deductions += 40
        report["findings"].append("ALPN h2 nao negociado: servidor sem multiplexacao moderna ou com h2c em texto claro.")
    if report["banner_leaked"]:
        deductions += 30
        report["findings"].append(f"Vazamento de versao de software ativo no banner: '{report.get('server_banner')}'")

    report["score"] = max(10, 100 - deductions)
    return report

def main():
    parser = argparse.ArgumentParser(
        description="TAVARDT Auditor de Resiliencia HTTP/2 & NoisyTCP Linux Kernel"
    )
    parser.add_argument("-host", help="Host remoto para auditoria de negociacao HTTP/2 e banners", default=None)
    parser.add_argument("-port", help="Porta remota (padrao: 443)", type=int, default=443)
    parser.add_argument("-kernel", action="store_true", help="Executar auditoria local dos parametros de rede do Linux")
    parser.add_argument("-json", action="store_true", help="Retornar saida exclusivamente em formato JSON")

    args = parser.parse_args()

    results = {
        "version": VERSION,
        "auditor": "TAVARDT Brasil",
        "documentation": "https://ag.tavardt.com/br/ciberseguranca/",
        "web_tool": "https://tavardt-brasil.github.io/http2-kernel-dos-resilience-checker-br/"
    }

    if args.kernel or (not args.host and not args.kernel):
        results["kernel_audit"] = audit_local_kernel()

    if args.host:
        results["remote_audit"] = audit_remote_host(args.host, args.port)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    print("================================================================================")
    print("      TAVARDT - AUDITOR DE RESILIENCIA HTTP/2 & QUEDA DE KERNEL LINUX           ")
    print("================================================================================")
    print(f"Versao: {VERSION} | Jurisdicao: Brasil | Portal: https://ag.tavardt.com/br/")
    print("================================================================================\n")

    if "kernel_audit" in results:
        ka = results["kernel_audit"]
        print(f"[*] AUDITORIA DE KERNEL LINUX (NoisyTCP Mitigation) | Score: {ka['score']}/100")
        if not ka["is_linux"]:
            print(f"    [AVISO] {ka.get('warning')}")
        else:
            for c in ka["checks"]:
                tag = "[OK]        " if c["status"] == "CONFORME" else "[VULNERAVEL]"
                print(f"    {tag} {c['param']}: atual={c['current']} | recomendado={c['recommended']}")
        print()

    if "remote_audit" in results:
        ra = results["remote_audit"]
        print(f"[*] AUDITORIA REMOTA DE PROTOCOLO: {ra['target']} | Score: {ra['score']}/100")
        print(f"    HTTP/2 Suportado (ALPN): {'SIM' if ra['http2_supported'] else 'NAO'}")
        print(f"    Versao TLS: {ra['tls_version'] or 'Desconhecida'}")
        print(f"    Banner Server Exposto: {'SIM (' + ra['server_banner'] + ')' if ra['banner_leaked'] else 'NAO (Protegido)'}")
        if ra["findings"]:
            print("    Apontamentos de Risco:")
            for f in ra["findings"]:
                print(f"      - {f}")
        print()

    print("Para suporte tecnico e blindagem perimetral:")
    print("TAVARDT Brasil: https://ag.tavardt.com/br/ciberseguranca/")

if __name__ == "__main__":
    main()
