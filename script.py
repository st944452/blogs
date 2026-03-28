#!/usr/bin/env python3
import argparse
import concurrent.futures
import ipaddress
import re
import signal
import socket
import ssl
import sys
import threading
from typing import Iterable, List, Optional, Sequence, Tuple


COMMON_TLS_PORTS = {443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 8443}
HTTP_PORTS = {80, 81, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8088, 8888}
STOP_EVENT = threading.Event()


def safe_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return (
            value.decode("utf-8", errors="replace")
            .encode("ascii", errors="replace")
            .decode("ascii")
        )
    return str(value).encode("ascii", errors="replace").decode("ascii")


def unique_preserve_order(items: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def parse_ports(port_spec: str) -> List[int]:
    ports = set()

    for part in port_spec.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            if start > end:
                start, end = end, start
            for port in range(start, end + 1):
                if 1 <= port <= 65535:
                    ports.add(port)
        else:
            port = int(part)
            if 1 <= port <= 65535:
                ports.add(port)

    return sorted(ports)


def parse_targets(target: str) -> List[str]:
    targets = []

    for raw_item in target.split(","):
        item = raw_item.strip()
        if not item:
            continue

        if "/" in item:
            network = ipaddress.ip_network(item, strict=False)
            targets.extend(str(ip) for ip in network.hosts())
            continue

        if "-" in item and item.count(".") == 3:
            prefix, last = item.rsplit(".", 1)
            start_s, end_s = last.split("-", 1)
            start = int(start_s)
            end = int(end_s)

            if not (0 <= start <= 255 and 0 <= end <= 255):
                raise ValueError(f"Invalid range target: {item}")

            if start > end:
                start, end = end, start

            targets.extend(f"{prefix}.{i}" for i in range(start, end + 1))
            continue

        targets.append(item)

    return unique_preserve_order(targets)


def extract_http_title(text: str) -> str:
    match = re.search(r"<title>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = " ".join(match.group(1).split())
    return safe_text(title)


def connect_socket(host: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((host, port), timeout=timeout)


def connect_open(host: str, port: int, timeout: float) -> bool:
    try:
        with connect_socket(host, port, timeout):
            return True
    except Exception:
        return False


def recv_quick(sock: socket.socket, size: int = 4096) -> bytes:
    try:
        return sock.recv(size)
    except Exception:
        return b""


def build_http_probe(host_header: str, path: str = "/") -> bytes:
    return (
        f"GET {path} HTTP/1.0\r\n"
        f"Host: {host_header}\r\n"
        "User-Agent: python-banner-grabber\r\n"
        "Connection: close\r\n\r\n"
    ).encode()


def summarize_http_response(data: bytes) -> str:
    text = safe_text(data)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""

    parts = [lines[0]]
    title = extract_http_title(text)
    if title:
        parts.append(f"Title={title}")

    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith("server:"):
            parts.append(line)
        elif lower.startswith("location:"):
            parts.append(line)
        elif lower.startswith("www-authenticate:"):
            parts.append(line)

    return " | ".join(unique_preserve_order(parts))


def try_plain_banner(
    host: str,
    port: int,
    timeout: float,
    http_host: str,
    http_path: str,
) -> str:
    with connect_socket(host, port, timeout) as sock:
        sock.settimeout(timeout)

        data = recv_quick(sock, 4096)
        if data:
            return safe_text(data).strip()

        if port in HTTP_PORTS:
            probe = build_http_probe(http_host, http_path)
        elif port == 21:
            probe = b"HELP\r\n"
        elif port == 22:
            probe = b"\r\n"
        elif port == 25:
            probe = b"EHLO test\r\n"
        elif port == 110:
            probe = b"QUIT\r\n"
        elif port == 143:
            probe = b". CAPABILITY\r\n"
        elif port == 6379:
            probe = b"PING\r\n"
        elif port in (179, 2601, 2605):
            probe = b"\r\n"
        else:
            probe = b"\r\n"

        sock.sendall(probe)
        data = recv_quick(sock, 4096)
        if not data:
            return ""

        if port in HTTP_PORTS:
            return summarize_http_response(data)

        return safe_text(data).strip()


def try_tls_banner(
    host: str,
    port: int,
    timeout: float,
    http_host: str,
    http_path: str,
    sni_host: str,
) -> str:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with connect_socket(host, port, timeout) as raw:
        raw.settimeout(timeout)
        with context.wrap_socket(raw, server_hostname=sni_host) as tls:
            parts = ["TLS"]

            try:
                cert = tls.getpeercert()
                if cert:
                    subject = cert.get("subject", ())
                    common_name = None
                    for item in subject:
                        for key, value in item:
                            if key == "commonName":
                                common_name = value
                                break
                        if common_name:
                            break
                    if common_name:
                        parts.append(f"CN={safe_text(common_name)}")
            except Exception:
                pass

            try:
                tls.sendall(build_http_probe(http_host, http_path))
                data = recv_quick(tls, 4096)
                if data:
                    summary = summarize_http_response(data)
                    if summary:
                        parts.append(summary)
            except Exception:
                pass

            return " | ".join(parts)


def scan_port(
    host: str,
    port: int,
    timeout: float,
    http_host: str,
    http_path: str,
    sni_host: str,
) -> Optional[Tuple[str, int, str]]:
    if STOP_EVENT.is_set():
        return None

    if not connect_open(host, port, timeout):
        return None

    banner = ""

    try:
        banner = try_plain_banner(host, port, timeout, http_host, http_path)
    except Exception:
        banner = ""

    if not banner and port in COMMON_TLS_PORTS:
        try:
            banner = try_tls_banner(host, port, timeout, http_host, http_path, sni_host)
        except Exception:
            banner = ""
    elif not banner:
        try:
            banner = try_tls_banner(host, port, timeout, http_host, http_path, sni_host)
        except Exception:
            banner = ""

    return host, port, safe_text(banner)


def sort_ip_key(ip: str):
    try:
        return tuple(int(part) for part in ip.split("."))
    except Exception:
        return (ip,)


def write_output(path: str, results: Sequence[Tuple[str, int, str]]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        current_host = None
        for host, port, banner in results:
            if host != current_host:
                if current_host is not None:
                    handle.write("\n")
                current_host = host
                handle.write(f"{host}\n")

            if banner:
                handle.write(f"  {port:<5} | {banner}\n")
            else:
                handle.write(f"  {port:<5} | <no banner>\n")


def main():
    parser = argparse.ArgumentParser(
        description="TCP port scanner + banner grabber using Python only"
    )
    parser.add_argument(
        "target",
        help=(
            "Target host/range. Examples: "
            "127.0.0.1, localhost, 172.16.1.0/24, 172.16.1.1-254, 127.0.0.1,172.16.1.10"
        ),
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="Ports to scan. Examples: 1-1024 or 21,22,80,179,443,2601,2605",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=0.3,
        help="Socket timeout in seconds. Default: 0.3",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=300,
        help="Number of worker threads. Default: 300",
    )
    parser.add_argument(
        "--http-host",
        default="localhost",
        help="Host header to use for HTTP/HTTPS probes. Default: localhost",
    )
    parser.add_argument(
        "--http-path",
        default="/",
        help="Path to request for HTTP/HTTPS probes. Default: /",
    )
    parser.add_argument(
        "--sni",
        default=None,
        help="SNI hostname for TLS probes. Default: same as --http-host",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Write summary output to a file",
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        print("[-] Timeout must be greater than 0")
        sys.exit(1)

    if args.workers <= 0:
        print("[-] Workers must be greater than 0")
        sys.exit(1)

    try:
        targets = parse_targets(args.target)
    except Exception as e:
        print(f"[-] Failed to parse target: {safe_text(e)}")
        sys.exit(1)

    try:
        ports = parse_ports(args.ports)
    except Exception as e:
        print(f"[-] Failed to parse ports: {safe_text(e)}")
        sys.exit(1)

    if not ports:
        print("[-] No valid ports to scan")
        sys.exit(1)

    sni_host = args.sni or args.http_host

    print(f"[+] Targets: {len(targets)}")
    print(f"[+] Ports per target: {len(ports)}")
    print(f"[+] Timeout: {args.timeout}s")
    print(f"[+] Workers: {args.workers}")
    print(f"[+] HTTP Host header: {args.http_host}")
    print(f"[+] HTTP Path: {args.http_path}")
    print(f"[+] TLS SNI: {sni_host}")
    print(f"[+] Total checks: {len(targets) * len(ports)}")

    results: List[Tuple[str, int, str]] = []
    executor: Optional[concurrent.futures.ThreadPoolExecutor] = None

    def handle_interrupt(signum, frame):
        STOP_EVENT.set()
        print("\n[!] Interrupted by user", flush=True)
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
        raise SystemExit(130)

    signal.signal(signal.SIGINT, handle_interrupt)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(
                scan_port,
                host,
                port,
                args.timeout,
                args.http_host,
                args.http_path,
                sni_host,
            )
            for host in targets
            for port in ports
        ]

        for future in concurrent.futures.as_completed(futures):
            try:
                if STOP_EVENT.is_set():
                    break
                result = future.result()
                if result:
                    host, port, banner = result
                    results.append(result)
                    if banner:
                        print(f"[OPEN] {host}:{port:<5} | {safe_text(banner)}")
                    else:
                        print(f"[OPEN] {host}:{port:<5} | <no banner>")
            except KeyboardInterrupt:
                STOP_EVENT.set()
                executor.shutdown(wait=False, cancel_futures=True)
                print("\n[!] Interrupted by user")
                sys.exit(130)
            except Exception:
                continue

    results.sort(key=lambda x: (sort_ip_key(x[0]), x[1]))

    print("\n[+] Scan complete")
    print(f"[+] Open ports found: {len(results)}")

    if results:
        print("\n[+] Summary")
        current_host = None
        for host, port, banner in results:
            if host != current_host:
                current_host = host
                print(f"\n{host}")
            if banner:
                print(f"  {port:<5} | {safe_text(banner)}")
            else:
                print(f"  {port:<5} | <no banner>")

        if args.output:
            try:
                write_output(args.output, results)
                print(f"\n[+] Wrote summary to {args.output}")
            except Exception as e:
                print(f"\n[-] Failed to write output file: {safe_text(e)}")


if __name__ == "__main__":
    main()
