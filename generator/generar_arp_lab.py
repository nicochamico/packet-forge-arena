#!/usr/bin/env python3
"""
SPNet Packet Forge Arena — Generador ARP parametrizado.

Uso:
  python generar_arp_lab.py --seed 42 --out ../output/arp_lab_seed42.pcapng

Salida:
  - PCAPNG sintético ARP
  - JSON con respuestas por ordinal para cargar con load_answer_keys_for_attempt()
  - TXT con resumen técnico para el instructor

No usa librerías externas.
"""

from __future__ import annotations
import argparse
import ipaddress
import json
import random
import struct
import time
from dataclasses import dataclass
from pathlib import Path

BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
ZERO_IP = "0.0.0.0"


def mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def ip_bytes(ip: str) -> bytes:
    return ipaddress.IPv4Address(ip).packed


def pad4(data: bytes) -> bytes:
    return data + (b"\x00" * ((4 - len(data) % 4) % 4))


def pcapng_block(block_type: int, body: bytes) -> bytes:
    total_len = 12 + len(body)
    return struct.pack("<II", block_type, total_len) + body + struct.pack("<I", total_len)


def write_pcapng(path: Path, packets: list[bytes]) -> None:
    # Section Header Block
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    # Interface Description Block: Ethernet, snaplen 65535
    idb_body = struct.pack("<HHI", 1, 0, 65535)

    out = bytearray()
    out += pcapng_block(0x0A0D0D0A, shb_body)
    out += pcapng_block(0x00000001, idb_body)

    ts_base = int(time.time() * 1_000_000)
    for i, pkt in enumerate(packets):
        ts = ts_base + i * 1000
        ts_high = ts >> 32
        ts_low = ts & 0xFFFFFFFF
        data = pad4(pkt)
        epb_body = struct.pack("<IIIII", 0, ts_high, ts_low, len(pkt), len(pkt)) + data
        out += pcapng_block(0x00000006, epb_body)

    path.write_bytes(out)


def arp_frame(
    eth_src: str,
    eth_dst: str,
    op: int,
    sha: str,
    spa: str,
    tha: str,
    tpa: str,
) -> bytes:
    eth = mac_bytes(eth_dst) + mac_bytes(eth_src) + struct.pack("!H", 0x0806)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op)
    arp += mac_bytes(sha) + ip_bytes(spa) + mac_bytes(tha) + ip_bytes(tpa)
    frame = eth + arp
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def make_mac(r: random.Random, used: set[str]) -> str:
    while True:
        mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(r.randrange(0, 256) for _ in range(5))
        if mac not in used:
            used.add(mac)
            return mac


@dataclass
class EventFrame:
    frame_no: int
    kind: str
    eth_src: str
    eth_dst: str
    op: int
    sha: str
    spa: str
    tha: str
    tpa: str


def build_lab(seed: int):
    r = random.Random(seed)
    used_macs: set[str] = set()

    # IPs documentales RFC 5737
    gateway_ip = "192.0.2.1"
    client_ip = f"192.0.2.{r.randint(10, 30)}"
    client_b_ip = f"192.0.2.{r.randint(31, 50)}"
    dns_ip = f"192.0.2.{r.randint(51, 70)}"
    scanner_ip = f"192.0.2.{r.randint(71, 85)}"
    attacker_ip = f"192.0.2.{r.randint(86, 99)}"
    conflict_ip = f"192.0.2.{r.randint(100, 115)}"
    new_ip = f"192.0.2.{r.randint(116, 130)}"
    scan_start = r.randint(131, 150)
    scan_ips = [f"192.0.2.{scan_start+i}" for i in range(20)]
    remote_ip = f"198.51.100.{r.randint(10, 240)}"

    gateway_mac = make_mac(r, used_macs)
    client_mac = make_mac(r, used_macs)
    client_b_mac = make_mac(r, used_macs)
    dns_mac = make_mac(r, used_macs)
    scanner_mac = make_mac(r, used_macs)
    attacker_mac = make_mac(r, used_macs)
    conflict_mac_1 = make_mac(r, used_macs)
    conflict_mac_2 = make_mac(r, used_macs)
    proxy_mac = make_mac(r, used_macs)
    new_mac = make_mac(r, used_macs)

    active_scan = {
        scan_ips[2]: make_mac(r, used_macs),
        scan_ips[5]: make_mac(r, used_macs),
        scan_ips[9]: make_mac(r, used_macs),
        scan_ips[13]: make_mac(r, used_macs),
        scan_ips[17]: make_mac(r, used_macs),
    }
    unused_ip = next(ip for ip in scan_ips if ip not in active_scan)

    events: list[EventFrame] = []

    def add(kind: str, eth_src: str, eth_dst: str, op: int, sha: str, spa: str, tha: str, tpa: str):
        events.append(EventFrame(len(events) + 1, kind, eth_src, eth_dst, op, sha, spa, tha, tpa))

    def req(kind: str, src_mac: str, src_ip: str, target_ip: str, eth_dst: str = BROADCAST, target_mac: str = ZERO_MAC):
        add(kind, src_mac, eth_dst, 1, src_mac, src_ip, target_mac, target_ip)

    def rep(kind: str, src_mac: str, src_ip: str, dst_mac: str, dst_ip: str):
        add(kind, src_mac, dst_mac, 2, src_mac, src_ip, dst_mac, dst_ip)

    # Resoluciones normales
    req("normal_request", client_mac, client_ip, gateway_ip)
    rep("normal_reply", gateway_mac, gateway_ip, client_mac, client_ip)
    req("normal_request", client_mac, client_ip, dns_ip)
    rep("normal_reply", dns_mac, dns_ip, client_mac, client_ip)
    req("normal_request", client_b_mac, client_b_ip, gateway_ip)
    rep("normal_reply", gateway_mac, gateway_ip, client_b_mac, client_b_ip)
    req("normal_request", dns_mac, dns_ip, gateway_ip)
    rep("normal_reply", gateway_mac, gateway_ip, dns_mac, dns_ip)
    req("normal_request", client_mac, client_ip, client_b_ip)
    rep("normal_reply", client_b_mac, client_b_ip, client_mac, client_ip)
    req("normal_request", client_b_mac, client_b_ip, client_ip)
    rep("normal_reply", client_mac, client_ip, client_b_mac, client_b_ip)

    # Gratuitous ARP / anuncio
    req("gratuitous", client_b_mac, client_b_ip, client_b_ip)
    add("gratuitous", client_b_mac, BROADCAST, 2, client_b_mac, client_b_ip, BROADCAST, client_b_ip)

    # Conflicto de IP: dos MAC responden por la misma IP
    req("conflict_query", client_mac, client_ip, conflict_ip)
    rep("conflict_reply_mac1", conflict_mac_1, conflict_ip, client_mac, client_ip)
    req("conflict_query", client_mac, client_ip, conflict_ip)
    rep("conflict_reply_mac2", conflict_mac_2, conflict_ip, client_mac, client_ip)

    # ARP scan
    for ip in scan_ips:
        req("scan_request", scanner_mac, scanner_ip, ip)
        if ip in active_scan:
            rep("scan_reply", active_scan[ip], ip, scanner_mac, scanner_ip)

    # Proxy ARP
    req("proxy_request", client_mac, client_ip, remote_ip)
    rep("proxy_reply", proxy_mac, remote_ip, client_mac, client_ip)

    # Spoofing: atacante dice que la IP del gateway está en su MAC
    first_spoof_frame = len(events) + 1
    for _ in range(4):
        rep("spoof_reply", attacker_mac, gateway_ip, client_mac, client_ip)
    rep("legit_correction", gateway_mac, gateway_ip, client_mac, client_ip)

    # ARP probing y anuncios posteriores
    for _ in range(3):
        req("probe", new_mac, ZERO_IP, new_ip)
    req("post_probe_announcement", new_mac, new_ip, new_ip)
    add("post_probe_announcement", new_mac, BROADCAST, 2, new_mac, new_ip, BROADCAST, new_ip)

    # Unicast ARP request + respuesta
    req("unicast_request", client_mac, client_ip, gateway_ip, eth_dst=gateway_mac, target_mac=gateway_mac)
    rep("unicast_reply", gateway_mac, gateway_ip, client_mac, client_ip)

    packets = [arp_frame(e.eth_src, e.eth_dst, e.op, e.sha, e.spa, e.tha, e.tpa) for e in events]

    request_count = sum(1 for e in events if e.op == 1)
    reply_count = sum(1 for e in events if e.op == 2)
    broadcast_count = sum(1 for e in events if e.eth_dst.lower() == BROADCAST)
    unicast_count = len(events) - broadcast_count
    gratuitous_count = sum(1 for e in events if e.spa == e.tpa and e.spa != ZERO_IP)
    spoof_count = sum(1 for e in events if e.kind == "spoof_reply")
    unanswered_scan_count = len(scan_ips) - len(active_scan)
    probe_count = sum(1 for e in events if e.kind == "probe" and e.spa == ZERO_IP)
    post_probe_count = sum(1 for e in events if e.kind == "post_probe_announcement")
    conflict_frame_count = sum(1 for e in events if e.kind.startswith("conflict"))
    gateway_reply_claims = [e for e in events if e.op == 2 and e.spa == gateway_ip]
    gateway_claim_macs = []
    for e in gateway_reply_claims:
        if e.sha not in gateway_claim_macs:
            gateway_claim_macs.append(e.sha)
    client_mac_frames = sum(1 for e in events if e.eth_src == client_mac or e.eth_dst == client_mac)

    answers = [
        {"ordinal": 1, "answer": str(len(events))},
        {"ordinal": 2, "answer": str(request_count)},
        {"ordinal": 3, "answer": str(reply_count)},
        {"ordinal": 4, "answer": gateway_ip},
        {"ordinal": 5, "answer": gateway_mac},
        {"ordinal": 6, "answer": client_ip},
        {"ordinal": 7, "answer": client_mac},
        {"ordinal": 8, "answer": gateway_ip},
        {"ordinal": 9, "answer": gateway_mac},
        {"ordinal": 10, "answer": str(broadcast_count)},
        {"ordinal": 11, "answer": str(unicast_count)},
        {"ordinal": 12, "answer": str(gratuitous_count)},
        {"ordinal": 13, "answer": client_b_ip},
        {"ordinal": 14, "answer": conflict_ip},
        {"ordinal": 15, "answer": conflict_mac_1},
        {"ordinal": 16, "answer": conflict_mac_2},
        {"ordinal": 17, "answer": attacker_ip},
        {"ordinal": 18, "answer": attacker_mac},
        {"ordinal": 19, "answer": gateway_ip},
        {"ordinal": 20, "answer": client_ip},
        {"ordinal": 21, "answer": str(spoof_count)},
        {"ordinal": 22, "answer": gateway_mac},
        {"ordinal": 23, "answer": scanner_ip},
        {"ordinal": 24, "answer": scanner_mac},
        {"ordinal": 25, "answer": scan_ips[0]},
        {"ordinal": 26, "answer": scan_ips[-1]},
        {"ordinal": 27, "answer": str(unanswered_scan_count)},
        {"ordinal": 28, "answer": unused_ip},
        {"ordinal": 29, "answer": remote_ip},
        {"ordinal": 30, "answer": proxy_mac},
        {"ordinal": 31, "answer": new_ip},
        {"ordinal": 32, "answer": str(probe_count)},
        {"ordinal": 33, "answer": str(post_probe_count)},
        {"ordinal": 34, "answer": new_ip},
        {"ordinal": 35, "answer": new_mac},
        {"ordinal": 36, "answer": str(conflict_frame_count)},
        {"ordinal": 37, "answer": str(len(gateway_reply_claims))},
        {"ordinal": 38, "answer": ",".join(gateway_claim_macs[:2])},
        {"ordinal": 39, "answer": str(client_mac_frames)},
        {"ordinal": 40, "answer": str(first_spoof_frame)},
    ]

    summary = {
        "seed": seed,
        "total_packets": len(events),
        "requests": request_count,
        "replies": reply_count,
        "gateway_ip": gateway_ip,
        "gateway_mac": gateway_mac,
        "client_ip": client_ip,
        "client_mac": client_mac,
        "attacker_ip": attacker_ip,
        "attacker_mac": attacker_mac,
        "first_spoof_frame": first_spoof_frame,
    }
    return packets, answers, summary, events


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    packets, answers, summary, events = build_lab(args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_pcapng(args.out, packets)

    answers_path = args.out.with_suffix(".answers.json")
    summary_path = args.out.with_suffix(".summary.txt")
    events_path = args.out.with_suffix(".events.tsv")

    answers_path.write_text(json.dumps(answers, indent=2, ensure_ascii=False), encoding="utf-8")
    summary_path.write_text("\n".join(f"{k}: {v}" for k, v in summary.items()) + "\n", encoding="utf-8")
    events_path.write_text(
        "frame\tkind\teth.src\teth.dst\top\tarp.sha\tarp.spa\tarp.tha\tarp.tpa\n" +
        "\n".join(
            f"{e.frame_no}\t{e.kind}\t{e.eth_src}\t{e.eth_dst}\t{e.op}\t{e.sha}\t{e.spa}\t{e.tha}\t{e.tpa}"
            for e in events
        ) + "\n",
        encoding="utf-8",
    )

    print(f"PCAPNG: {args.out}")
    print(f"Answers JSON: {answers_path}")
    print(f"Packets: {summary['total_packets']}")


if __name__ == "__main__":
    main()
