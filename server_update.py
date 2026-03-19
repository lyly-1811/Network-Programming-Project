import socket
import struct
import time
from colorama import init

init()  # enable color on Windows

# ==============================
# COLOR
# ==============================
class Color:
    RESET = "\033[0m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"


# ==============================
# CONFIG
# ==============================
PORT = 8888
DNS_SERVER = "8.8.8.8"
DNS_PORT = 53
BUF_SIZE = 2048

# cache: (domain, type) -> {ip, expire, is_nx}
dns_cache = {}


# ==============================
# UI
# ==============================
def banner():
    print(Color.CYAN + "="*60)
    print("        DNS RESOLVER SERVER (UDP)")
    print("   Support: A (IPv4), AAAA (IPv6)")
    print("   Command: /cache")
    print("="*60 + Color.RESET)


# ==============================
# BUILD QNAME
# ==============================
def build_qname(domain):
    res = b''
    for p in domain.split('.'):
        res += bytes([len(p)]) + p.encode()
    return res + b'\x00'


# ==============================
# SKIP NAME (DNS compression)
# ==============================
def skip_name(resp, offset):
    while True:
        l = resp[offset]
        if l == 0:
            return offset + 1
        if (l & 0xC0) == 0xC0:
            return offset + 2
        offset += l + 1


# ==============================
# CACHE DUMP
# ==============================
def dump_cache():
    now = time.time()
    out = "\n--- CURRENT DNS CACHE ---\n"

    if not dns_cache:
        return out + "Cache is empty.\n"

    for key, val in list(dns_cache.items()):
        domain, rtype = key
        ttl = int(val['expire'] - now)

        if ttl <= 0:
            del dns_cache[key]
            continue

        status = "NXDOMAIN" if val['is_nx'] else val['ip']
        out += f"{domain} [{rtype}] -> {status} | TTL: {ttl}s\n"

    return out + "-------------------------\n"


# ==============================
# RESOLVE
# ==============================
def resolve(domain, rtype="A"):
    now = time.time()
    key = (domain, rtype)

    # ===== CACHE =====
    if key in dns_cache:
        e = dns_cache[key]
        if now < e['expire']:
            ttl = int(e['expire'] - now)

            if e['is_nx']:
                return f"Error: NXDOMAIN - '{domain}' does not exist.\nSource: Cache\nTTL: {ttl}s remaining\n"

            return f"Result: {domain} -> {e['ip']}\nSource: Cache hit\nTTL: {ttl}s remaining\n"

    # ===== SEND DNS QUERY =====
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)

        header = struct.pack("!HHHHHH", 1234, 0x0100, 1, 0, 0, 0)

        qname = build_qname(domain)
        qtype = 28 if rtype == "AAAA" else 1
        question = struct.pack("!HH", qtype, 1)

        packet = header + qname + question

        sock.sendto(packet, (DNS_SERVER, DNS_PORT))
        resp, _ = sock.recvfrom(BUF_SIZE)
        sock.close()

    except:
        return "Error: Timeout reaching DNS server.\n"

    # ===== PARSE HEADER =====
    _, flags, _, ancount, _, _ = struct.unpack("!HHHHHH", resp[:12])
    rcode = flags & 0x000F

    # ===== NXDOMAIN =====
    if rcode == 3:
        dns_cache[key] = {
            "ip": "",
            "expire": now + 60,
            "is_nx": True
        }
        return f"Error: NXDOMAIN - '{domain}' does not exist.\n"

    # ===== ANSWER =====
    if ancount > 0:
        offset = skip_name(resp, 12) + 4

        for _ in range(ancount):
            offset = skip_name(resp, offset)

            atype, _, ttl, rdlength = struct.unpack("!HHIH", resp[offset:offset+10])
            offset += 10

            # IPv4
            if atype == 1 and rtype == "A":
                ip = socket.inet_ntoa(resp[offset:offset+4])

                dns_cache[key] = {
                    "ip": ip,
                    "expire": now + ttl,
                    "is_nx": False
                }

                return f"Result: {domain} -> {ip}\nSource: DNS query (fresh)\nTTL: {ttl}s\n"

            # IPv6
            if atype == 28 and rtype == "AAAA":
                ip = socket.inet_ntop(socket.AF_INET6, resp[offset:offset+16])

                dns_cache[key] = {
                    "ip": ip,
                    "expire": now + ttl,
                    "is_nx": False
                }

                return f"Result: {domain} -> {ip}\nSource: DNS query (fresh)\nTTL: {ttl}s\n"

            offset += rdlength

        return f"Error: No valid {rtype} record found.\n"

    return "Error: Empty DNS response.\n"


# ==============================
# MAIN
# ==============================
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))

    banner()
    print(Color.GREEN + f"[INFO] Server running on port {PORT}\n" + Color.RESET)

    while True:
        data, addr = server.recvfrom(BUF_SIZE)
        req = data.decode().strip()

        if not req:
            continue

        print(Color.BLUE + "-"*60 + Color.RESET)
        print(Color.YELLOW + f"[CLIENT] {addr}" + Color.RESET)
        print(Color.CYAN + f"[REQUEST] {req}" + Color.RESET)

        # ===== HANDLE =====
        if req == "/cache":
            res = dump_cache()

        else:
            parts = req.split()
            domain = parts[0]
            rtype = parts[1].upper() if len(parts) > 1 else "A"

            if rtype not in ["A", "AAAA"]:
                res = "Error: Only A and AAAA are supported.\n"
            else:
                print(Color.MAGENTA + f"[ACTION] Resolving {domain} ({rtype})" + Color.RESET)
                res = resolve(domain, rtype)

        print(Color.GREEN + "[RESPONSE]" + Color.RESET)

        if "Error" in res:
            print(Color.RED + res.strip() + Color.RESET)
        else:
            print(Color.GREEN + res.strip() + Color.RESET)

        print(Color.BLUE + "-"*60 + Color.RESET)

        server.sendto(res.encode(), addr)


# ==============================
# RUN
# ==============================
if __name__ == "__main__":
    main()
