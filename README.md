# D2 – DNS Resolver & Cache Server (UDP, Raw DNS per RFC 1035)

## Language and Operating System
* **Programming Language:** Python 3.12+
* **Libraries Used:** Python Standard Library (`socket`, `struct`, `time`) and `colorama` (for terminal formatting only).
* **Operating System Tested:** Linux (Kali Linux / Ubuntu-based distributions).
* **Network Environment:** Localhost communication over IPv4 (127.0.0.1) using UDP.

---

## Project Overview
This project implements a functional DNS resolver server from the ground up, strictly adhering to the **RFC 1035** specification. Unlike standard applications that rely on high-level system calls (e.g., `gethostbyname`), this implementation manually constructs raw DNS binary packets, handles bit-level flag manipulation, and manages an internal cache with Time-To-Live (TTL) expiration logic.

The system consists of two primary components:
1.  **Resolver Server:** A multi-functional intermediary that intercepts client requests, communicates with Public DNS (8.8.8.8), and maintains an in-memory database of previous queries.
2.  **DNS Client:** A specialized terminal interface that uses a custom framing protocol to interact with the resolver.

---

## Technical Specifications & DNS Packet Construction

### 1. Message Framing (Client ↔ Resolver)
To ensure data integrity over UDP, a simple application-layer framing is implemented. Each message is prefixed with a **2-byte length header** (unsigned short, big-endian `!H`).
* **Structure:** `[2-byte Length][Message Body]`
* **Purpose:** Allows the receiver to validate the buffer size and handle potential fragmentation or concatenation at the application level before processing the payload.

### 2. Raw DNS Packet Structure (Resolver ↔ 8.8.8.8)
The resolver builds a 12-byte header followed by a variable-length Question section.

#### Header Section (Bit-Field Mapping):
| Field | Size | Description |
|:--- |:--- |:--- |
| ID | 16 bits | Transaction ID (e.g., 1234) |
| QR/Opcode/AA/TC/RD | 16 bits | Query flags (0x0100 for standard recursive query) |
| QDCOUNT | 16 bits | Number of questions (1) |
| ANCOUNT | 16 bits | Number of answers (0 for query) |
| NSCOUNT | 16 bits | Authority records (0) |
| ARCOUNT | 16 bits | Additional records (0) |

#### Question Section:
The domain name is converted into a sequence of length-prefixed labels. For example, `usth.edu.vn` is packed as:
`\x04 usth \x03 edu \x02 vn \x00`
This is strictly followed by:
* **QTYPE:** 2 bytes (`0x0001` for A records, `0x001C` for AAAA records).
* **QCLASS:** 2 bytes (`0x0001` for IN/Internet).

### 3. Response Parsing & Compression
The resolver implements a robust `skip_name` algorithm to navigate the variable-length DNS response. It specifically handles **DNS Message Compression** (identifying pointers starting with `0xC0`), allowing the parser to bypass the mirrored Question section and directly extract the relevant IP address and TTL from the Answer section.

---

## Cybersecurity Considerations

As a security-focused implementation, the following risks and architectural mitigations are identified:

1.  **DNS Cache Poisoning:** This project currently utilizes a static Transaction ID (`1234`). In a production-grade security environment, this identifier must be randomized cryptographically per request to prevent off-path attackers from injecting malicious records by guessing the ID.
2.  **UDP Spoofing and Amplification:** Since UDP is a connectionless protocol, the resolver is susceptible to source IP spoofing. While we verify the source address via `recvfrom`, a robust deployment would require DNSSEC implementation to cryptographically verify the integrity of the records received from 8.8.8.8.
3.  **Information Leakage via Management Commands:** The `/cache` command provides full transparency into the server's memory. From a privacy and operational security perspective, this exposes user browsing history and internal network behavior. This command should be restricted to administrative interfaces or authenticated channels.
4.  **Negative Caching Efficiency:** By implementing negative caching for `NXDOMAIN` (stored for 60 seconds), the server actively prevents "Random Subdomain Attacks" (e.g., Water Torture attacks) from overwhelming the upstream recursive resolver, providing a fundamental layer of resource exhaustion protection.

---

## How to Run

### 1. Start the Resolver Server
Execute the server script first to begin listening for incoming connections:

    python3 server.py

The server binds to `0.0.0.0:8888`. It will display incoming client addresses and the status of each resolution (Cache hit vs. Fresh query).

### 2. Run the DNS Client
In a separate terminal, launch the interactive client application:

    python3 client.py

**Interactive Commands:**
* `<domain>` (e.g., `google.com`) — Queries the default IPv4 (A) record.
* `<domain> AAAA` (e.g., `google.com AAAA`) — Queries the IPv6 (AAAA) record.
* `/cache` — Requests a full dump of the server's current cache status.
* `exit` — Safely closes the socket and terminates the client session.

### 3. Live Demo Observations
As demonstrated in the project execution logs:
* **Initial Lookup:** A query for `google.com` results in a "DNS query (fresh)" with the original TTL (e.g., 27s).
* **Subsequent Lookup:** Repeating the same query immediately returns "Source: Cache hit" with a decreasing TTL, confirming the internal expiration timer is functioning accurately.
* **Non-existent Domain:** A query for an invalid domain returns a red-formatted `NXDOMAIN` error, which is subsequently stored in the negative cache.
* **Cache Management:** Executing `/cache` displays all active memory records, their types (A/AAAA/NXDOMAIN), and real-time remaining TTL.

---
