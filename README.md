# DNS Resolver & Cache Server (UDP, From Scratch)

## 1. Introduction

This project implements a fully functional DNS Resolver Server using low-level UDP socket programming in Python. The resolver is built from scratch without relying on external DNS libraries, providing a deep understanding of how the Domain Name System (DNS) operates internally.

The system is capable of constructing DNS queries manually, communicating with a public DNS server, parsing binary responses (including compressed formats), and caching results based on Time-To-Live (TTL).

---

## 2. Key Features

* Manual DNS packet construction (Header + Question)
* UDP-based client-server architecture
* DNS query forwarding to 8.8.8.8
* Full DNS response parsing
* Support for A (IPv4) and AAAA (IPv6) records
* TTL-based caching system
* Negative caching (NXDOMAIN handling)
* Cache inspection via command interface
* Clean and structured terminal output

---

## 3. System Architecture

Client → Resolver Server → External DNS Server (8.8.8.8)

### Workflow

1. Client sends a domain query to the resolver
2. Resolver checks local cache
3. If cache hit → return cached result
4. If cache miss → forward request to external DNS
5. Parse response and extract relevant records
6. Store result with TTL in cache
7. Return formatted result to client

---

## 4. Project Structure

```
Network-Programming-Project/
│
├── server.py        # DNS Resolver Server
├── client.py        # DNS Client
├── utils.py         # DNS packet utilities
├── cache.py         # Cache logic and TTL handling
└── README.md
```

---

## 5. DNS Protocol Implementation

### 5.1 DNS Header

Each DNS query includes a 12-byte header:

* ID: Unique query identifier
* Flags: Standard query (0x0100)
* QDCOUNT: Number of questions (1)
* ANCOUNT, NSCOUNT, ARCOUNT: Initially 0

---

### 5.2 Domain Name Encoding

Domain names are encoded into DNS format:

Example:

google.com →
06 google 03 com 00

---

### 5.3 Record Types Supported

* A (Type 1): IPv4 address
* AAAA (Type 28): IPv6 address

---

### 5.4 Name Compression Handling

DNS responses often use pointer compression:

* Prefix 0xC0 indicates a pointer
* Resolver correctly skips compressed labels

---

## 6. Caching System

### Cache Structure

Each cache entry includes:

* Domain name
* Record type
* IP address or error
* Expiration time (TTL)

### Behavior

* Cache hit → return immediately
* Cache miss → query external DNS
* Expired entries are automatically removed

---

## 7. Negative Caching

When a domain does not exist:

* Store NXDOMAIN result
* Assign short TTL
* Avoid repeated external queries

---

## 8. Communication Protocol

### Client Request Format

```
<domain> [TYPE]
```

Examples:

```
google.com
google.com AAAA
/cache
```

---

### Server Response Format

Success:

```
Result: domain -> IP
Source: Cache hit / DNS query
TTL: remaining seconds
```

Error:

```
Error: NXDOMAIN - domain does not exist
```

---

## 9. Demonstration

### Example 1: Cache Miss

Request:

```
google.com
```

Response:

```
Result: google.com -> 142.250.xxx.xxx
Source: DNS query (fresh)
TTL: 27s
```

---

### Example 2: Cache Hit

```
Source: Cache hit
```

---

### Example 3: Cache Inspection

```
/cache
```

Output:

```
--- CURRENT CACHE ---
google.com [A] -> 142.250.xxx.xxx | TTL: 12s
```

---

## 10. How to Run

### Start Server

```
python3 server.py
```

---

### Start Client

```
python3 client.py
```

---

### Sample Commands

```
google.com
example.com
/cache
exit
```

---

## 11. Technical Highlights

* Low-level socket programming (UDP)
* Binary packet manipulation using struct
* DNS protocol reverse engineering
* TTL-based caching strategy
* Error handling for real-world scenarios

---

## 12. Performance Considerations

* Cache significantly reduces query latency
* Avoids redundant DNS requests
* Efficient handling of repeated queries

---

## 13. Future Improvements

* Support additional DNS records (MX, CNAME, NS)
* Multi-threaded resolver
* Persistent cache (file/database)
* Web-based interface
* Performance benchmarking and logging

---

## 14. Learning Outcomes

Through this project, we achieved:

* Strong understanding of DNS internals
* Practical experience with network protocols
* Ability to build systems without high-level libraries
* Improved debugging and packet analysis skills

---

## 15. Conclusion

This project demonstrates a complete DNS Resolver system with caching, built entirely from scratch. It replicates key behaviors of real-world DNS systems, providing both educational value and practical experience in network programming.

---
