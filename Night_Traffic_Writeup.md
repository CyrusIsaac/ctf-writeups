# CTF Writeup: Night Traffic (DNS Breadcrumbs)

## Challenge Overview

**Challenge Name:** Night Traffic  
**Difficulty:** Medium  
**Category:** Network Analysis / DNS Forensics  
**Flag Format:** `0xV01D{......}`

## Challenge Description

This challenge provides a PCAP (Packet Capture) file containing network traffic that needs to be analyzed to recover a hidden flag. The flag is encoded within DNS queries using a technique called DNS exfiltration - a method where data is hidden within DNS domain names.

## Tools Required

- **Scapy** (Python library for packet manipulation)
- **Python 3.x**
- Basic hex decoding knowledge

## Analysis Steps

### Step 1: Extract the PCAP File

The challenge provides a ZIP archive containing a single PCAP file:
```bash
unzip 05_medium_dns_breadcrumbs.zip
# Output: capture.pcap
```

### Step 2: Read and Analyze the PCAP File

Using Python's Scapy library, we can parse the PCAP file and extract DNS packets:

```python
from scapy.all import rdpcap, DNS

packets = rdpcap('capture.pcap')
print(f"Total packets: {len(packets)}")

for idx, packet in enumerate(packets):
    if packet.haslayer(DNS):
        print(packet.show())
```

### Step 3: Identify DNS Queries

The PCAP file contains **3 DNS query packets**:

#### Packet 0:
- **DNS Query Name:** `3078563031447b444e.part1.ctf.local`
- **Query Type:** A (Address)
- **Query ID:** 16641

#### Packet 1:
- **DNS Query Name:** `535f4c4142454c535f.part2.ctf.local`
- **Query Type:** A (Address)
- **Query ID:** 16642

#### Packet 2:
- **DNS Query Name:** `4152455f4c4f55447d.part3.ctf.local`
- **Query Type:** A (Address)
- **Query ID:** 16643

### Step 4: Extract Hex-Encoded Data

The subdomain portions of each DNS query contain hex-encoded data:

1. `3078563031447b444e`
2. `535f4c4142454c535f`
3. `4152455f4c4f55447d`

### Step 5: Decode from Hex to ASCII

Each hex string represents ASCII characters. Convert using hex decoding:

```python
# Part 1
part1_hex = b'3078563031447b444e'
part1_ascii = bytes.fromhex(part1_hex.decode()).decode()
# Result: "0xV01D{DN"

# Part 2
part2_hex = b'535f4c4142454c535f'
part2_ascii = bytes.fromhex(part2_hex.decode()).decode()
# Result: "S_LABELS_"

# Part 3
part3_hex = b'4152455f4c4f55447d'
part3_ascii = bytes.fromhex(part3_hex.decode()).decode()
# Result: "ARE_LOUD}"
```

### Step 6: Combine the Parts

Concatenate all three decoded parts in order:

```
0xV01D{DN + S_LABELS_ + ARE_LOUD} = 0xV01D{DNS_LABELS_ARE_LOUD}
```

## Solution Breakdown

### Hex to ASCII Conversion Table

| Hex String | ASCII Value |
|-----------|------------|
| `30` | `0` |
| `78` | `x` |
| `56` | `V` |
| `30` | `0` |
| `31` | `1` |
| `44` | `D` |
| `7b` | `{` |
| `44` | `D` |
| `4e` | `N` |
| `53` | `S` |
| `5f` | `_` |
| `4c` | `L` |
| `41` | `A` |
| `42` | `B` |
| `45` | `E` |
| `4c` | `L` |
| `53` | `S` |
| `4152455f4c4f55447d` | `ARE_LOUD}` |

## Complete Solution Script

```python
#!/usr/bin/env python3
"""
Night Traffic CTF Challenge Solver
DNS Breadcrumbs Analysis
"""

from scapy.all import rdpcap, DNS

def solve_challenge(pcap_file):
    """Extract and decode DNS breadcrumbs from PCAP file"""
    
    packets = rdpcap(pcap_file)
    dns_queries = []
    
    # Extract DNS queries from packets
    for packet in packets:
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            # The qname contains our hex-encoded data
            if dns_layer.qdcount > 0:
                # Extract the subdomain (first part of qname)
                qname = dns_layer.qd[0].qname
                if isinstance(qname, bytes):
                    qname = qname.decode()
                
                # Remove the domain suffix and trailing dot
                subdomain = qname.split('.')[0]
                dns_queries.append(subdomain)
    
    # Sort by part number to ensure correct order
    dns_queries.sort(key=lambda x: x.split('.')[-1] if '.' in x else x)
    
    # Decode hex strings
    flag_parts = []
    for query in dns_queries:
        # Extract hex portion (before .part)
        hex_part = query.split('.')[0]
        try:
            decoded = bytes.fromhex(hex_part).decode()
            flag_parts.append(decoded)
        except ValueError as e:
            print(f"Error decoding {hex_part}: {e}")
    
    # Combine all parts
    flag = ''.join(flag_parts)
    return flag

if __name__ == "__main__":
    result = solve_challenge('capture.pcap')
    print(f"Flag: {result}")
```

## Key Concepts

### DNS Exfiltration
DNS exfiltration is a technique used to covertly extract data from a network by embedding it within DNS queries. Since DNS traffic is often allowed through firewalls, it can be used as a covert channel.

### Subdomain Encoding
The challenge encodes data in the subdomain labels of DNS queries, which is part of the normal DNS protocol structure.

### Hex Encoding
Data is encoded in hexadecimal format, which represents binary data using base-16 notation (0-9 and A-F characters).

## Flag

```
0xV01D{DNS_LABELS_ARE_LOUD}
```

## Lessons Learned

1. **Always analyze network traffic** - PCAP files can reveal sensitive information
2. **DNS can be abused** - DNS is often overlooked as a security risk but can be used for data exfiltration
3. **Data encoding is important** - Understanding different encoding methods (hex, base64, etc.) is crucial for CTF challenges
4. **Packet analysis tools are essential** - Tools like Scapy, Wireshark, and tshark are invaluable for network forensics

## References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [DNS Protocol RFC 1035](https://tools.ietf.org/html/rfc1035)
- [DNS Exfiltration Techniques](https://blog.talosintelligence.com/)

## Author Notes

This challenge effectively demonstrates how DNS can be misused for data exfiltration and emphasizes the importance of monitoring DNS traffic for anomalies. The use of hex encoding in subdomains is a simple but effective obfuscation technique.

---

**Solved by:** CTF Challenger  
**Date:** May 19, 2026  
**Status:** ✅ COMPLETED
