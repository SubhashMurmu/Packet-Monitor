# packet_monitor

A lightweight Netfilter kernel module (`NF_INET_PRE_ROUTING`) for IPv4 traffic accounting and IP-based filtering.

## Build and Load

Requires Linux kernel headers.
```bash
make
sudo make load
```

## Usage

Interaction is handled entirely via the `/proc` filesystem.

### 1. Statistics — `/proc/packet_monitor`

Read-only interface exposing packet counts, byte totals, TCP SYN tracking, PPS (packets per second), and the top 10 source IPs.
```bash
cat /proc/packet_monitor
```

> **Note:** Hot-path counters use `atomic_long_t`. The PPS calculator uses `spin_trylock` to guarantee the network stack is never blocked by stat reads.

### 2. Filtering — `/proc/packet_filter`

Write-only control plane for IP rules. Maximum 64 rules.
```bash
# Add/remove rules
echo "block 192.168.1.50" > /proc/packet_filter
echo "allow 10.0.0.5"     > /proc/packet_filter
echo "remove 192.168.1.50" > /proc/packet_filter

# Change mode (default: blacklist)
echo "mode whitelist" > /proc/packet_filter
echo "mode blacklist" > /proc/packet_filter

# Flush all rules
echo "clear" > /proc/packet_filter
```

## Technical Notes

- **SoftIRQ safety:** All shared structures (filter arrays, IP tables) are protected via `spin_lock_bh` to prevent deadlocks when user-space `/proc` reads are interrupted by bottom-half packet processing.

- **Non-linear `sk_buff` handling:** Packet boundaries are validated via `skb_headlen()` before struct casting, preventing kernel page faults when handling hardware-offloaded (GRO/LRO) or fragmented packets.

- **Kernel API:** Uses `in4_pton()` for string-to-IP conversion, maintaining compatibility with modern kernels where `in_aton()` has been removed.
