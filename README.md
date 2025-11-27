# Slice-XDP Firewall

A lightweight, high-performance XDP-based firewall with per-IP and per-flow rate limiting, port filtering, whitelist/blacklist support, alerting capabilities, and a live statistics dashboard.

## Features

- **Per-IP Rate Limiting**: Track and limit traffic from individual source IPs
  - Total packets per second (PPS)
  - SYN packets per second
  - UDP packets per second
  - UDP bytes per second (BPS)
  - Total bytes per second

- **Per-Flow Rate Limiting**: Track and limit traffic for individual flows (5-tuple: src IP, dst IP, protocol, src port, dst port)
  - All the same metrics as per-IP limiting
  - Fine-grained control over specific connections

- **Port Filtering**: Protect specific ports while allowing all other traffic
  - Single port: `80`
  - Multiple ports: `80,443,25565`
  - Port range: `1000-5000`

- **Whitelist/Blacklist**: IP-based access control
  - Support for IPv4 addresses and CIDR notation
  - Whitelisted IPs bypass all rate limits
  - Blacklisted IPs are instantly dropped

- **Alerting**: Multiple alerting options
  - Log to file
  - Discord webhook notifications
  - Per-limit-type alert configuration

- **Live Statistics**: Real-time dashboard showing:
  - Packets passed/dropped
  - Current PPS and BPS
  - Per-limit hit counters
  - Whitelist/blacklist hits
  - Active map sizes
  - Refreshes every second

## Requirements

- Linux kernel 4.18+ (5.10+ recommended)
- Root privileges (for loading XDP programs)

**Dependencies** (automatically installed by `install.sh`):
- `clang` and LLVM
- Go 1.21+
- `libbpf-dev` / `libbpf-devel`
- Kernel headers for your running kernel

## Installation

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/xdp-firewall.git
cd xdp-firewall

# Run the installer (handles everything automatically)
sudo ./install.sh
```

**That's it!** The installer will:
- Detect your Linux distribution
- Install all required dependencies
- Build the XDP program and Go loader
- Install to system paths
- Optionally set up systemd service

### What Gets Installed

- Binary: `/usr/local/bin/slice-xdp`
- XDP object: `/usr/local/lib/slice-xdp/xdp_firewall.o`
- Config: `/etc/slice-xdp/config.toml`
- Whitelist: `/etc/slice-xdp/whitelist.txt`
- Blacklist: `/etc/slice-xdp/blacklist.txt`
- Log directory: `/var/log/slice-xdp/`

### Manual Build (Optional)

If you want to build without installing:

```bash
make        # Build everything
./start -i eth0 -d generic -t 10  # Test locally
```

## Configuration

The firewall is configured via `config.toml` (TOML format).

### Basic Configuration

```toml
[general]
interface = "eth0"          # Network interface to protect
xdp_mode = "native"         # XDP mode: native or generic
timeout = 0                 # Auto-detach timeout (0 = run indefinitely)

[ports]
ports_to_protect = "80,443" # Ports to filter (single, multiple, or range)

[per_ip_limits]
per_ip_pps_limit = 10000          # Total packets per second
per_ip_syn_pps_limit = 100        # SYN packets per second
per_ip_udp_pps_limit = 5000       # UDP packets per second
per_ip_udp_bps_limit = 10485760   # UDP bytes per second (10 MB/s)
per_ip_bps_limit = 52428800       # Total bytes per second (50 MB/s)
action = "drop"                   # Action: pass or drop

[per_flow_limits]
per_flow_pps_limit = 5000         # Total packets per second
per_flow_syn_pps_limit = 50       # SYN packets per second
per_flow_udp_pps_limit = 2500     # UDP packets per second
per_flow_udp_bps_limit = 5242880  # UDP bytes per second (5 MB/s)
per_flow_bps_limit = 10485760     # Total bytes per second (10 MB/s)
action = "drop"                   # Action: pass or drop

[whitelist]
preload_whitelist_file = "./whitelist.txt"

[blacklist]
preload_blacklist_file = "./blacklist.txt"

[alerting]
alert = "log"                                      # Options: none, log, webhook+log
log_file = "/var/log/slice-xdp/slice-xdp.log"
webhook_url = ""                                   # Discord webhook URL

[alerting.enable]
per_ip_pps = true
per_ip_syn_pps = true
per_ip_udp_pps = true
per_ip_udp_bps = true
per_ip_bps = true
per_flow_pps = true
per_flow_syn_pps = true
per_flow_udp_pps = true
per_flow_udp_bps = true
per_flow_bps = true
other = true
```

### Port Configuration Examples

```toml
# Single port
ports_to_protect = "80"

# Multiple ports
ports_to_protect = "80,443,25565"

# Port range
ports_to_protect = "1000-5000"
```

### Action Configuration

- **`pass`**: Allow traffic, but don't increment counters past the limit
- **`drop`**: Drop only the packets/bytes exceeding the limit (rate limiting)

### Whitelist/Blacklist Format

Both files support IPv4 addresses and CIDR notation, one entry per line:

```
# whitelist.txt or blacklist.txt
192.168.1.0/24
10.0.0.1
172.16.0.0/16
8.8.8.8
```

## Usage

### Running Locally

```bash
# Build first
make

# Run with default config
sudo ./start -i eth0 -d native

# Run with timeout
sudo ./start -t 60 -i eth0 -d native

# Run with custom config
sudo ./start -c /path/to/config.toml -i eth0 -d native
```

### Command-Line Options

```
-t <seconds>    Timeout in seconds (0 = run indefinitely)
-i <interface>  Network interface (e.g., eth0)
-d <mode>       XDP mode: native (best performance) or generic (fallback)
-c <path>       Config file path (default: config.toml)
```

### XDP Modes

- **native**: Attaches XDP to the NIC driver (best performance, requires driver support)
- **generic**: Fallback mode that works with any driver (lower performance)

To check if your NIC supports native XDP:
```bash
ethtool -i eth0 | grep driver
# Then search online: "<driver_name> xdp support"
```

### Running as a System Service

Create `/etc/systemd/system/slice-xdp.service`:

```ini
[Unit]
Description=Slice-XDP Firewall
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/slice-xdp -i eth0 -d native -c /etc/slice-xdp/config.toml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable slice-xdp
sudo systemctl start slice-xdp
sudo systemctl status slice-xdp
```

## Live Statistics Dashboard

When running, the firewall displays a live dashboard that refreshes every second:

```
=== Slice-XDP Firewall Stats ===

Traffic:
  Packets Passed:  1,234,567
  Packets Dropped: 123
  Current PPS:     45,678
  Current BPS:     123.4 MB

Per-IP Limit Hits:
  PPS:     12
  SYN PPS: 5
  UDP PPS: 8
  UDP BPS: 3
  BPS:     2

Per-Flow Limit Hits:
  PPS:     7
  SYN PPS: 4
  UDP PPS: 3
  UDP BPS: 1
  BPS:     2

List Hits:
  Whitelist: 456
  Blacklist: 78

Map Sizes:
  IP Map:   234 entries
  Flow Map: 567 entries
```

## Performance

XDP operates at the earliest possible point in the network stack, providing:
- **Line-rate performance**: Process packets at NIC speed
- **Low CPU usage**: Minimal overhead compared to traditional firewalls
- **Scalability**: Handle millions of packets per second

### Benchmarks

Performance varies based on hardware, but typical results on modern hardware:
- Native mode: 10+ Gbps throughput with <5% CPU usage
- Generic mode: 2-5 Gbps throughput with ~15% CPU usage

## Handling File Uploads

If your server handles file uploads, see the [File Upload Guide](FILE_UPLOAD_GUIDE.md) for detailed configuration instructions. Quick tips:

- **Set high BPS limits**: `per_ip_bps_limit = 209715200` (200 MB/s) for large file uploads
- **Whitelist authenticated users**: Add trusted IPs to `whitelist.txt`
- **Focus on PPS, not BPS**: Protect against packet floods, be generous with bandwidth
- **Monitor first**: Use `action = "pass"` to test before enforcing

See `examples/file-upload-server.toml` for a complete configuration example.

## Troubleshooting

### XDP program fails to load

1. Check kernel version:
```bash
uname -r  # Should be 4.18+
```

2. Verify kernel has XDP support:
```bash
grep -i xdp /boot/config-$(uname -r)
```

3. Try generic mode if native fails:
```bash
sudo ./start -i eth0 -d generic
```

### Permission denied

XDP requires root privileges:
```bash
sudo ./start -i eth0 -d native
```

### Interface not found

List available interfaces:
```bash
ip link show
```

### Build errors

Ensure all dependencies are installed:
```bash
# Check clang
clang --version

# Check Go
go version

# Install missing headers
sudo apt install linux-headers-$(uname -r) libbpf-dev
```

## Architecture

### Components

1. **XDP Program (`xdp_firewall.c`)**: Kernel-space eBPF program that filters packets
2. **Go Loader (`main.go`)**: User-space application that loads the XDP program and manages configuration
3. **Maps**: Shared memory between kernel and user space for configuration, statistics, and state

### Data Flow

```
Network Packet → NIC → XDP Hook → Firewall Logic → Pass/Drop Decision
                                         ↓
                                   Update Stats
                                         ↓
                              User Space (Live Display)
```

### Maps

- **config_map**: Stores rate limit configuration
- **ip_map**: Tracks per-IP statistics
- **flow_map**: Tracks per-flow statistics
- **whitelist_map**: Stores whitelisted IPs/CIDRs
- **blacklist_map**: Stores blacklisted IPs/CIDRs
- **ports_map**: Stores protected ports
- **stats_map**: Global statistics counters

## Security Considerations

- **Root required**: XDP programs require root privileges to load
- **Rate limiting only**: This is not a full IDS/IPS, just a rate limiter
- **Whitelist carefully**: Whitelisted IPs bypass all checks
- **Monitor logs**: Regular log review is recommended
- **Update regularly**: Keep kernel and dependencies up to date

## License

GPL-2.0 (required for eBPF programs)

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For issues, questions, or feature requests, please open an issue on GitHub.

## Acknowledgments

Built with:
- [cilium/ebpf](https://github.com/cilium/ebpf) - eBPF library for Go
- [BurntSushi/toml](https://github.com/BurntSushi/toml) - TOML parser for Go
- [fatih/color](https://github.com/fatih/color) - Colored terminal output

## References

- [XDP Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [eBPF Documentation](https://ebpf.io/)
- [Linux XDP Project](https://github.com/xdp-project/xdp-tutorial)

