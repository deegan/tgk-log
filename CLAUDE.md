# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

tgk-log is a network packet logging daemon written in C. Originally designed for Linux 2.2.x kernels, it has been modernized to work with current Linux kernels using the AF_PACKET API. It captures and logs TCP, UDP, and ICMP traffic on a specified network interface, designed particularly for IP masquerading (NAT) gateways.

Version: 2.5 (modernized)

## Build System

### Building
```bash
make
```

Compiles `tgk-log.c` into the `tgk-log` executable with `-Wall -O2` flags.

### Cleaning
```bash
make clean
```

Removes object files and the binary.

### libc5 Support
To compile under libc5 (instead of glibc2), uncomment `-DLIBC5` in the `CFLAGS` line of the Makefile. This switches to Linux kernel headers (`linux/ip.h`, `linux/tcp.h`, etc.) instead of standard netinet headers.

## Configuration

### Config File Location
`/etc/tgk-log.conf` (hardcoded in `tgk-log.c:178`)

### Configuration Script
```bash
./make-conf.sh
```

Interactive shell script that generates `/etc/tgk-log.conf` by prompting for:
- DNS resolution (on/off)
- Protocol logging toggles (TCP/UDP/ICMP)
- Log file paths for each protocol
- Network device (e.g., eth0, eth1)
- Promiscuous mode
- Logging scope (all traffic vs. filtered)
- For filtered mode: intranet address, network class (8/16/24), traffic direction rules

### Example Config
See `tgk-log.conf` for a sample configuration with all protocols enabled, promiscuous mode on, and logging all traffic on eth0.

## Architecture

### Core Components

**Main Loop** (`main()` at line 540)
- Forks into daemon process
- Sets up signal handlers (SIGINT/TERM/KILL/QUIT → cleanup, SIGHUP → reread config)
- Enters infinite loop reading raw ethernet packets from socket

**Packet Processing Pipeline**
1. `check_paket()` (line 523) - Examines IP protocol field and dispatches to TCP/UDP/ICMP handlers
2. `check_rules()` (line 389) - Applies filtering rules based on source/dest IPs, intranet settings, and `log_all` flag
3. `write_node()` (line 417) - Formats and writes log entries to appropriate file

**Configuration Parser** (`read_config()` at line 173)
- Parses `/etc/tgk-log.conf` line by line
- Validates all options and exits with error messages if invalid
- Opens log files in append mode
- Calls `setup_interface()` to configure network device

**Interface Setup** (`setup_interface()` at line 126)
- Creates `AF_INET`/`SOCK_PACKET`/`ETH_P_ALL` raw socket for packet capture
- Optionally enables promiscuous mode via `SIOCSIFFLAGS` ioctl
- Retrieves and stores NIC's hardware (MAC) address and IP address

### Data Structures

**`struct etherpacket`** (line 54)
- Combines ethernet header, IP header, and buffer for upper-layer data
- Global instance `ep` used throughout

**Packet Headers**
- `ip`, `tcp`, `udp`, `icmp` are global pointers offset into `ep` structure
- Pointers initialized in `main()` with manual offset calculations (lines 542-545)

### Logging Behavior

**TCP**: Only logs SYN packets (connection initiation) when `log-tcp on`

**UDP**: Logs all UDP packets when `log-udp on`

**ICMP**: Logs all ICMP packets with type-specific formatting (DEST_UNREACH, REDIRECT, TIME_EXCEEDED get additional code information)

**Filtering Logic** (when `log_all no`):
- `log_intranet`: Controls logging of traffic where both source and dest are within intranet
- `log_intraffic`: Controls logging of traffic from outside to inside intranet
- Network class (8/16/24) determines subnet mask for IP prefix matching
- Filters out packets originating from the NIC itself (compares source IP and MAC)

### Signal Handling

**SIGHUP**: Closes all files/sockets, disables promiscuous mode, re-reads config (`reread()` at line 488)

**SIGINT/SIGTERM/SIGKILL/SIGQUIT**: Cleanup and exit (`cleanup()` at line 453)
- Closes socket and log files
- Disables promiscuous mode if enabled
- Exits with status 1

## Important Notes

### Kernel Compatibility
The code has been modernized from the original Linux 2.2.x implementation to use the AF_PACKET socket API, making it compatible with modern Linux kernels. Key modernization changes:
- Replaced deprecated `SOCK_PACKET` with `AF_PACKET`/`SOCK_RAW`
- Added proper socket binding using `sockaddr_ll` structure
- Updated interface index retrieval with `SIOCGIFINDEX` ioctl
- Added required headers: `<stdlib.h>`, `<time.h>`, `<unistd.h>`, `<linux/if_packet.h>`

### Raw Socket Permissions
The binary requires root privileges (CAP_NET_RAW capability) to:
- Create AF_PACKET raw sockets
- Configure network interfaces
- Enable promiscuous mode

### Hardcoded Limits
See `defines.h` for buffer sizes:
- `BUFFER_SIZE`: 2000 bytes for packet data
- `PATH_SIZE`: 256 chars for log file paths
- `HOST_SIZE`: 256 chars for resolved hostnames
- `DEVICE_SIZE`: 6 chars for device name (e.g., "eth0")

### Running the Daemon
```bash
# Must run as root
sudo ./tgk-log
```

The daemon forks into the background and logs will be written to the paths specified in `/etc/tgk-log.conf`.
