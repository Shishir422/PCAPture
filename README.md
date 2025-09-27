# PCAPture v2.0 - Enhanced Network Packet Sniffer

**PCAPture** is a security-hardened, enterprise-grade packet sniffer written in **C** using **raw sockets** on Linux. It captures live network traffic and parses Ethernet, IP, TCP, UDP, and ICMP headers with comprehensive security features and robust error handling.

**🔒 Security-First Design** - Built with privilege dropping, buffer overflow protection, and comprehensive input validation to prevent common vulnerabilities found in network analysis tools.

---

## ✨ Enhanced Features

### 🛡️ Security Features
- **Automatic privilege dropping** after socket creation
- **Buffer overflow protection** with comprehensive bounds checking
- **Input validation and sanitization** for all user inputs
- **Secure memory handling** with explicit memory zeroing
- **Signal handling** for graceful shutdown and cleanup
- **Format string vulnerability prevention**
- **Stack protection and ASLR support**

### 📊 Packet Analysis
- **Multi-protocol parsing**: Ethernet, IP, TCP, UDP, ICMP
- **Real-time packet processing** with configurable filtering
- **Detailed packet statistics** and performance metrics
- **Configurable verbosity levels** for debugging
- **Timestamp precision** with nanosecond accuracy
- **Packet size validation** and truncation handling

### ⚙️ Configuration & Management
- **Command-line interface** with GNU-style long options
- **Configuration file support** for persistent settings
- **Flexible packet filtering** with protocol and port matching
- **Configurable capture limits** and interface selection
- **Comprehensive logging** with structured output
- **Installation and distribution** targets

---

## 🛠️ Requirements

### System Requirements
- **Linux** (Ubuntu 18.04+, Debian 9+, CentOS 7+, Fedora 28+)
- **Root privileges** (required for raw socket creation)
- **Kernel version** 3.0+ (for enhanced socket features)

### Development Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential libcap-dev

# CentOS/RHEL/Fedora  
sudo yum install gcc make libcap-devel
# or
sudo dnf install gcc make libcap-devel

# Optional development tools
sudo apt install cppcheck valgrind clang-format flawfinder  # Static analysis
```

---

## 🚀 Quick Start

### Build and Install
```bash
# Clone or download the project
cd PCAPture

# Build the enhanced version
make release

# Install system-wide (optional)
sudo make install

# Or run directly
sudo ./pcapture --help
```

### Basic Usage
```bash
# Capture packets on any interface
sudo ./pcapture

# Capture on specific interface with limit
sudo ./pcapture --interface eth0 --count 100

# Verbose output with TCP filtering
sudo ./pcapture --verbose --filter tcp

# Capture HTTP traffic
sudo ./pcapture --filter "80" --verbose
```

### Configuration File
```bash
# Copy sample configuration
sudo cp pcapture.conf /etc/pcapture.conf

# Edit configuration
sudo nano /etc/pcapture.conf

# Run with configuration
sudo ./pcapture
```

---

## 📋 Command Line Options

```
Usage: pcapture [OPTIONS]

Enhanced Network Packet Sniffer v2.0.0

Options:
  -i, --interface IFACE    Network interface to capture from (default: any)
  -c, --count COUNT        Number of packets to capture (default: unlimited)
  -f, --filter FILTER      Packet filter expression
  -l, --log-file FILE      Log file path (default: /var/log/pcapture.log)
  -v, --verbose            Enable verbose output
  -n, --no-privileges      Don't drop privileges (stay as root)
  -u, --uid UID            User ID to drop privileges to (default: 1000)
  -g, --gid GID            Group ID to drop privileges to (default: 1000)
  -h, --help               Show help message
  -V, --version            Show version information

Examples:
  pcapture                       # Capture on any interface
  pcapture -i eth0 -c 1000       # Capture 1000 packets on eth0
  pcapture -f tcp -v             # Capture TCP packets with verbose output
  pcapture -i wlan0 -f "80"      # Capture HTTP traffic on wlan0
```

---

## 🔧 Build System

The enhanced Makefile provides multiple build targets and security features:

### Build Targets
```bash
make              # Standard build
make debug        # Debug build with sanitizers
make release      # Optimized release build
make install      # Install to /usr/local/bin
make clean        # Clean build artifacts
```

### Development Targets
```bash
make lint         # Static code analysis
make security-check  # Security vulnerability scanning
make memcheck     # Memory leak detection with Valgrind
make format       # Code formatting with clang-format
make help         # Show all available targets
```

### Security Hardening
The build system includes multiple security enhancements:
- **Stack protection** (`-fstack-protector-strong`)
- **Position Independent Executable** (PIE)
- **Format string protection** (`-Wformat-security`)
- **Buffer overflow detection** (`-D_FORTIFY_SOURCE=2`)
- **RELRO and NX bit** protection (`-Wl,-z,relro -Wl,-z,now`)

---

## 🛡️ Security Features Deep Dive

### Privilege Management
- **Automatic privilege dropping** after raw socket creation
- **Configurable target UID/GID** for dropped privileges
- **Verification of privilege drop** success
- **Capability-based permissions** (when available)

### Memory Safety
- **Comprehensive bounds checking** for all buffer operations
- **Safe string operations** with length validation
- **Secure memory zeroing** for sensitive data
- **Buffer overflow prevention** in packet parsing

### Input Validation
- **Command line argument sanitization**
- **Configuration file validation**
- **Packet size validation** before processing
- **Protocol header validation** with size checks

### Error Handling
- **Structured error codes** for different failure modes
- **Detailed logging** with timestamps and context
- **Graceful degradation** on non-fatal errors
- **Resource cleanup** on all exit paths

---

## 📊 Sample Output

### Standard Output
```
[14:25:30.123] TCP 192.168.1.100:45234 -> 93.184.216.34:80 (1514 bytes)
[14:25:30.125] UDP 192.168.1.1:53 -> 192.168.1.100:34567 (89 bytes)  
[14:25:30.127] ICMP 192.168.1.1 -> 8.8.8.8 (98 bytes)
```

### Verbose Output
```
[14:25:30.123] TCP 192.168.1.100:45234 -> 93.184.216.34:80 (1514 bytes)
  ├─ Source IP: 192.168.1.100
  ├─ Dest IP: 93.184.216.34
  ├─ Protocol: 6
  ├─ Source Port: 45234
  └─ Dest Port: 80

=== Capture Statistics ===
Packets captured: 1247
Packets dropped:  3
Bytes captured:   1854362
Elapsed time:     30.5 seconds
Capture rate:     40.89 packets/sec
========================
```

---

## ⚠️ Security Considerations

### Running as Root
PCAPture requires root privileges to create raw sockets. The application:
- **Validates root access** before socket creation
- **Automatically drops privileges** after socket setup
- **Provides clear error messages** for permission issues
- **Supports capability-based permissions** where available

### Network Security
- **Only captures packets** visible to the host
- **No network modification** or packet injection
- **Respects network interface constraints**
- **Provides filtering** to limit captured data

### Data Handling  
- **No persistent packet storage** by default
- **Secure memory cleanup** on exit
- **Configurable logging levels** to control data exposure
- **Input sanitization** for all user-provided data

---

## 🐛 Troubleshooting

### Common Issues

**Permission Denied**
```bash
Error: PCAPture requires root privileges to create raw sockets.
Solution: Run with sudo ./pcapture
```

**Interface Not Found**
```bash
Error: Interface eth0 not found
Solution: Check available interfaces with 'ip link' or use --interface any
```

**Build Errors**
```bash
Error: libcap-dev not found
Solution: Install development dependencies (see Requirements section)
```

### Debug Mode
```bash
# Build with debug symbols and sanitizers
make debug

# Run with verbose logging
sudo ./pcapture --verbose

# Check for memory leaks
make memcheck
```

---

## 🤝 Contributing

### Development Setup
```bash
# Install development dependencies
sudo apt install cppcheck valgrind clang-format

# Run code quality checks
make lint
make security-check
make format
```

### Security Guidelines
- **All buffer operations** must include bounds checking
- **User input** must be validated and sanitized  
- **Memory allocations** must be checked for failure
- **Privilege operations** must be logged and verified
- **Error paths** must properly clean up resources

---

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🙏 Acknowledgments

- Enhanced with comprehensive security features
- Built with modern C security best practices
- Inspired by network analysis tools like Wireshark and tcpdump
- Developed with a focus on education and security research

---

**⚡ PCAPture v2.0** - Secure, Fast, Reliable Network Analysis