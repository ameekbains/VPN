# VPN
A secure VPN implementation featuring modern cryptography and Linux networking capabilities. Designed for educational purposes while implementing production-grade security patterns.
## Features
- **Modern Cryptography**
  - X25519 key exchange
  - AES-256-GCM authenticated encryption
  - Perfect Forward Secrecy
  - Replay attack protection
- **Networking**
  - TUN interface management
  - Full traffic routing
  - DNS leak prevention
  - NAT traversal
  - Multi-client support
- **Security**
  - Ephemeral session keys
  - Kernel-bypass packet processing
  - Defense-in-depth design
  - Secure protocol negotiation

## Prerequisites
### Hardware/OS
- Linux kernel ≥ 5.4
- x86_64 or ARM64 architecture
- TUN/TAP device support

### Software
- Python 3.9+
- cryptography ≥ 3.4
- iptables
- iproute2
- resolvconf

### Permissions
- Root access for interface configuration
- CAP_NET_ADMIN capabilities
