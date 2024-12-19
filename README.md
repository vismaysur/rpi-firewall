# Network Security Monitor

A real-time network packet analyzer with DoS detection capabilities and configurable filtering rules.

## Team Contributions

### Philip

- RPI positioning
- Traffic sniffing code
- Logging

### Vismay

- User rules + packet filtering
- DOS detection

## Installation & Setup

1. Install dependencies:

```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev clang make

# macOS
brew install libpcap
```

2. Build the project:

```bash
make
make install  # Optional, requires root
```

## Usage

1. Basic usage:

```bash
sudo ./bin/sniffer
```

2. With custom rules file:

```bash
sudo ./bin/sniffer rules/custom.rules
```

## Acknowledgments

Based on libpcap and inspired by open-source network monitoring tools.
