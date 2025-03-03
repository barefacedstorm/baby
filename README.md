A lightweight deep packet inspection tool for network traffic analysis

## Description

Baby DPI is a lightweight tool for network traffic capture, protocol detection, and basic intrusion prevention system (IPS) capabilities. It helps you capture and analyze network packets from interfaces or PCAP files.

## Installation

### Prerequisites

- Python 3.6 or higher
- Administrative/root privileges (for capturing on network interfaces)
- Scapy library

### Installation Steps

1. Clone the repository:

    ```bash
    git clone https://github.com/barefacedstorm/baby.git
    cd baby
    ```

2. Create and activate a virtual environment (recommended):

    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows: .venv\Scripts\activate
    ```

3. Install the requirements:

    ```
    pip install -r requirements.txt
    ```

4. Install the package in development mode:

    ```
    pip install -e .
    ```


## Basic Usage

The Baby DPI tool provides two main commands:

- capture: For capturing and analyzing network packets
- ips: For running the intrusion prevention system

### Capturing Packets

```csharp
sudo python cli.py capture -i <interface> -c 100
```

This will capture 100 packets from the specified interface.

### Reading from PCAP File

```delphi
sudo python cli.py capture -f path/to/file.pcap
```

## Continuous Capture Mode

Continuous capture mode allows Baby DPI to capture packets indefinitely until manually stopped (with Ctrl+C).

### Starting Continuous Capture

```css
sudo python cli.py capture -i <interface> --continuous
```

### Saving Captured Packets

To save captured packets to PCAP files during continuous capture:

```css
sudo python cli.py capture -i <interface> --continuous -o /path/to/output/directory
```

This will:

1. Create the output directory if it doesn't exist
2. Save captured packets in rotating PCAP files
3. Name the files with timestamps (e.g., capture_20231120-143015.pcap)

### Configuring PCAP File Rotation

You can configure how often new PCAP files are created:

```css
sudo python cli.py capture -i <interface> --continuous -o /path/to/output --buffer-size 2000 --rotation-interval 600
```

This will:

- Save packets in batches of 2000 (buffer-size)
- Create a new file every 10 minutes (600 seconds)

## Examples

### Example 1: Continuous Capture on Wi-Fi Interface

```css
sudo python cli.py capture -i en0 --continuous -o ~/pcaps
```

### Example 2: Verbose Continuous Capture

```css
sudo python cli.py capture -i eth0 --continuous -o /tmp/captures -v
```


The -v flag enables verbose output, showing more details about captured packets.

### Example 3: Continuous Capture with Custom Rotation

```css
sudo python cli.py capture -i wlan0 --continuous -o ./network_data --buffer-size 5000 --rotation-interval 1800
```


This captures packets continuously and:

- Creates a new PCAP file every 30 minutes (1800 seconds)
- Writes to disk after every 5000 packets

### Example 4: Running IPS

```css
sudo python cli.py ips -i eth0
```


This runs the IPS engine on the eth0 interface.

## CLI Options

### Capture Command Options

- -i, --interface: Network interface to capture from (e.g., en0 for Wi-Fi on macOS)
- -f, --file: PCAP file to read packets from instead of live capture
- -c, --count: Number of packets to capture (0 for unlimited, default: 100)
- -v, --verbose: Enable verbose output with detailed packet information
- --continuous: Run in continuous mode until manually stopped with Ctrl+C
- -o, --output-dir: Directory to save captured packets as PCAP files
- --buffer-size: Number of packets to buffer before writing to disk (default: 1000)
- --rotation-interval: Time in seconds before rotating to a new PCAP file (default: 300)

### IPS Command Options

- -i, --interface: Network interface to monitor (required)
- -r, --rules: Path to custom rules file (currently only built-in rules are supported)
- -c, --count: Number of packets to analyze (0 for infinite, default: 0)
- -v, --verbose: Enable verbose output with detailed alert information
- -o, --output-dir: Directory to save captured suspicious packets as PCAP files
- --continuous: Run in continuous mode until manually stopped with Ctrl+C

## Troubleshooting

### Permission Issues

If you encounter permission errors:

```css
sudo PYTHONPATH=/path/to/baby python cli.py capture -i <interface> --continuous
```

### Interface Not Found

To list available interfaces:

```scss
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

### Large PCAP Files

If you're generating very large files during continuous capture:

- Decrease the --rotation-interval value
- Monitor disk space usage
- Use external tools like logrotate to manage older capture files

## Advanced Usage

### Capturing to a Named Pipe

For real-time analysis with other tools:

```bash
mkfifo /tmp/capture_pipe
sudo python cli.py capture -i eth0 --continuous -o /tmp/capture_pipe &
wireshark -k -i /tmp/capture_pipe
```

### Automatic Protocol Detection

Baby DPI automatically detects these protocols:

- HTTP
- DNS
- SSH
- TLS/HTTPS

## Notes

- The tool requires root/administrative privileges to capture packets on network interfaces
- For best performance, adjust buffer-size and rotation-interval based on your network traffic volume
- Use the verbose (-v) flag for debugging but be aware it may slow down processing slightly