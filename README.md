
# Python-Based Traceroute Application

This project provides a traceroute tool to trace the path to a specific target over a network. It uses Python's socket library to send ICMP packets and trace the network route hop-by-hop.

## Features

- **ICMP Packets:** Uses ICMP packets to trace network paths.
- **Maximum Hop Count:** User-adjustable maximum hop count (default: 30).
- **Timeout Duration:** Adjustable timeout duration for each hop (default: 2 seconds).
- **Easy Usage:** Provides quick and straightforward command-line usage.

## Installation

Ensure Python 3.x is installed. To run the project, follow these steps:

```bash
git clone https://github.com/erendrcnn/traceroute-app
cd traceroute
python traceroute.py <target_address>
```

## Usage

To start the traceroute tool:

```bash
sudo python traceroute.py google.com
```

## Parameters

- **ZAMAN_ASIMI:** Timeout duration for each hop (default: 2 seconds).
- **MAX_ADIM:** Maximum allowed hop count (default: 30).

## Contributing

We welcome contributions. Please submit a pull request or open an issue.

## License

This project is licensed under the MIT License.
