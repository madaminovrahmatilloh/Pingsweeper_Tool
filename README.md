# ARP Network Scanner (Fast, Multi-Threaded)

A lightweight Python tool that performs fast ARP-based host discovery on your **local network only**.  
Uses multi-threading for speed and exports results to `scan_results.csv`.

## Requirements

```
Python 3.x
scapy
```

Install dependencies:

```
pip install scapy
```

## Description

```
This tool performs:
- ARP scanning across a subnet
- Multi-threaded IP scanning for higher speed
- Hostname resolution
- CSV exporting of discovered devices

The tool can only scan devices inside the same LAN.
It cannot scan external networks or the internet.
```

## Usage

1. Edit the target subnet:
```
TARGET = "192.168.1.0/24"
```

2. Run the script:
```
python scanner.py
```

3. After the scan, results will appear in:
```
scan_results.csv
```

## Output Format

```
IP, MAC, Hostname
192.168.1.10, aa:bb:cc:dd:ee:ff, device-name
```

## Notes

```
Run as Administrator/root for best performance.
This tool works only on your own local network.
```
