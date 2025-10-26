# mDNS Logger
A lightweight tool to capture and log incoming mDNS (Multicast DNS) packets, designed for network diagnostics and analysis.

## Features
- Captures mDNS packets on port 5353.
- Parses and displays DNS headers, questions, answers, authority, and additional records.
- Supports IPv4 multicast group (224.0.0.251).
- Graceful shutdown with SIGINT handling.

## Requirements
- Linux-based system (no other OS support currently).
- C++17 or later.

## Build Instructions
run build.sh

## Useful Links
- https://datatracker.ietf.org/doc/html/rfc1035
