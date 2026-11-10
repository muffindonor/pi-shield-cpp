# PiThing

A network-wide ad blocker written in C++20, meant to run on a Raspberry Pi 3B.
The goal is to beat DNS sinkholes like Pi-hole in places where they are
structurally weak, while staying small and fast enough for a Pi.

## Status

| Piece | State |
|---|---|
| DNS wire parser / response builder (`src/dns`) | done, tested |
| Domain set: compact sorted suffix-matching set (`src/blocklist/domain_set`) | done, tested |
| List parser: hosts, plain domain lists, Adblock `\|\|domain^` / `@@` (`list_parser`) | done, tested |
| Filter: block + allow rules, CNAME-cloaking check (`filter`) | done, tested |
| UDP/TCP DNS server and DoH/DoT upstream forwarding | not started |
| Config file, logging, systemd unit, web UI | not started |
| Cross-compiling and running on the Pi | not started |

## Build and test

Needs a C++20 compiler and CMake 3.20+. No other dependencies.

```
cmake -S . -B build -G Ninja
cmake --build build
build/pithing_tests
```

Try the rules engine on real lists:

```
build/pithing_check hosts.txt easylist.txt -- ads.example.com www.example.org
```

## How it works

- **`dns/`** parses queries and responses (name compression, with loop and
  bounds protection) and builds "blocked" replies: NXDOMAIN, or `0.0.0.0` /
  `::` for A/AAAA with an empty answer for other types.
- **`DomainSet`** keeps all rules in one sorted buffer with an 8-byte index
  entry each. Lookup walks the query's suffixes (`a.b.example.com`,
  `b.example.com`, `example.com`) with a binary search per suffix, so
  blocking `example.com` blocks every subdomain. 1M rules load in under a
  second on a PC.
- **`Filter`** holds a block set and an allow set. Allow always wins.
  `check_response()` looks at the CNAME chain in an answer, which catches
  trackers hiding behind first-party names (`metrics.shop.com` ->
  `shop.tracker.net`). A plain DNS blocker never sees that.
- **List parser** keeps only what DNS can express. Rules that need a path,
  a wildcard, `$options` or page content are counted as `unsupported` rather
  than guessed at, because applying them to a whole domain would block
  things the list never meant to block.

## Roadmap

1. **Tier A, DNS sinkhole** (next): async UDP/TCP server, forward to an
   upstream resolver (DoH/DoT), apply `Filter` to queries and answers, stats.
2. **Tier B, SNI filtering**: also block by TLS SNI hostname, with no
   decryption, to catch apps that bypass DNS.
3. **Tier C, HTTPS proxy** (optional): decrypt and filter by full URL.
   Needs a CA certificate installed on every device. Weigh that cost first.

## Notes

- MinGW builds link the C++ runtime statically. Without that, an exe run
  from Git Bash can load Git for Windows' older `libstdc++-6.dll` from `PATH`
  and crash.
- Target hardware is a Raspberry Pi 3B (Cortex-A53, 1 GB RAM, 100 Mbit
  Ethernet). It needs a fresh Raspberry Pi OS Lite install, because the
  current card has Windows IoT Core on it.
