# ICSNPP test fixtures

These are ICSNPP's own test baseline logs, committed byte-for-byte unchanged:

| File | Source |
|---|---|
| `s7comm-snap7/s7comm.log` | [cisagov/icsnpp-s7comm](https://github.com/cisagov/icsnpp-s7comm) `102a35c8f967f20640bd2427bb28a7c609b37493`, `testing/baseline/analyzer.snap7/s7comm.log` |
| `s7comm-plus/s7comm.log` · `s7comm-plus/s7comm_plus.log` | same repository and commit, `testing/baseline/analyzer.s7comm_plus/` |
| `modbus-basic/modbus_detailed.log` | [cisagov/icsnpp-modbus](https://github.com/cisagov/icsnpp-modbus) `6dd3dab173169e454a73925d0426d3c019104852`, `testing/baseline/analyzer.basic/modbus_detailed.log` |

ICSNPP is BSD-3-Clause (Copyright 2023 Battelle Energy Alliance, LLC); its `LICENSE` and `NOTICE` are kept here as `LICENSE-icsnpp-*.txt` and `NOTICE-icsnpp-*.txt`. `.gitattributes` sets `* -text` so line endings are never converted.

The baselines start with a btest banner line and mask `ts` as `XXXXXXXXXX.XXXXXX`. Tests strip the banner and substitute timestamps in memory only; the files stay as committed. Huginn's production code refuses masked timestamps.

Running Zeek 9.0.1 with the pinned ICSNPP commits on ICSNPP's own traces reproduced these logs exactly except `ts`, `uid` and random link ids (checked 2026-11-01).

The traces themselves (`snap7.pcap`, `modbus_example.pcap`) are not committed: a repository license alone does not establish the provenance of a capture. `scripts/fetch-icsnpp-traces.sh` downloads them from the pinned commits into `samples/icsnpp/` and checks their SHA-256; with `HUGINN_ICSNPP_TRACES` pointing there, `IcsnppCrossCheckTest` reads each trace both ways.
