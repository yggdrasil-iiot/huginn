#!/usr/bin/env bash
# pcap 을 Zeek + ICSNPP 로 돌려 Huginn 이 읽는 로그를 만든다. Docker 가 필요하다.
#
#   bash scripts/zeek-logs.sh samples/4SICS-GeekLounge-151022.pcap
#   → samples/zeek/4SICS-GeekLounge-151022/{s7comm,s7comm_plus,modbus_detailed}.log (있는 것만)
#
# 4SICS 캡처에서 만든 로그도 캡처와 같은 이유로 커밋하지 않는다(samples/.gitignore).
set -euo pipefail

if [ $# -ne 1 ] || [ ! -f "$1" ]; then
  echo "사용법: bash scripts/zeek-logs.sh <capture.pcap>" >&2
  exit 2
fi

cd "$(dirname "$0")/.."
IMAGE="huginn-zeek-icsnpp:9.0.1"
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker build -t "$IMAGE" scripts/zeek

capture="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
name="$(basename "$1" .pcap)"
out="$PWD/samples/zeek/$name"
mkdir -p "$out"

# 'packages' 를 빼면 ICSNPP 가 실리지 않아 s7comm.log 가 생기지 않는다.
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$(dirname "$capture"):/in:ro" -v "$out:/out" -w /out \
  "$IMAGE" zeek -C -r "/in/$(basename "$capture")" local packages

echo "만든 로그:"
ls "$out" | grep -E '^(s7comm|s7comm_plus|modbus_detailed)\.log$' | sed "s|^|  $out/|"
