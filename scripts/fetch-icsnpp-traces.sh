#!/usr/bin/env bash
# ICSNPP 자체 시험의 트레이스 둘을 받아 samples/icsnpp/ 에 둔다 — IcsnppCrossCheckTest 가
# 같은 트레이스를 Huginn 해독기와 ICSNPP 기준 로그(zeek/src/test/resources/icsnpp/)로 읽어 맞춰 본다.
#
# 트레이스는 커밋하지 않는다. 기준 로그와 달리 캡처 자체의 출처는 저장소 라이선스만으로 확정되지
# 않기 때문이다. 받는 곳은 기준 로그와 같은 고정 커밋이고, 해시는 그 커밋의 파일에서 잰 값이다.
set -euo pipefail

cd "$(dirname "$0")/.."
TARGET="samples/icsnpp"
mkdir -p "$TARGET"

# 이름 · 고정 커밋의 raw URL · SHA-256
TRACES=(
  "snap7.pcap https://raw.githubusercontent.com/cisagov/icsnpp-s7comm/102a35c8f967f20640bd2427bb28a7c609b37493/testing/traces/snap7.pcap 2b91f6a8a203ec83e4f2dbb69d5e61602845f23da0baa31d95d029fb24cbd427"
  "modbus_example.pcap https://raw.githubusercontent.com/cisagov/icsnpp-modbus/6dd3dab173169e454a73925d0426d3c019104852/testing/traces/modbus_example.pcap a84656f9af62b2c948200ec288d51b81f03037c277a31a40efee0cfb244f1e30"
)

for entry in "${TRACES[@]}"; do
  read -r name url sum <<<"$entry"
  target="$TARGET/$name"
  if [ ! -f "$target" ]; then
    echo "받는 중: $url"
    curl -fSL --retry 2 -o "$target.part" "$url"
    mv "$target.part" "$target"
  fi
  echo "$sum  $target" | sha256sum -c -
done

echo
echo "교차 대사:"
echo "  HUGINN_ICSNPP_TRACES=\"\$PWD/$TARGET\" mvn test"
