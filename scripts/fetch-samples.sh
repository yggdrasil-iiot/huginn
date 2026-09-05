#!/usr/bin/env bash
# 공개 ICS 캡처를 내려받아 samples/ 에 둔다 — 설계 §10 의 반증 조건을 실제로 시험하기 위한 것이다.
#
# 캡처 자체는 저장소에 넣지 않는다(라이선스가 제각각). 재현 가능한 부분은
# 이 스크립트와 캡처별 정책 파일이다.
set -euo pipefail

cd "$(dirname "$0")/.."
SAMPLES="samples"
mkdir -p "$SAMPLES"

# 출처. URL 은 배포처가 바꿀 수 있으므로 실패하면 조용히 넘기지 않고 멈춘다.
#   4SICS ICS Lab (Netresec 배포) — https://www.netresec.com/?page=PCAP4SICS
SOURCES=(
  "https://www.netresec.com/files/4SICS-GeekLounge-151020.pcap"
  "https://www.netresec.com/files/4SICS-GeekLounge-151021.pcap"
  "https://www.netresec.com/files/4SICS-GeekLounge-151022.pcap"
)

# editcap 은 이 프로젝트의 유일한 외부 도구다. PcapReader 는 pcapng 를 거부하므로
# 받은 파일이 pcapng 이면 pcap 으로 정규화해야 한다. 없으면 조용히 건너뛰지 않고 멈춘다 —
# 건너뛰면 캡처가 없는데도 성공한 것처럼 보인다.
if ! command -v editcap >/dev/null 2>&1; then
  echo "editcap 이 PATH 에 없다. Wireshark 를 설치하고 다시 실행한다." >&2
  echo "  Windows: winget install WiresharkFoundation.Wireshark" >&2
  echo "  Debian/Ubuntu: sudo apt install wireshark-common" >&2
  echo "  macOS: brew install wireshark" >&2
  exit 2
fi

for url in "${SOURCES[@]}"; do
  name="$(basename "$url")"
  target="$SAMPLES/$name"
  if [ -f "$target" ]; then
    echo "이미 있음: $target"
    continue
  fi
  echo "받는 중: $url"
  curl -fSL --retry 2 -o "$target.part" "$url"
  mv "$target.part" "$target"

  # pcapng 매직(0x0A0D0D0A)이면 pcap 으로 정규화한다.
  magic="$(head -c 4 "$target" | od -An -tx1 | tr -d ' \n')"
  if [ "$magic" = "0a0d0d0a" ]; then
    echo "pcapng 를 pcap 으로 정규화: $name"
    editcap -F pcap "$target" "$target.converted"
    mv "$target.converted" "$target"
  fi
done

# 해시 검증. SHA256SUMS 가 있으면 대조하고, 없으면 관측값을 적어두되 검증했다고 말하지 않는다 —
# 손에 없는 해시를 스크립트에 박아 넣으면 검증이 아니라 검증하는 척이 된다.
SUMS="$SAMPLES/SHA256SUMS"
if [ -f "$SUMS" ]; then
  echo "해시 검증 중..."
  (cd "$SAMPLES" && sha256sum -c "$(basename "$SUMS")")
else
  echo "SHA256SUMS 가 없다 — 이번 내려받기의 해시를 기록한다(검증이 아니라 최초 기록이다)."
  (cd "$SAMPLES" && sha256sum ./*.pcap > "$(basename "$SUMS")")
  echo "출처를 직접 확인한 뒤 $SUMS 를 커밋한다. 다음 실행부터 이 파일로 검증한다."
fi

echo
echo "다음 단계:"
echo "  mvn -DskipTests package"
echo "  java -jar cli/target/huginn.jar $SAMPLES/<capture>.pcap $SAMPLES/<capture>-policy.yaml"
