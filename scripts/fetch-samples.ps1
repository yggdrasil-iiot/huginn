# 공개 ICS 캡처를 내려받아 samples/ 에 둔다 — 설계 §10 의 반증 조건을 실제로 시험하기 위한 것이다.
# 주 개발 환경이 Windows 이므로 .sh 와 같은 일을 하는 판을 함께 둔다.
$ErrorActionPreference = 'Stop'

Set-Location (Join-Path $PSScriptRoot '..')
$samples = 'samples'
New-Item -ItemType Directory -Force -Path $samples | Out-Null

# 출처 — 4SICS ICS Lab (Netresec 배포): https://www.netresec.com/?page=PCAP4SICS
$sources = @(
    'https://www.netresec.com/files/4SICS-GeekLounge-151020.pcap',
    'https://www.netresec.com/files/4SICS-GeekLounge-151021.pcap',
    'https://www.netresec.com/files/4SICS-GeekLounge-151022.pcap'
)

# editcap 이 없으면 멈춘다 — 조용히 건너뛰면 캡처가 없는데도 성공한 것처럼 보인다.
$editcap = Get-Command editcap -ErrorAction SilentlyContinue
if (-not $editcap) {
    Write-Error @'
editcap 이 PATH 에 없다. Wireshark 를 설치하고 다시 실행한다.
  winget install WiresharkFoundation.Wireshark
설치 후 PATH 에 C:\Program Files\Wireshark 가 들어갔는지 확인한다.
'@
    exit 2
}

foreach ($url in $sources) {
    $name = Split-Path $url -Leaf
    $target = Join-Path $samples $name
    if (Test-Path $target) {
        Write-Host "이미 있음: $target"
        continue
    }
    Write-Host "받는 중: $url"
    Invoke-WebRequest -Uri $url -OutFile "$target.part"
    Move-Item "$target.part" $target

    # pcapng 매직(0x0A0D0D0A)이면 pcap 으로 정규화한다 — PcapReader 는 pcapng 를 거부한다.
    $magic = [System.IO.File]::ReadAllBytes($target)[0..3]
    if ($magic[0] -eq 0x0A -and $magic[1] -eq 0x0D -and $magic[2] -eq 0x0D -and $magic[3] -eq 0x0A) {
        Write-Host "pcapng 를 pcap 으로 정규화: $name"
        & editcap -F pcap $target "$target.converted"
        Move-Item -Force "$target.converted" $target
    }
}

# 해시. SHA256SUMS 가 있으면 대조하고, 없으면 관측값을 기록하되 검증했다고 말하지 않는다.
$sums = Join-Path $samples 'SHA256SUMS'
if (Test-Path $sums) {
    Write-Host '해시 검증 중...'
    $expected = @{}
    foreach ($line in Get-Content $sums) {
        if ($line -match '^([0-9a-fA-F]{64})\s+\*?\.?[\\/]?(.+)$') {
            $expected[$Matches[2].Trim()] = $Matches[1].ToLower()
        }
    }
    foreach ($file in Get-ChildItem (Join-Path $samples '*.pcap')) {
        $actual = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLower()
        if (-not $expected.ContainsKey($file.Name)) {
            Write-Error "SHA256SUMS 에 없는 파일: $($file.Name)"; exit 1
        }
        if ($expected[$file.Name] -ne $actual) {
            Write-Error "해시 불일치: $($file.Name)"; exit 1
        }
        Write-Host "  OK  $($file.Name)"
    }
} else {
    Write-Host 'SHA256SUMS 가 없다 — 이번 내려받기의 해시를 기록한다(검증이 아니라 최초 기록이다).'
    Get-ChildItem (Join-Path $samples '*.pcap') | ForEach-Object {
        '{0}  ./{1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
    } | Set-Content -Encoding utf8 $sums
    Write-Host "출처를 직접 확인한 뒤 $sums 를 커밋한다. 다음 실행부터 이 파일로 검증한다."
}

Write-Host ''
Write-Host '다음 단계:'
Write-Host '  mvn -DskipTests package'
Write-Host "  java -Dstdout.encoding=UTF-8 -jar cli/target/huginn.jar $samples/<capture>.pcap $samples/<capture>-policy.yaml"
