# Zeek + ICSNPP S7comm·Modbus. Huginn 의 --zeek-log 입력을 손에 있는 pcap 으로 만들어 보기 위한 것이다.
# 버전은 Huginn 이 맞춰 짠 그대로 고정한다(zeek/src/main/java/.../ZeekSchema.java).
FROM zeek/zeek:9.0.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake g++ make git libpcap-dev libssl-dev zlib1g-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN zkg autoconfig --force \
 && zkg install --force --skiptests https://github.com/cisagov/icsnpp-s7comm --version 102a35c8f967f20640bd2427bb28a7c609b37493 \
 && zkg install --force --skiptests https://github.com/cisagov/icsnpp-modbus --version 6dd3dab173169e454a73925d0426d3c019104852
