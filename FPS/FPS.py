import os  # 운영 체제와 상호작용하여 파일 경로를 설정하는 데 사용
import time  # 스캔 시작 및 종료 시간을 기록하고 경과 시간을 계산하는 데 사용
from scapy.all import IP, TCP, sr  # 네트워크 패킷을 만들고 전송하는 데 필요한 Scapy의 모듈들
import argparse  # 명령줄 인자를 쉽게 처리할 수 있도록 돕는 라이브러리

# Nmap 서비스 매핑 로드 함수: nmap-services 파일에서 포트 번호와 서비스 이름 매핑 정보를 읽어오는 함수
def load_nmap_services(filename):
    service_map = {}  # 서비스 정보를 저장할 빈 딕셔너리 생성
    # 파일 열기
    with open(filename, "r") as file:
        # 파일의 각 줄을 읽습니다
        for line in file:
            # 각 줄이 주석('#')으로 시작하는 경우, 해당 줄은 무시하고 넘어갑니다.
            if not line.startswith("#"):
                parts = line.split()  # 각 줄의 정보를 공백으로 분리
                # 분리한 정보에서 포트와 서비스 이름을 가져옵니다
                if len(parts) >= 2:  # 최소한 2개의 요소가 있을 때만 처리
                    service = parts[0]  # 서비스 이름
                    port, proto = parts[1].split("/")  # 포트 번호와 프로토콜(tcp/udp)을 분리
                    # 딕셔너리에 포트 번호와 프로토콜을 키로, 서비스 이름을 값으로 저장
                    service_map[(int(port), proto)] = service
    return service_map  # 서비스 매핑 딕셔너리를 반환

# 서비스 매핑 파일 경로 설정 및 로드
# 현재 스크립트가 위치한 폴더에 있는 nmap-services 파일 경로를 설정합니다.
# 만약 해당 파일이 존재한다면, 로드하여 서비스 매핑 정보를 가져옵니다.
service_file_path = os.path.join(os.path.dirname(__file__), "nmap-services")
nmap_service_map = load_nmap_services(service_file_path) if os.path.exists(service_file_path) else {}

# 포트 범위 해석 함수: 입력받은 포트 문자열을 숫자 범위 또는 리스트로 변환
def parse_ports(port_str):
    # 포트가 범위(예: "1-1000") 형식일 경우
    if "-" in port_str:
        # 시작 포트와 끝 포트를 분리하여 숫자로 변환
        start, end = map(int, port_str.split("-"))
        return range(start, end + 1)  # 범위를 반환 (1부터 1000까지)
    # 포트가 단일 숫자들로 나열된 경우 (예: "80,443")
    return [int(p) for p in port_str.split(",")]  # 각 포트를 리스트에 담아 반환

# 일괄 포트 스캔 함수: 여러 포트를 동시에 스캔하여 빠르게 상태를 확인
def batch_scan(ip, ports):
    open_ports_info = []  # 열린 포트 정보를 저장할 리스트
    closed, filtered = 0, 0  # 닫힌 포트와 필터링된 포트의 개수를 초기화
    
    # 스캔할 패킷을 한 번에 생성하여 리스트에 저장합니다.
    # IP와 TCP 패킷을 결합하여 지정된 각 포트에 대해 SYN 패킷을 생성합니다.
    packets = [IP(dst=ip) / TCP(dport=port, flags="S") for port in ports]
    # sr 함수로 일괄 전송을 실행하여 응답을 수집합니다.
    # timeout은 0.5초로 설정하여 빠르게 응답을 처리합니다.
    answered, unanswered = sr(packets, timeout=0.5, verbose=0)

    # 응답이 있는 패킷을 분석하여 열린 포트와 닫힌 포트를 구분합니다.
    for snd, rcv in answered:
        port = snd.dport  # 전송된 패킷의 목적지 포트 번호
        # 응답이 SYN-ACK 패킷(SYN 요청에 대한 승낙)일 경우 해당 포트를 'open'으로 간주
        if rcv.haslayer(TCP) and rcv.getlayer(TCP).flags == 0x12:
            service = nmap_service_map.get((port, "tcp"), "unknown")  # 서비스 이름 가져오기
            ttl = rcv.ttl  # 응답 패킷의 TTL(Time to Live) 값을 가져옵니다.
            # 열린 포트 정보를 딕셔너리로 저장하여 리스트에 추가
            open_ports_info.append({"port": port, "state": "open", "service": service, "ttl": ttl})
        else:
            closed += 1  # SYN-ACK가 아닌 다른 응답은 닫힌 포트로 간주하여 개수 증가

    # 응답이 없는 패킷(필터링된 포트)은 unanswered에 저장되어 있으므로, 필터링된 포트 수로 처리
    filtered = len(unanswered)
    
    return open_ports_info, closed, filtered  # 열린 포트 정보와 닫힌/필터링된 포트 수 반환

# 메인 함수: 프로그램의 진입점
if __name__ == "__main__":
    # 명령줄 인자 파서 설정
    parser = argparse.ArgumentParser(description="Optimized Batch Python Port Scanner")
    parser.add_argument("ip", help="IP address to scan")  # 스캔할 IP 주소
    parser.add_argument("-p", "--ports", type=str, default="1-1000", help="List of ports or range (default: 1-1000)")
    args = parser.parse_args()  # 인자 파싱

    # 포트 목록을 파싱하여 숫자형 리스트로 변환
    ports = parse_ports(args.ports)
    
    # 스캔 시작 시간 기록
    start_time = time.time()
    print(f"Starting scan on {args.ip} at {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # 일괄 포트 스캔을 수행하여 열린 포트, 닫힌 포트, 필터링된 포트를 확인
    open_ports_info, closed_ports, filtered_ports = batch_scan(args.ip, ports)

    # 스캔 종료 시간 기록 및 경과 시간 계산
    elapsed_time = round(time.time() - start_time, 2)

    # 스캔 결과 출력
    print(f"\nScan report for {args.ip}")
    print(f"Host is up. Scanned in {elapsed_time} seconds.")
    print(f"{closed_ports} closed ports and {filtered_ports} filtered ports not shown.")
    
    # 열린 포트를 테이블 형식으로 출력
    if open_ports_info:
        # 헤더 출력
        print("\nPORT       STATE    SERVICE          TTL")
        print("-" * 45)
        # 열린 포트 정보를 반복하면서 각 열을 정렬하여 출력
        for info in open_ports_info:
            # 각 열린 포트의 정보를 일정한 열 너비로 맞춰 출력
            print(f"{str(info['port']) + '/tcp':<10}{info['state']:<9}{info['service']:<16}{info['ttl']}")
    else:
        print("No open ports found.")  # 열린 포트가 없을 경우
