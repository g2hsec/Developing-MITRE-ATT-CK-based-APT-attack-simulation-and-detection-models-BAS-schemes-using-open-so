import subprocess
import json
from datetime import datetime

# 도구 실행 및 결과 캡처 함수
def run_tool(tool_name, command, category, output_filename):
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # 공격 시작 시간 기록
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
       
        # 성공/실패 여부 판단 (출력에 에러가 있거나 비정상 종료시 실패로 처리)
        if result.returncode == 0 and "error" not in result.stderr.lower():
            status = 0  # 성공 시 0 반환
            output = result.stdout  # 성공 시 출력 저장
        else:
            status = 1  # 실패 시 1 반환
            output = result.stderr if result.stderr else "Command failed"
       
        # 성공 시 결과 정보를 파일에 저장
        if status == 0:
            with open(output_filename, 'w') as f:
                f.write(f"Tool: {tool_name}\n")
                f.write(f"Command: {command}\n")
                f.write(f"Category: {category}\n")
                f.write(f"Start Time: {start_time}\n")
                f.write(f"Output:\n{output}\n")
                f.write("\n" + "="*40 + "\n\n")
            print(f"Results saved to {output_filename}")

        return {
            "tool": tool_name,
            "command": command,
            "category": category,  # 공격 카테고리 추가
            "status": status,  # 성공 여부 (0: 성공, 1: 실패)
            "start_time": start_time  # 공격 시작 시간 포함
        }
    except Exception as e:
        return {
            "tool": tool_name,
            "command": command,
            "category": category,  # 공격 카테고리 추가
            "output": str(e),
            "status": 1,  # 예외 발생 시 실패로 처리
            "start_time": start_time  # 공격 시작 시간 포함
        }

# 도구별 공격 실행 함수
def execute_nmap(target, output_filename):
    command = f"nmap -sV --script vulners {target}"
    print(f"Running nmap scan on {target} with command: {command}")
    return run_tool('nmap', command, "Scanning", output_filename)  # 카테고리 추가

def execute_nikto(target, output_filename):
    command = f"nikto -h {target}"
    print(f"Running nikto scan on {target} with command: {command}")
    return run_tool('nikto', command, "Scanning", output_filename)  # 카테고리 추가

def execute_netenum(target_range, output_filename):
    command = f"netenum {target_range} 3"
    print(f"Running netenum scan on {target_range} with command: {command}")
    return run_tool('netenum', command, "Scanning", output_filename)  # 카테고리 추가

def execute_zmap(target, output_filename):
    command = f"zmap -p 80 {target} -o -"
    print(f"Running zmap scan on {target} with command: {command}")
    return run_tool('zmap', command, "Scanning", output_filename)  # 카테고리 추가

# 공격 로그를 개별 JSON 파일로 저장하는 함수
def save_log_to_json(log_data, index):
    filename = f"attack_log{index}.json"  # 순번에 따른 파일명 지정
    with open(filename, 'w') as f:
        json.dump(log_data, f, indent=4)
    print(f"Log saved to {filename}")

# 공격 실행 함수
def execute_attack(target, target_range, domain):
    # 각 도구 실행 후 로그를 개별 JSON 파일로 저장
    save_log_to_json(execute_nmap(target, "nmap_results.txt"), index=1)
    save_log_to_json(execute_nikto(target, "nikto_results.txt"), index=2)
    save_log_to_json(execute_netenum(target_range, "netenum_results.txt"), index=3)
    save_log_to_json(execute_zmap(target, "zmap_results.txt"), index=4)

# 타겟 입력 및 공격 실행
if __name__ == "__main__":
    target_ip = input("Enter the target IP or range (e.g., 192.168.1.0/24): ")
    target_range = input("Enter the target range for netenum (e.g., 192.168.1.0/24): ")
    target_domain = input("Enter the target domain (e.g., example.com): ")

    execute_attack(target_ip, target_range, target_domain)

