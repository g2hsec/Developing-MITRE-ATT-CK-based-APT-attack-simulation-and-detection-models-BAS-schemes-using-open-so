import requests
import yaml
import uuid
import json
from pycti import OpenCTIApiClient
import logging
import time
import urllib3
from requests.auth import HTTPBasicAuth

# HTTPS 경고 비활성화
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def send_to_logstash(log_entries, chunk_size=50):  # 청크 크기를 더 줄임
    logstash_url = "http://:"
    headers = {'Content-Type': 'application/json'}
    
    chunk = {}
    count = 0
    for key, value in log_entries.items():
        chunk[key] = value
        count += 1
        if count % chunk_size == 0:
            response = requests.post(logstash_url, data=json.dumps(chunk), headers=headers)
            if response.status_code == 200:
                print("Successfully sent chunk")
            else:
                print(f"Failed to send chunk: {response.status_code}")
            chunk = {}  # 청크 초기화
    
    if chunk:
        response = requests.post(logstash_url, data=json.dumps(chunk), headers=headers)
        if response.status_code == 200:
            print("Successfully sent remaining chunk")
        else:
            print(f"Failed to send remaining chunk: {response.status_code}")



count=0
# 로깅 수준을 WARNING으로 설정하여 INFO 메시지를 숨깁니다.
logging.basicConfig(level=logging.WARNING)

# OpenCTI API 설정
api_url = 'http://:'
api_token = ''
headers = {
    'Authorization': f'Bearer {api_token}',
    'Content-Type': 'application/json'
}

# OpenCTI 초기화
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# 모든 침해 집합 목록 가져오기
intrusion_sets = opencti_api_client.intrusion_set.list()

# 필요한 값만 추출하여 저장할 리스트
data = []
names = []  # Name만 따로 저장할 리스트

for intrusion_set in intrusion_sets:
    intrusion_set_data = {
        "ID": intrusion_set.get("id"),
        "Name": intrusion_set.get("name"),
        "Description": intrusion_set.get("description"),
        #"Aliases": intrusion_set.get("aliases"),
        "Created": intrusion_set.get("created"),
        "Modified": intrusion_set.get("modified"),
    }
    data.append(intrusion_set_data)  # 기존 data 리스트에 intrusion_set_data 추가

    # Name 값을 names 리스트에 따로 저장
    name = intrusion_set.get("name")
    if name:  # Name 값이 존재할 경우에만 추가
        names.append(name)

# 추출된 데이터 출력 (선택사항)
print('=============APT Groups List=============')
for name in names:
    count+=1
    print(count, name)
print('=========================================')

# 사용자로부터 번호 입력받기
choice = int(input("원하는 그룹의 번호를 입력하세요: "))

# 입력한 번호에 맞는 이름을 가져오기 (리스트는 0부터 시작하므로 -1)
if 1 <= choice <= len(names):  # 입력 값이 유효한 범위인지 확인
    selected_data = data[choice - 1]  # 선택한 인덱스의 데1터를 가져옴
    selected_name = selected_data["Name"]
    selected_description = selected_data["Description"]
    
    print(f"선택한 그룹의 이름: {selected_name}")
    print(f"선택한 그룹의 설명: {selected_description}")
else:
    print("잘못된 번호를 입력하셨습니다.")


# JSON 파일로 저장
with open("intrusion_sets.json", "w") as f:
    json.dump(data, f, indent=4)

print("Selected intrusion set data saved to intrusion_sets.json")


# Define intrusion set name (APT 그룹)
intrusion_set_name = selected_name  # 예시: APT29 그룹의 TTPs를 가져오려면
intrusion_set_id = None

for intrusion_set in intrusion_sets:
    if intrusion_set["name"] == intrusion_set_name:
        intrusion_set_id = intrusion_set["id"]
        break

if intrusion_set_id:
    print(f"Intrusion Set ID: {intrusion_set_id}")
else:
    print(f"Intrusion Set '{intrusion_set_name}' not found")

ttp_relationships = opencti_api_client.stix_core_relationship.list(
    fromId=intrusion_set_id, 
    toTypes=["Attack-Pattern"]
)

# TTPs 정보 출력
x_mitre_ids = []  # 빈 배열을 선언
ttp_names = []
tactics_order = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact", "multiple"]
for relationship in ttp_relationships:
    ttp = relationship["to"]
    ttp_id = ttp['id']
    ttp_name = ttp['name']
    
    # TTP의 상세 정보 조회
    ttp_details = opencti_api_client.attack_pattern.read(id=ttp_id)
    
    # x_mitre_id 값 가져오기
    x_mitre_id = ttp_details.get('x_mitre_id', 'Not found')
    if x_mitre_id != 'Not found':  # 유효한 ID만 추가
        x_mitre_ids.append(x_mitre_id)
    if ttp_name != 'Not found':  # 유효한 ID만 추가
        ttp_names.append(ttp_name)
    # killChainPhases에서 phase_name 값 가져오기
    kill_chain_phases = ttp_details.get('killChainPhases', [])

    # phase_name 리스트 생성
    phase_names = [phase['phase_name'] for phase in kill_chain_phases] if kill_chain_phases else ['No phase name found']
    print(f"TTP Name: {ttp_name}, TTP ID: {ttp_id}, x_mitre_id: {x_mitre_id}, Phase Names: {', '.join(phase_names)}")

ability_ids = []       

generated_uuid = str(uuid.uuid4())
# Caldera 서버 URL 및 API 키
caldera_url = "http://:/api/v2/abilities"  # Caldera API URL
api_key = ""  # Caldera API 키

# 헤더에 API 키를 포함
headers = {
    'KEY': api_key,
    'Content-Type': 'application/json'
}

# API 호출을 통해 현재 실행 중인 모든 작업(abilities)을 확인
response = requests.get(caldera_url, headers=headers)

abilities = response.json()  # API 응답에서 Ability 목록 가져오기

# Ability를 리스트에 저장
ability_list = []

for ability in abilities:
    ability_data = {
        "id": ability.get("ability_id"),
        "technique_id": ability.get("technique_id"),
        "name": ability.get("name"),
        "technique_name": ability.get("technique_name"),
        "tactic": ability.get("tactic"),
    }
    ability_list.append(ability_data)

print('----------------------')

ability_ids = []
test_id=[]
technique_ids = []
tactics = []
# ability 리스트 순회
#print(json.dumps(abilities, indent=4)) <구조확인>
for tx_mitre_id in x_mitre_ids:
    for ability in abilities:
        if tx_mitre_id in ability.get("technique_id"):
            print(tx_mitre_id)
            ability_ids.append(ability.get("ability_id"))
            technique_ids.append(ability.get("technique_id"))
            tactics.append(ability.get("tactic"))
            break   

# 정렬할 데이터들을 하나의 리스트로 묶음
combined = list(zip(tactics, ability_ids, technique_ids))

# tactics_order에 따라 tactics 순서 재정렬
combined_sorted = sorted(combined, key=lambda x: tactics_order.index(x[0]))

# 재정렬된 데이터를 다시 각 변수로 분리
tactics, ability_ids, technique_ids = zip(*combined_sorted)
#print(tactics)
objectives_url='http://:/api/v2/objectives'
response = requests.get(objectives_url, headers=headers)

if response.status_code == 200:
    objectives = response.json()
    for objective in objectives:
        print(f"Objective ID: {objective['id']}, Name: {objective['name']}")
else:
    print(f"실패: {response.status_code}, {response.text}")

# adversary_id 생성
adversary_id=str(uuid.uuid4())

adversaries_data = {
    "adversary_id": adversary_id,
    "description": selected_description,
    "id": generated_uuid,
    "name": selected_name,
    "atomic_ordering": ability_ids,
    "objective": objective['id'],
    #"technique_id" : technique_ids,
    #"tactic" : tactics,
    "plugin": None
}


adversaries_url='http://:/api/v2/adversaries'

# POST 요청 보내기
response = requests.post(adversaries_url, headers=headers, json=adversaries_data)
 
if response.status_code == 200:
    print("Adversary 생성 성공")
else:
    print(f"실패: {response.status_code}, {response.text}")


planners_url = 'http://:/api/v2/planners'
response = requests.get(planners_url, headers=headers)

if response.status_code == 200:
    planners = response.json()
    if planners:
        planner_info = planners[0]  # 첫 번째 플래너의 정보를 사용
        #print(f"사용할 플래너 정보: {planner_info}")
    else:
        print("사용 가능한 플래너가 없습니다.")
        exit()
else:
    print(f"플래너 목록을 가져오는 데 실패했습니다: {response.status_code}, {response.text}")
    exit()
    
# ability_id 순서대로 각각의 step을 지정
steps = [{"ability_id": ability_id} for ability_id in ability_ids]

operation_data = {
    "name": "MyOperation",
    "adversary": {
        "adversary_id": adversary_id,
        "name": "Adversary Name",
        "description": "Adversary Description",
        "atomic_ordering": ability_ids,  # 기존 방식 유지
        "objective": objective['id'],
        "tags": ['test']
    },
    "planner": {
        "id": planner_info['id'],
        "name": planner_info.get('name', ''),
        "module": planner_info.get('module', ''),
        "params": planner_info.get('params', {}),
        "description": planner_info.get('description', ''),
        "stopping_conditions": planner_info.get('stopping_conditions', []),
        "ignore_enforcement_modules": planner_info.get('ignore_enforcement_modules', [])
    },
    "jitter": "2/8",
    "group": "red",
    "steps": steps  # 명시적으로 steps 추가
}   
#print("ability id : ", ability_ids)
operations_url = 'http://:/api/v2/operations'
response = requests.post(operations_url, headers=headers, json=operation_data)

if response.status_code == 200:
    operation_id = response.json()['id']
    print(f"Operation 생성 성공: {operation_id}")
else:
    print(f"Operation 생성 실패: {response.status_code}, {response.text}")
    exit()

check_interval = 60

status_url = f'http://:/api/v2/operations/{operation_id}'

def check_operation_status():
    while True:
        # 상태 요청
        status_response = requests.get(status_url, headers=headers)
        
        if status_response.status_code == 200:
            status_data = status_response.json()
            operation_status = status_data.get('state', '')  # 'state' 값이 running 또는 finished
            
            # 상태 출력
            print(f"Operation 상태: {operation_status}")
            
            if operation_status == 'finished':
                print(f"Operation {operation_id}이 완료되었습니다!")
                return 'finished'
            elif operation_status == 'running':
                print(f"Operation {operation_id}이 진행 중입니다...")
        else:
            print(f"상태 확인 실패: {status_response.status_code}, {status_response.text}")
            return None

        # 설정한 시간만큼 대기 (폴링 간격)
        time.sleep(check_interval)



# Operation 상태 체크 시작
result = check_operation_status()
#time.sleep(3) #collect 대비
# 재시도 횟수 설정 (무한 루프가 아닌 경우)
# 상태에 따라 추가 작업 실행 가능
if result == 'finished':
    # Operation 완료 후 로그나 결과를 처리하는 작업 추가 가능
    logs_url = f'http://:/api/v2/operations/{operation_id}/event-logs'
    logs_response = requests.post(logs_url, headers=headers)
    # 성공한 공격에 대해서만 링크 API 호출
    links_url = f"http://:/api/v2/operations/{operation_id}/links"
    links_response = requests.get(links_url, headers=headers)
    event_logs = []
    # 커맨드 값을 초기화
    commands = []

    max_retries = 99  # 최대 재시도 횟수 설정

    if logs_response.status_code == 200 and links_response.status_code == 200:
        logs_data = logs_response.json()
        links_data = links_response.json()
        
        for event, links in zip(logs_data, links_data):
            retry_count = 0  # 재시도 카운트 초기화
            #print(event)
            # links가 dict인 경우 각 command를 추출
            commands_list = []
            if isinstance(links, dict):
                for key, value in links.items():
                    if key == 'command':
                        commands_list.append(value)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict) and 'command' in item:
                                commands_list.append(item['command'])

            while retry_count < max_retries:
                if event.get('status') == -3:
                    print(f"status가 -3입니다. 재요청 중... ({retry_count + 1}/{max_retries})")
                    retry_count += 1
                    time.sleep(3)  # 3초 대기 후 재요청

                    # 재요청 수행
                    logs_response_retry = requests.post(logs_url, headers=headers)
                    links_response_retry = requests.get(links_url, headers=headers)

                    if logs_response_retry.status_code == 200 and links_response_retry.status_code == 200:
                        logs_data_retry = logs_response_retry.json()
                        links_data_retry = links_response_retry.json()

                        # logs_data_retry에서 event와 동일한 id를 가진 새로운 event를 찾아 업데이트
                        new_event = next((item for item in logs_data_retry if item.get('id') == event.get('id')), None)
                        
                        if new_event:
                            event = new_event  # 새로운 event로 업데이트

                            # 새로운 event로 업데이트되었으나 status가 여전히 -3인지 확인
                            if event.get('status') == -3:
                                print("재요청 후에도 status가 -3입니다. 재시도 진행 중...")
                                continue  # 루프 재시도
                            else:
                                print("재요청 성공, event 처리 완료.")
                                log_entry = {
                                    'status': event.get('status'),
                                    'attack_metadata': event.get('attack_metadata'),
                                    'agent_id': event.get('agent_metadata', {}).get('paw')
                                }
                                command_entry = {
                                    'command': commands_list
                                }
                                event_logs.append(log_entry)
                                commands.append(command_entry)
                                break  # 성공적으로 처리되었으므로 루프 종료
                        else:
                            print(f"이벤트가 logs_data_retry에 존재하지 않습니다: {event}")
                            break  # 이벤트가 없으면 루프 종료
                    else:
                        print(f"재요청 실패: {logs_response_retry.status_code}, {links_response_retry.status_code}")
                        break
                else:
                    # status가 -3이 아닌 경우, 정상적으로 로그를 추가하고 루프 종료
                    log_entry = {
                        'status': event.get('status'),
                        'attack_metadata': event.get('attack_metadata'),
                        'agent_id': event.get('agent_metadata', {}).get('paw')
                    }
                    command_entry = {
                        'command': commands_list
                    }
                    event_logs.append(log_entry)
                    commands.append(command_entry)
                    break

        #print(event_logs)
        # 전술별로 상태를 저장할 dictionary
        tactic_status = {}

        # 각 항목을 반복하며 상태별로 전술을 분류
        for entry in event_logs:
            fail_agent_id = entry['agent_id']  # agent id
            tactic = entry['attack_metadata']['tactic']
            status = entry['status']
            
            if fail_agent_id not in tactic_status:
                tactic_status[fail_agent_id] = {}

            if tactic not in tactic_status[fail_agent_id]:
                tactic_status[fail_agent_id][tactic] = {'total': 0, 'failed': 0}
            
            tactic_status[fail_agent_id][tactic]['total'] += 1
            if status == 1:
                tactic_status[fail_agent_id][tactic]['failed'] += 1

        failed_agents_tactics = []
        # 에이전트별로 전부 실패한 전술 목록을 수집
        for fail_agent_id, tactics in tactic_status.items():
            failed_tactics = [tactic for tactic, counts in tactics.items() if counts['total'] == counts['failed']]
            
            # 결과 출력
            if failed_tactics:
                print(f"에이전트 {fail_agent_id}에서 전부 실패로 간주된 전술:", failed_tactics)
                failed_agents_tactics.append({'fail_agent_id': fail_agent_id, 'failed_tactics': failed_tactics})
            else:
                print(f"에이전트 {fail_agent_id}에서 모든 공격에 성공했습니다.")

        # JSON 파일을 읽어 parsed_data로 변환
        #attack_object_id, attack_object_name 가 마이터, nist는 capability_group,capability_description
        with open("nist_800_53-rev5_attack-14.1-enterprise_json.json", "r") as nist_mitre_mapper_file:
            parsed_data = json.load(nist_mitre_mapper_file)  # JSON 데이터를 딕셔너리로 읽기

        # 'mapping_objects' 키의 데이터만 추출
        mapping_objects = parsed_data.get("mapping_objects", [])

        # 기술 ID에 해당하는 모든 로그를 Logstash로 전송
        all_log_data = []  # 모든 로그 데이터를 저장할 리스트
        all_log_data_dict = {}
        successful_ttps = []
        print("Event Logs:")
        #print(commands)
        print(event_logs)
        status = []
        tactic = []
        technique_name = []
        for log, cmd in zip(event_logs,commands):
            if log.get('status') != -3: #0이 성공
                technique_id = log.get('attack_metadata', {}).get('technique_id')
                comment = log.get('attack_metadata', {}).get('comment')
                command = cmd.get('command')
                status = log.get('status')
                tactic = log.get('attack_metadata', {}).get('tactic')
                technique_name = log.get('attack_metadata', {}).get('technique_name')

                if command and isinstance(command, list):
                    commands_list.extend(command)
                #cmd = cmd.get('command')
                print('command : ', commands_list)
                if technique_id:
                    # 성공한 TTP를 리스트에 추가
                    successful_ttps.append({
                        "technique_id": technique_id,
                        "color": "#ff0000",  # 성공한 공격은 초록색으로 표시
                        "comment": comment or "Successful TTP"  # comment가 없으면 기본값 설정
                    })
                    print(f"\n기술 ID: {technique_id}")
                    #print(status)
                    # mapping_objects에서 해당 technique_id에 해당하는 항목 필터링
                    for item in mapping_objects:
                        if isinstance(item, dict) and item.get('attack_object_id') == technique_id:
                            capability_id = item.get('capability_id')
                            capability_description = item.get('capability_description')
                            attack_object_name = item.get('attack_object_name')

                            log_data = {
                                "technique_id": technique_id,
                                "capability_id": capability_id,
                                "capability_description": capability_description,
                                #"attack_object_name": attack_object_name,
                                "operation_id": operation_id,
                                "command": commands_list,
                                "status": status,
                                "tactic": tactic,
                                "technique_name": technique_name,
                                #"commands": commands,  # 커맨드 값 추가
                                "timestamp": item.get('timestamp')  # 예시로 timestamp 추가
                            }

                            #print(f"Capability ID: {capability_id}")
                            #print(f"Capability Description: {capability_description}")
                            #print(f"Attack Object Name: {attack_object_name}")
                            if technique_id not in all_log_data_dict:
                                all_log_data_dict[technique_id] = []
                            all_log_data_dict[technique_id].append(log_data)
                        else:
                            log_data = {
                                "technique_id": technique_id,
                                "operation_id": operation_id,
                                "command": commands_list,  # commands_list를 포함
                                "status": status,
                                "tactic": tactic,
                                "technique_name": technique_name,
                                "timestamp": item.get('timestamp')  # 예시로 timestamp 추가
                            }

                            # 중복 여부 확인
                            duplicate_found = False
                            if technique_id in all_log_data_dict:
                                for existing_log in all_log_data_dict[technique_id]:
                                    # command 비교
                                    if existing_log["command"] == log_data["command"]:
                                        duplicate_found = True  # 중복 발견
                                        break  # 중복이 발견되면 루프 종료

                            if not duplicate_found:
                                # 기술 ID를 키로 하여 로그 데이터 추가
                                if technique_id not in all_log_data_dict:
                                    all_log_data_dict[technique_id] = []
                                all_log_data_dict[technique_id].append(log_data)

                            #print("all_log_data_dict : ", all_log_data_dict)
                            #print(all_log_data_dict[technique_id])

            if log.get('status') == 1:
                technique_id = log.get('attack_metadata', {}).get('technique_id')
                comment = log.get('attack_metadata', {}).get('comment')
                #command = cmd.get('command')
                #status = log.get('status')
                #if command and isinstance(command, list):
                    #commands_list.extend(command)
                if technique_id:
                    # 실패한 TTP를 리스트에 추가
                    successful_ttps.append({
                        "technique_id": technique_id,
                        "color": "#0000ff",  # 실퓨ㅐ한 공격은 빨간색으로 표시
                        "comment": comment or "Successful TTP"  # comment가 없으면 기본값 설정
                    })

        # 이후 레이어 파일 생성 코드와 동일
        layer_data = {
            "name": "Successful TTPs",
            "version": "4.5",
            "domain": "enterprise-attack",
            "description": "Layer for successful TTPs from the recent operation.",
            "techniques": [],
            "gradient": {
                "colors": ["#ffffff", "#ff0000", "0000ff"],
                "minValue": 0,
                "maxValue": 1
            },
            "legendItems": [
                {"label": "Successful TTP (Red)", "color": "#ff0000"},
                {"label": "Successful TTP (Blue)", "color": "#0000ff"}
            ]
        }
        # 성공한 TTP를 레이어 파일에 추가하며, 관련 capability_id도 comment에 포함
        for ttp in successful_ttps:
            # 해당 technique_id에 맞는 모든 capability_id를 찾아서 리스트로 구성
            capability_ids = [item.get('capability_id') for item in mapping_objects if item.get('attack_object_id') == ttp["technique_id"]]
            
            # comment에 capability_id 리스트를 추가
            capabilities_comment = f"Capabilities: {', '.join(capability_ids)}" if capability_ids else ""
            
            # 기존 comment와 capability_id를 결합하여 최종 comment 생성
            final_comment = f"{ttp.get('comment', 'Successful TTP')} {capabilities_comment}"
            
            layer_data["techniques"].append({
                "techniqueID": ttp["technique_id"],
                "color": ttp.get("color", "#ff6666"),
                "comment": final_comment  # comment에 모든 capability_id 추가
            })

        # 레이어 파일 저장
        with open("successful_ttps_layer.json", "w") as layer_file:
            json.dump(layer_data, layer_file, indent=4)

        print("Layer file 'successful_ttps_layer.json' has been created.")
        #print("logdata:", log_data)
        for technique_id, log_entries in all_log_data_dict.items():
            # print(all_log_data_dict)
            # print()
            # print(log_entries)
            # print()
            if log_entries:
                # log_entries와 commands_list의 개수에 맞춰 병합된 명령어 리스트를 생성
                #commands_for_each_entry = [commands_list[i] if i < len(commands_list) else None for i in range(len(log_entries))]
                
                # 각 log_entry에 commands_list의 명령어를 할당
                for i, entry in enumerate(log_entries):
                    #entry["command"] = commands_for_each_entry[i]
                    #print('i : ',i)
                    #print('entry : ',entry)
                    # 병합된 데이터 생성
                    merged_log_data = {
                        "technique_id": technique_id,
                        "capability_id": ", ".join([entry["capability_id"] for entry in log_entries if entry.get("capability_id")]),
                        "capability_description": ", ".join([entry["capability_description"] for entry in log_entries if entry.get("capability_description")]),
                        #"attack_object_name": ", ".join([entry["attack_object_name"] for entry in log_entries if entry.get("attack_object_name")]),
                        "operation_id": operation_id,
                        "status": entry["status"],
                        "tactic": entry["tactic"],
                        "technique_name": entry["technique_name"],
                        # commands_list에서 병합된 명령어 할당
                        "command": entry["command"],
                        # 첫 번째 항목의 timestamp 사용
                        "timestamp": log_entries[0].get('timestamp'),
                        "fail_agent_id": [agent['fail_agent_id'] for agent in failed_agents_tactics],
                        "failed_tactics": [agent['failed_tactics'] for agent in failed_agents_tactics]
                    }

                #print(merged_log_data)  # 출력
                send_to_logstash(merged_log_data)  # 병합된 데이터 전송
            print(f"Successfully sent {len(merged_log_data)} log entries to Logstash.")
    else:
        print(f"로그 가져오기 실패: {logs_response.status_code}, {logs_response.text}")

elif result == 'failed':
    # 실패 시 처리할 로직 추가 가능
    print("Operation이 실패하여 추가 작업을 진행합니다.")

# Elasticsearch URL 및 인증 정보
elasticsearch_url = "https://:/_search?pretty"
username = ""
password = ""

# 쿼리 데이터
data = {
    "query": {
        "bool": {
            "must": [
                {"exists": {"field": "rule.groups"}},
                {"term": {"rule.groups": "purple"}},
                {"range": {"@timestamp": {"gte": "now-1d/d", "lt": "now/d"}}}
            ]
        }
    },
    "size": 500,
    "sort": [
        {"@timestamp": {"order": "desc"}}
    ]
}
time.sleep(10)
# 요청 보내기
elasticsearch_response = requests.get(elasticsearch_url, auth=HTTPBasicAuth(username, password), json=data, verify=False)

# 결과 처리
if elasticsearch_response.status_code == 200:
    # JSON 파일로 저장
    with open('elasticsearch_response.json', 'w') as json_file:
        json.dump(elasticsearch_response.json(), json_file, indent=4)
    print("응답을 'elasticsearch_response.json' 파일로 저장했습니다.")
else:
    print("요청 실패:", elasticsearch_response.status_code, elasticsearch_response.text)

input_file = "successful_ttps_layer.json"
output_file = "elasticsearch_response.json"  # 파일명 수정
purple_color = "#800080"  # 겹치는 ID의 색상 코드

def load_mitre_layer(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)

def merge_mitre_layers(layer_a, layer_b):
    merged_techniques = {}

    # A 파일에서 techniqueID와 색상 저장
    for technique in layer_a.get("techniques", []):
        technique_id = technique["techniqueID"]
        merged_techniques[technique_id] = {
            "color": technique["color"],
            "overlap": False  # 중복 여부를 표시하는 플래그
        }

    # B 파일에서 techniqueID를 확인하고 병합
    for hit in layer_b.get("hits", {}).get("hits", []):
        technique_ids = hit["_source"].get("rule", {}).get("mitre", {}).get("id", [])
        
        for technique_id in technique_ids:  # 여러 techniqueID 처리
            if technique_id in merged_techniques:
                # 중복되는 ID는 보라색으로 설정하고 플래그를 갱신
                merged_techniques[technique_id]["color"] = purple_color
                merged_techniques[technique_id]["overlap"] = True
            else:
                # 새 techniqueID를 추가
                merged_techniques[technique_id] = {
                    "color": "#000000",  # 기본 색상
                    "overlap": False
                }

    # 병합된 결과를 새로운 layer 템플릿으로 생성
    merged_layer = {
        "version": "4.5",
        "name": "Merged Wazuh Alerts Layer",
        "description": "Layer merged from two Wazuh alert layers",
        "domain": "enterprise-attack",
        "techniques": [
            {
                "techniqueID": tid,
                "color": details["color"]
            }
            for tid, details in merged_techniques.items()
        ],
        "gradient": {
            "colors": ["#ffffff", purple_color],  # 보라색 포함
            "minValue": 0,
            "maxValue": 1
        },
        "legendItems": [
            {
                "label": "Unique Techniques from A and B",
                "color": "#0000ff"
            },
            {
                "label": "Overlapping Techniques",
                "color": purple_color
            }
        ]
    }


    return merged_layer

# A 및 B 파일 읽기
layer_a = load_mitre_layer(input_file)
layer_b = load_mitre_layer(output_file)

# 레이어 병합
merged_layer = merge_mitre_layers(layer_a, layer_b)
result_file = "merged_mitre_layer.json"

# 결과를 출력 파일로 저장
with open(result_file, "w", encoding="utf-8") as file:
    json.dump(merged_layer, file, ensure_ascii=False, indent=4)

print(f"병합된 MITRE ATT&CK layer 파일이 {result_file}로 생성되었습니다.")

# 프로그램이 종료되지 않도록 대기
input("프로그램이 완료되었습니다. 종료하려면 Enter를 누르세요...")