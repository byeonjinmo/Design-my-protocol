# server_thread dictionary exit
# 클라이언트로 부터 exit 문자열이 올때까지 계속 수신
# e 문자열을 수신하면 while 문 탈출하여 연결종료
from socket import *
from select import *
from threading import Thread, Event
from collections import defaultdict

event = Event()  # 키보드 입력받으면 키보드 종료시키기 위한 이벤트
HOST = ''
PORT = 5001
BUFSIZE = 1024
ADDR = (HOST, PORT)
# 서버에서 관리하는 다양한 자료 구조들
# 클라이언트의 ID를 키(key)로, 해당 클라이언트의 소켓 객체를 값(value) / 주로 메시지 전송과 관련된 작업에 사용
clientSockets = {}
# 소켓 객체를 키(key)로, 해당 클라이언트의 ID를 값(value) / clientIDs는 클라이언트 관리 및 인증 명확하게 책임분리를 사용하여 유지관리 용이함.
clientIDs = {}
# 필터링 키워드 저장 사전 (클라이언트id와 연결되어 저장) 수정 삭제는 본인이 지정한 키워드만 다룰 수 있기 위함
filter_keywords = defaultdict(list)
# 필터링된 키워드 집합 (모든 필터링된 단어의 저장) 그 외의 통신은 누구의 필터링이건 상관없이 적용되야하기 때문에 별도의 필터링 저장 공간 필요
filtered_keywords = set()
# 필터링 되는 대처 표현
def filter_message(msg, keyword):
    return msg.replace(keyword, "[****]")
def msg_proc(cs, m):
    global clientSockets, clientIDs, filter_keywords, filtered_keywords
    tokens = m.split(':')
    code = tokens[0]
    try:
        if (code.upper() == "ID"):
            print(f"command ID processed: {m}")
            clientID = tokens[1]
            # 필터링된 키워드 체크
            if any(keyword in clientID for keyword in filtered_keywords):
                matched_keywords = [keyword for keyword in filtered_keywords if keyword in clientID]
                # 매칭된 키워드 목록으로 에러 메시지 구성
                error_message = "Filtered_keywords: " + ", ".join(matched_keywords)
                send_c_res(cs, status="Error", action="Client_input_Error", message=f"{error_message}_ Please_enter_the_ID:yourID_command_again")
                return True
            # 중복 아이디 방지
            elif clientID in clientSockets:
                send_c_res(cs, status="Error", action="Duplicate_ID",
                           message="This_ID_is_already_in_use._Please_try_a_different_one.")
                return True
            else:
                print(f"Received message: {m}")  # 받은 메시지 로그 출력
                # ID 등록 및 클라이언트 소켓과 ID 매핑
                clientSockets[clientID] = cs
                clientIDs[cs] = clientID
                # 서버 코드 예시
                send_c_res(cs, status="Success", action="ID_Registration", message=f"Hello!_{clientID}!")

                return True
        elif (code.upper() == "TO"):
            print(f"command TO processed: {m}")
            fromID = tokens[1]
            toID = tokens[2]
            toMsg = tokens[3]
            # 수신자가 clientSockets에 존재하는지 확인
            if toID in clientSockets:
                # 모든 필터링 키워드를 메시지에 적용
                for keyword_list in filter_keywords.values():
                    for keyword in keyword_list:
                        toMsg = filter_message(toMsg, keyword)
            # 필터링된 메시지를 수신자에게 전송
                toSocket = clientSockets[toID]
                toSocket.send(f"TO:{fromID}:{toMsg}".encode())
                send_c_res(cs, status="Success", action="1to1", message=f"TO:{fromID}_Message_sent:{toMsg}")
            else:
                send_c_res(cs, status="Error", action="Recipient_Not_Found", message=f"Recipient_{toID}_not_found")
            return True

        elif (code.upper() == "BR"):
            print('broadcast data: ', m)
            fromID = tokens[1]
            toMsg = tokens[2]
            for toID, socket in clientSockets.items():
                # 수신자별 필터링 적용
                if toID in filtered_keywords:  # 임시 저장 공간 변경
                    filteredMsg = filter_message(toMsg, filter_keywords[toID])
                else:
                    filteredMsg = toMsg
                # 필터링된 메시지를 각 클라이언트에게 전송
                socket.send(f"BR:{fromID}:{filteredMsg}".encode())
            # 발신자에게 브로드캐스트 성공 메시지 전송
            if cs in clientSockets.values():
                send_c_res(cs, status="Success", action="Broadcast", message="Broadcast_completed_successfully")
            return True

        elif (code.upper() == "FILTER"):
            print(f"command FILTER processed: {m}")  # FILTER 명령 처리 로그
            fromID = tokens[1]
            keyword = tokens[2]
            # 클라이언트 ID 확인
            actualID = clientIDs.get(cs)  # 현재 소켓에 연결된 실제 클라이언트 ID
            if actualID != fromID:
                send_c_res(cs, status="Error", action="Other_user_ID_value", message=f"Only_own_ID_can_be_used")
                print(f"Other_people's_ID_value{fromID}")
            # 필터링 키워드 중복 검사
            elif keyword in filter_keywords[fromID]:    # 여긴 본인이 지정한 필터가 아니여도 적용
                # 이미 설정된 필터링 키워드일 경우
                send_c_res(cs, status="Error", action="Filter_Already_Set",
                           message=f"Keyword_already_filtered: {keyword}")
                print(f"Filter_Already_Set {fromID}: {keyword}")
            else:
                # 필터링 키워드 유효성 검사 (예: 숫자, 문자 유형 등)
                if not all(char.isalpha() or char.isspace() for char in keyword):
                    send_c_res(cs, status="Error", action="Invalid_Keyword", message="Please_enter_only_letters")
                else:
                    # 유효한 필터링 키워드인 경우에만 업데이트
                    filter_keywords[fromID].append(keyword)
                    filtered_keywords.add(keyword)  # 여기에 필터링 키워드를 추가
                    print(f"Filter set by {fromID}: {keyword}")  # 필터링 설정 로그
                    send_c_res(cs, status="Success", action="Filter_Set",
                               message=f"Filter_set_by_{fromID}_for_keyword_{keyword}")

        # FM 명령 처리 부분
        elif code == "FM":
            print(f"command FM processed: {m}")
            fromID = tokens[1]
            old_keyword = tokens[2]
            new_keyword = tokens[3]
            # 클라이언트 ID 확인 및 기존 키워드 존재 여부 확인
            actualID = clientIDs.get(cs)
            if actualID != fromID:
                send_c_res(cs, status="Error", action="Other_user_ID_value", message=f"Only_own_ID_can_be_used")
                print(f"Other_people's_ID_value{fromID}")
                return True
            elif old_keyword not in filtered_keywords:
                send_c_res(cs, status="Error", action="Keyword_Not_Found", message="filter_keyword_not_found")
                return True
            elif old_keyword not in filter_keywords[fromID]:
                send_c_res(cs, status="Error", action="Not_your_keywords.", message="Not_a_keyword_you_specified")
                return True
            else:
                # 필터링 키워드 유효성 검사
                if not all(char.isalpha() or char.isspace() for char in new_keyword):
                    send_c_res(cs, status="Error", action="Invalid_Keyword", message="Please_enter_only_letters")
                    return True
                else:
                    # 기존 키워드를 새 키워드로 교체
                    old_keyword_index = filter_keywords[fromID].index(old_keyword)
                    filter_keywords[fromID][old_keyword_index] = new_keyword

                    # filtered_keywords 집합도 업데이트
                    filtered_keywords.discard(old_keyword)  # 기존 키워드 제거
                    filtered_keywords.add(new_keyword)  # 새 키워드 추가

                    send_c_res(cs, status="Success", action="Filter_Modified",
                               message=f"{old_keyword}_Filter_modified_to_{new_keyword}")
        elif (code.upper() == "FD"):
            print(f"command FD processed: {m}")
            fromID = tokens[1]
            keyword = tokens[2]

            # 클라이언트 ID 확인 및 키워드 삭제
            actualID = clientIDs.get(cs)
            if actualID != fromID:
                send_c_res(cs, status="Error", action="Other_user_ID_value", message=f"Only_own_ID_can_be_used")
                print(f"Other_people's_ID_value{fromID}")
                return True
            elif keyword not in filtered_keywords:
                send_c_res(cs, status="Error", action="Keyword_Not_Found", message="filter_keyword_not_found")
                return True
            elif keyword not in filter_keywords[fromID]:
                send_c_res(cs, status="Error", action="Not_your_keywords.", message="Not_a_keyword_you_specified")
                return True
            else:
                # 필터링 키워드 삭제
                filter_keywords[fromID].remove(keyword)
                filtered_keywords.remove(keyword)
                send_c_res(cs, status="Success", action="FilterDeleted",
                           message=f"Filter keyword deleted: {keyword}")
        elif (code.upper() == "FIRST_SF"):
            print(f"Processing FIRST_SF command: {m}")
            if filtered_keywords:
                # 집합에 값이 있는 경우, 모든 필터링된 키워드를 문자열로 변환
                all_filters = ', '.join(filtered_keywords)
                send_c_res(cs, status="Success", action="Show_All_Filters",
                            message=f"Current_filters: {all_filters}")
                return True
            else:
                # 집합이 비어있는 경우, 에러 메시지 전송
                send_c_res(cs, status="Error", action="No_Filters", message="No_filters_set")
                return True
        elif (code.upper() == "SF"):
            print(f"Processing SF command: {m}")
            fromID = tokens[1]
            actualID = clientIDs.get(cs)
            if actualID != fromID:
                send_c_res(cs, status="Error", action="Other_user_ID_value", message=f"Only_own_ID_can_be_used")
                print(f"Other_people's_ID_value{fromID}")
                return True
            # filtered_keywords 집합이 비어있는지 확인
            if filtered_keywords:
                # 집합에 값이 있는 경우, 모든 필터링된 키워드를 문자열로 변환
                all_filters = ', '.join(filtered_keywords)
                send_c_res(cs, status="Success", action="Show_All_Filters",
                            message=f"Current_filters: {all_filters}")
                return True
            else:
                # 집합이 비어있는 경우, 에러 메시지 전송
                send_c_res(cs, status="Error", action="No_Filters", message="No_filters_set")
                return True
        elif (code.upper() == "Q"):
            fromID = tokens[1]
            # 클라이언트 소켓 및 ID 삭제
            clientSocket = clientSockets.pop(fromID, None)
            if clientSocket:
                clientIDs.pop(clientSocket, None)
            #클라이언트가 설정한 필터링 키워드 삭제
            if fromID in filter_keywords:
                # 삭제할 필터링 키워드 가져오기
                keywords_to_remove = filter_keywords.pop(fromID, [])
                # filtered_keywords에서 해당 키워드 제거
                for keyword in keywords_to_remove:
                    if all(keyword not in kwds for kwds in filter_keywords.values()):
                        filtered_keywords.discard(keyword)
            if clientSocket:
                clientSocket.close()
            print("Disconnected: {}", fromID)
            return False

    except Exception as e:
        print(f"Error:{e}")

def client_com(cs):
    # 클라이언트로부터 id 메시지를 받음
    while True:
        if event.is_set():  # event 발생하면 스레드 종료
            return
        try:  # 아래 문장 무조건 실행
            msg = cs.recv(BUFSIZE).decode()
            if not msg:  # 클라이언트가 연결을 비정상적으로 종료했을 경우 빈 문자열을 받음
                raise ConnectionError("Client disconnected unexpectedly")
            print('recieve data : ',msg)
        except Exception as e:  # 위 문장 에러 처리: client no longer connected
            print(f"Error or disconnect: {e}")
            handle_client_exit(cs)  # 클라이언트 종료 처리 함수 호출
            break
        else:  # recv 성공하면 메시지 처리
            if (msg_proc(cs, msg) == False):
                break  # 클라이언트가 종료하면 루프 탈출 후 스레드 종료


def handle_client_exit(cs):
    """
    클라이언트의 비정상 종료를 처리하는 함수.
    이 함수는 클라이언트 소켓 객체(cs)를 인자로 받아,
    해당 클라이언트와 관련된 모든 데이터를 정리한다.
    """
    # clientIDs 사전에서 클라이언트의 ID를 찾아 삭제
    clientID = clientIDs.pop(cs, None)

    if clientID:
        # clientSockets 사전에서 클라이언트의 소켓 객체를 삭제
        clientSockets.pop(clientID, None)

        # 필터링 키워드 삭제
        if clientID in filter_keywords:
            # 클라이언트가 설정한 모든 필터링 키워드를 가져와 삭제
            keywords_to_remove = filter_keywords.pop(clientID, [])
            for keyword in keywords_to_remove:
                # 해당 키워드가 다른 클라이언트에 의해 사용되지 않는 경우에만 filtered_keywords에서 제거
                if all(keyword not in kwds for kwds in filter_keywords.values()):
                    filtered_keywords.discard(keyword)

        print(f"Cleaned_up_resources_for_disconnected_client_{clientID}")
    else:
        print("Client_ID_not_found_for_the_given_socket.")
def client_acpt():
    # 소켓 생성
    global serverSocket
    serverSocket = socket(AF_INET, SOCK_STREAM)
    # 소켓 주소 정보 할당
    serverSocket.bind(ADDR)
    # 연결 수신 대기 상태
    serverSocket.listen(10)
    print('대기')
    # 연결 수락
    while True:
        if event.is_set():  # event 발생하면 스레드 종료
            return
        clientSocket, addr_info = serverSocket.accept()
        print('연결 수락: client 정보 ', addr_info)
        tc = Thread(target=client_com, args=(clientSocket,))
        tc.daemon = True
        tc.start()

ta = Thread(target=client_acpt)
ta.daemon = True
ta.start()

def create_c_res(**kwargs):
    response_parts = [f"{key}={value}" for key, value in kwargs.items() if value is not None]
    return ';'.join(response_parts)

def send_c_res(cs, **kwargs):
    response = create_c_res(**kwargs)
    cs.send(response.encode())

msg = input()
if msg.upper() == "Q":
    event.set()
# 소켓 종료

for socket in clientSockets.values():
    try:
        socket.shutdown()
        socket.close()
    except Exception as e:
        continue

serverSocket.close()
print('종료')