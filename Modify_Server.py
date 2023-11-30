# server_thread dictionary exit
# 클라이언트로 부터 exit 문자열이 올때까지 계속 수신
# exit 문자열을 수신하면 while 문 탈출하여 연결종료
from socket import *
from select import *
from threading import Thread, Event
from collections import defaultdict

event = Event()  # 키보드 입력받으면 키보드 종료시키기 위한 이벤트
HOST = ''
PORT = 5001
BUFSIZE = 1024
ADDR = (HOST, PORT)

# 연결된 client의 소켓 집합 set of connected client sockets
clientSockets = {}
# 각 소켓에 대한 클라이언트 ID 저장
clientIDs = {}
# 필터링 키워드 저장 사전 (클라이언트id와 연결되어 저장)
filter_keywords = {}

# 필터링된 키워드 집합 (모든 필터링된 단어의 저장 헷갈리지 마라 진모야)
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
            clientID = tokens[1]
            # 필터링된 키워드 체크
            if any(keyword in clientID for keyword in filtered_keywords):
                cs.send("에러_필터링_지정_단어는_ID_사용_불가_Q_입력_후_재접속_제안".encode())
                return True

            else:
                print(f"Received message: {m}")  # 받은 메시지 로그 출력
                # ID 등록 및 클라이언트 소켓과 ID 매핑
                clientSockets[clientID] = cs
                clientIDs[cs] = clientID
                cs.send("Success:Reg_ID".encode())
                return True

        elif (code.upper() == "TO"):
            print(f"TO command processed: {m}")
            fromID = tokens[1]
            toID = tokens[2]
            toMsg = tokens[3]
            # 메시지 필터링: 수신자의 필터링 키워드를 적용
            if toID in filter_keywords:
                toMsg = filter_message(toMsg, filter_keywords[toID])
            print(f"1to1: From {fromID} To {toID} Message {toMsg}")
            # 필터링된 메시지를 수신자에게 전송
            toSocket = clientSockets.get(toID)
            toSocket.send(f"TO:{fromID}:{toMsg}".encode())  # 수정된 메시지를 전송
            cs.send("Success:1to1".encode())
            return True

        elif (code.upper() == "BR"):
            print('broadcast data: ', m)
            fromID = tokens[1]
            toMsg = tokens[2]
            for toID, socket in clientSockets.items():
                # 수신자별 필터링 적용
                if toID in filter_keywords:
                    filteredMsg = filter_message(toMsg, filter_keywords[toID])
                else:
                    filteredMsg = toMsg
                # 필터링된 메시지를 각 클라이언트에게 전송
                socket.send(f"BR:{fromID}:{filteredMsg}".encode())
            # 발신자에게 브로드캐스트 성공 메시지 전송
            if cs in clientSockets.values():
                cs.send("Success:BR".encode())

            return True

        elif (code.upper() == "FILTER"):
            print(f"Processing FILTER command: {m}")  # FILTER 명령 처리 로그
            fromID = tokens[1]
            keyword = tokens[2]
            # 클라이언트 ID 확인
            actualID = clientIDs.get(cs)  # 현재 소켓에 연결된 실제 클라이언트 ID
            if actualID != fromID:
                cs.send("에러_본인_ID만_사용_가능ID".encode())
                print(f"Unauthorized ID usage attempt: {fromID}")
                return True
            # 필터링 키워드 중복 검사
            if fromID in filter_keywords and filter_keywords[fromID] == keyword:
                # 이미 설정된 필터링 키워드일 경우
                cs.send(f"에러_이미_필터링_적용된_키워드입니다._{keyword}".encode())
                print(f"FilterAlreadySet {fromID}: {keyword}")
            else:
                # 필터링 키워드 유효성 검사 (예: 숫자, 문자 유형 등)
                if not all(char.isalpha() or char.isspace() for char in keyword):
                    cs.send("에러2_한글,영어만 입력해주세요.".encode())
                    return True
                # 필터링 키워드 업데이트
                filter_keywords[fromID] = keyword
                filtered_keywords.add(keyword)  # 여기에 필터링 키워드를 추가
                print(f"Filter set by {fromID}: {keyword}")  # 필터링 설정 로그
                success_message = f"Success:Filter_Set_By_{fromID}_Keyword_{keyword}"
                for socket in clientSockets.values():
                    socket.send(success_message.encode())

        elif (code.upper() == "FM"):
            fromID = tokens[1]
            old_keyword = tokens[2]
            new_keyword = tokens[3]

            # 클라이언트 ID 확인 및 기존 키워드 일치 여부 확인
            actualID = clientIDs.get(cs)
            if actualID != fromID or filter_keywords.get(fromID) != old_keyword:
                cs.send("에러_본인_'기존'_필터링만_수정_가능".encode())
                return True
            else:
                # 필터링 키워드 유효성 검사 (예: 숫자, 문자 유형 등)
                if not all(char.isalpha() or char.isspace() for char in new_keyword):
                    cs.send("에러2_한글,영어만 입력해주세요.".encode())
                    return True
            # 필터링 키워드 업데이트
            filter_keywords[fromID] = new_keyword
            cs.send(f"Success:FilterModified_{new_keyword}".encode())
            return True
        elif (code.upper() == "FD"):
            fromID = tokens[1]
            keyword_to_delete = tokens[2]

            # 클라이언트 ID 확인 및 키워드 삭제
            actualID = clientIDs.get(cs)
            if actualID != fromID or filter_keywords.get(fromID) != keyword_to_delete:
                cs.send("Error:InvalidFilterDeletion".encode())
                return True
            # 필터링 키워드 삭제
            del filter_keywords[fromID]
            cs.send(f"Success:FilterDeleted_{keyword_to_delete}".encode())

        elif (code.upper() == "QUIT"):
            fromID = tokens[1]
            clientSockets.pop(fromID)
            cs.close()
            print("Disconnected:{}", fromID)
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
            print('recieve data : ',msg)
        except Exception as e:  # 위 문장 에러 처리: client no longer connected
            print(f"Error:{e}")
            clientSockets.pop(cs)
        else:  # recv 성공하면 메시지 처리
            if (msg_proc(cs, msg) == False):
                break  # 클라이언트가 종료하면 루프 탈출 후 스레드 종료

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