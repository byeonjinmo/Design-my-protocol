#client ID BR TO Q
import socket
from threading import Thread
import time
# 반드시 시작 시 FIRST_SF
# server's IP address
# if the server is not on this machine,
# put the private (network) IP address (e.g 192.168.1.2)
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5001 # 서버 포트
BUF_SIZE = 1024 # 버퍼 크기
SEP = ":" # 구분자

# initialize TCP socket
s = socket.socket()
print(f"[*] Connecting to {SERVER_HOST}:{SERVER_PORT}...")
# connect to the server
s.connect((SERVER_HOST, SERVER_PORT))
print("[+] Connected.")

# 사용자가 ID를 성공적으로 등록했는지 여부를 확인
id_registered = False
# 서버로부터 받은 응답을 해석
def parse_custom_response(response):
    parsed_data = {}
    elements = response.split(";")
    for element in elements:
        if "=" in element:
            key, value = element.split("=")
            parsed_data[key] = value
        else:
            print(f"Unexpected format: {element}")
    return parsed_data
# 서버로부터 메시지를 수신하고 처리하는 함수 별도의 스레드에서 실행됨.
def listen_for_messages():
    global id_registered
    while True:
        try:
            message = s.recv(BUF_SIZE).decode()
            if message == "":
                print("서버로부터 연결이 끊어졌습니다.")
                break

            if ";" in message:
                parsed_response = parse_custom_response(message)

                status = parsed_response.get("status", "Unknown_status")
                action = parsed_response.get("action", "No_action")
                additional_message = parsed_response.get("message", "No_additional_message_provided")

                if status == "Success" and action == "ID_Registration":
                    id_registered = True

                print(f"Status: {status}, Action: {action}, Message: {additional_message}")
            else:
                print(message)
        except Exception as e:
            print(f"Error: {e}")
            break

# 서버로부터 메시지를 듣는 스레드를 생성 및 시작
t = Thread(target=listen_for_messages)
t.daemon = True
t.start()
# 사용자로부터 명령어를 입력받아 서버에 전송하는 메인 루프 / Q 누르기 전까지 소켓 지속.
while True:
    print("필터링 설정된 단어가 있을 수 있습니다.먼저 FIRST_SF(SHOW_FILTER_KEYWORD)를 입력하여 확인해주세요.")
    msg = input()
    tokens = msg.split(SEP)
    code = tokens[0]
    if code.upper() == "FIRST_SF":
        if len(tokens) < 1 or len(tokens) > 1:
            print("FIRST_SF 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP
            s.send(to_Msg.encode())
            break

while True:
    time.sleep(1)  # 1초 대기
    myID = input("Enter your ID: ")
    to_Msg = "ID" + SEP + myID + SEP
    s.send(to_Msg.encode())
    break
while True:
    msg =  input()
    tokens = msg.split(SEP)
    code = tokens[0]
    # 명령어별 입력 형식 검증
    if code.upper() == "BR":
        if len(tokens) < 2 or len(tokens) > 2:
            print("BR 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP + myID + SEP + tokens[1] + SEP
            s.send(to_Msg.encode())
    elif code.upper() == "ID":
        if len(tokens) < 2 or len(tokens) > 2:
            print("ID 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        elif id_registered:
                print("You_already_have_a_username._You_cannot_use_the_ID_command_again.")
                continue
        else:
            to_Msg = "ID" + SEP + tokens[1] + SEP
            s.send(to_Msg.encode())

    elif code.upper() == "TO":
        if len(tokens) < 3 or len(tokens) > 3:
            print("TO 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP + myID + SEP + tokens[1] + SEP + tokens[2] + SEP
            s.send(to_Msg.encode())

    elif code == "FILTER":
        if len(tokens) < 3 or len(tokens) > 3:
            print("FILTER 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP + tokens[1] + SEP + tokens[2] + SEP
            s.send(to_Msg.encode())

    elif code == "FM":
        if len(tokens) < 4 or len(tokens) > 4:
            print("FM 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP + tokens[1] + SEP + tokens[2] + SEP + tokens[3] + SEP
            s.send(to_Msg.encode())

    elif code == "FD":
        if len(tokens) < 3 or len(tokens) > 3:
            print("FD 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code +  SEP + tokens[1] + SEP + tokens[2] + SEP
            s.send(to_Msg.encode())

    elif code.upper() == 'Q':
        to_Msg = "Q" + SEP + myID + SEP
        s.send(to_Msg.encode())
        break
    if code.upper() == "SF":
        if len(tokens) < 2 or len(tokens) > 2:
            print("SF 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP + tokens[1] + SEP
            s.send(to_Msg.encode())

    to_Msg = ''  # 초기화

# 소켓 종료
s.close()