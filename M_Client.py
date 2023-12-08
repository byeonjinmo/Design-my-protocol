#client ID BR TO Q
import socket
from threading import Thread
import time
# 반드시 시작FIRST_SF
# server's IP address
# if the server is not on this machine,
# put the private (network) IP address (e.g 192.168.1.2)
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5001 # server's port
BUF_SIZE = 1024
SEP = ":" # we will use this to separate the client name & message

# initialize TCP socket
s = socket.socket()
print(f"[*] Connecting to {SERVER_HOST}:{SERVER_PORT}...")
# connect to the server
s.connect((SERVER_HOST, SERVER_PORT))
print("[+] Connected.")

# 이 변수는 사용자가 ID를 성공적으로 등록했는지 여부를 추적합니다.
id_registered = False
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

                status = parsed_response.get("status", "Unknown status")
                action = parsed_response.get("action", "No action")
                additional_message = parsed_response.get("message", "No additional message provided")

                if status == "Success" and action == "ID_Registration":
                    id_registered = True

                print(f"Status: {status}, Action: {action}, Message: {additional_message}")
            else:
                print(message)
        except Exception as e:
            print(f"Error: {e}")
            break

# make a thread that listens for messages to this client
t = Thread(target=listen_for_messages)
# make the thread daemon so it ends whenever the main thread ends
t.daemon = True
# start the thread
t.start()
# register of my ID to the Server
while True:
    print("필터링 설정된 단어가 있을 수 있습니다.먼저 FIRST_SF(SHOW_FILTER_KEYWORD)를 입력하여 확인해주세요.")
    msg = input()
    tokens = msg.split(SEP)
    code = tokens[0]
    if code.upper() == "FIRST_SF":
        if len(tokens) < 1:
            print("FIRST_SF 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP
            s.send(to_Msg.encode())
            break

while True:
    # input message we want to send to the server
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
        if len(tokens) < 2:
            print("BR 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP + tokens[1] + SEP
            s.send(to_Msg.encode())
    elif code.upper() == "ID":
        if len(tokens) < 2:
            print("ID 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        elif id_registered:
                print("You have already registered your ID. No need to register again.")
                continue
        else:
            to_Msg = "ID" + SEP + tokens[1] + SEP
            s.send(to_Msg.encode())

    elif code.upper() == "TO":
        if len(tokens) < 3:
            print("TO 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP + myID + SEP + tokens[1] + SEP + tokens[2] + SEP
            s.send(to_Msg.encode())

    elif code == "FILTER":
        if len(tokens) < 3:
            print("FILTER 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP + tokens[1] + SEP + tokens[2] + SEP
            s.send(to_Msg.encode())

    elif code == "FM":
        if len(tokens) < 4:
            print("FM 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP + tokens[1] + SEP + tokens[2] + SEP + tokens[3] + SEP
            s.send(to_Msg.encode())

    elif code == "FD":
        if len(tokens) < 3:
            print("FD 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code +  SEP + tokens[1] + SEP + tokens[2] + SEP
            s.send(to_Msg.encode())

    elif code.upper() == 'Q':
        to_Msg = "Q" + SEP + myID + SEP
        s.send(to_Msg.encode())
        break
    if code.upper() == "SF":
        if len(tokens) < 2:
            print("SF 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP + tokens[1] + SEP
            s.send(to_Msg.encode())

    to_Msg = ''  # Initialization

# close the socket
s.close()