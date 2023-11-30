#client ID BR TO Q
import socket
from threading import Thread
from datetime import datetime

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

def listen_for_messages():
    while True:
        try:
            message = s.recv(BUF_SIZE).decode()
            print("\n" + message)
        except Exception as e:
            print(f"Error:{e}")

# make a thread that listens for messages to this client
t = Thread(target=listen_for_messages)
# make the thread daemon so it ends whenever the main thread ends
t.daemon = True
# start the thread
t.start()

# register of my ID to the Server

while True:
    myID = input("Enter your ID: ")
    to_Msg = "ID"+SEP+myID+SEP
    s.send(to_Msg.encode())
    # 성공 메시지를 확인하고 루프 탈출
    if "Success:Reg_ID":
        break
    #else:
        #print("ID registration failed. Please try again.")

while True:
    # input message we want to send to the server
    msg =  input()
    tokens = msg.split(SEP)
    code = tokens[0]
    # 명령어별 입력 형식 검증
    if code.upper() == "BR":
        if len(tokens) < 2:
            print("BR 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP + myID + SEP + tokens[1] + SEP
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
            to_Msg = code + SEP + myID + SEP + tokens[1] + SEP + tokens[2] + SEP
            s.send(to_Msg.encode())

    elif code == "FM":
        if len(tokens) < 4:
            print("FM 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP + myID + SEP + tokens[1] + SEP + tokens[2] + SEP + tokens[3] + SEP
            s.send(to_Msg.encode())

    elif code == "FD":
        if len(tokens) < 3:
            print("FD 명령 형식이 잘못되었습니다. 다시 시도해주세요.")
        else:
            to_Msg = code + SEP + myID + SEP + tokens[1] + SEP + tokens[2] + SEP
            s.send(to_Msg.encode())

    elif code.upper() == 'Q':
        to_Msg = "Quit" + SEP + myID + SEP
        s.send(to_Msg.encode())
        break

    else:
        print("형식이_올바르지_않습니다.")
    to_Msg = ''  # Initialization

# close the socket
s.close()
