# 6_server_thd
# 다중 클라이언트로 부터 메시지를 받아서 브로드캐스트
# 클라이언트가 exit 문자열이 보내올때까지 계속 수신
# exit 문자열을 수신하면 while 문 탈출하여 연결종료

from socket import *    # import socket 으로 하면 오류
from select import *
from threading import Thread

HOST = ''
PORT = 10000
BUFSIZE = 1024
ADDR = (HOST, PORT)

# 연결된 client의 소켓 집합 set of connected client sockets
clientSockets = set()

# 소켓 생성
serverSocket = socket(AF_INET, SOCK_STREAM)
##     socket.socket(socket.AF_INET, socket.SOCK_STREAM)


# 소켓 주소 정보 할당
serverSocket.bind(ADDR)
print('바인드')

# 연결 수신 대기 상태
serverSocket.listen(10)
print('대기')

def client_com(cs):
    # 클라이언트로부터 메시지를 가져옴
    while True:
        try:  # 아래 문장 무조건 실행
            msg = cs.recv(BUFSIZE).decode()
            #print('recieve data : ',msg)
        except Exception as e:  # 위 문장 에러 처리: client no longer connected
            print(f"Error:{e}")
            clientSockets.remove(cs)
        else:  # 위 문장 에러 없을 시 실행
            if msg == 'exit': # exit라는 메세지를 받으면 정상종료
                cs.close()
                clientSockets.remove(cs)
                break
            print('broadcast data : ',msg)
            i=1;
            for socket in clientSockets: # broadcast
                socket.send(msg.encode())
                print(i)
                i=i+1

# 연결 수락
while True:
    clientSocekt, addr_info = serverSocket.accept()
    print('연결 수락: client 정보 ', addr_info)
    clientSockets.add(clientSocekt)
    t = Thread(target = client_com, args=(clientSocekt,))
    t.daemon = True
    t.start()

# 소켓 종료
for cs in clientSockets:
    cs.close()
serverSocket.close()
print('종료')