import socket
import threading
import base64
# python3에서 pycryto가 안되서 pycryptodome 사용
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome import Random
from Cryptodome.PublicKey import RSA

'''
사용 방법

서버 연결 : con {username}
공개키 교환 : pubkey {sender} {receiver}
대칭키 교환 : key {sender} {receiver}
메시지 전송 : send {sender} {receiver} {message}
서버 연결 종료 : discon {username}
'''

# 서버 연결정보; 자체 서버 실행시 변경 가능
SERVER_HOST = "homework.islab.work"
SERVER_PORT = 8080

connectSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connectSocket.connect((SERVER_HOST, SERVER_PORT))

# RSA 키 생성
rsa = RSA.generate(2048)
my_pri = rsa
my_pub = rsa.public_key().export_key()
# 상대의 공개키
pub_key = None

# AES 키 생성
my_key = Random.get_random_bytes(32)
my_iv = Random.get_random_bytes(16)
# 통신에 사용할 대칭키, iv
key = my_key
iv = my_iv
Block_Size = 32

# RSA 암복호화에 사용
enc = ''
dec = PKCS1_OAEP.new(my_pri)

def socket_read():
    while True:
        readbuff = connectSocket.recv(2048)

        if len(readbuff) == 0:
            continue

        recv_payload = readbuff.decode('utf-8')
        parse_payload(recv_payload)

def socket_send():
    while True:
        str = input("MESSAGE: ")
        command = parse_command(str)
        send_bytes = command.encode('utf-8')

        connectSocket.sendall(send_bytes)

def parse_payload(payload):
    # 수신된 페이로드를 여기서 처리; 필요할 경우 추가 함수 정의 가능
    # 전역변수 사용
    global enc, pub_key, aes, key, iv
    # 페이로드의 정보는 줄마다 구분되므로 한 줄씩 파싱
    lines = payload.split('\n')
    # method는 0번 줄에 공백 뒤에 있음 -> 3EPROTO METHOD
    command = lines[0].split()[1]

    # 키 교환 요청일 경우
    if command == 'KEYXCHG' or command == 'KEYXCHGRST':
        # 키 알고리즘은 1번 줄에 있음
        # 공개키 교환
        if lines[1].split(':')[1] == 'RSA':
            # 아직 키가 교환되지 않아 상대의 공개키가 없으면 공개키 교환
            if pub_key is None:
                send_payload = '3EPROTO KEYXCHG\nAlgo: RSA\nFrom: ' + lines[3].split(':')[1] \
                            + '\nTo: ' + lines[2].split(':')[1] + '\n\n' \
                            + my_pub.decode('utf-8')
                connectSocket.sendall(send_payload.encode('utf-8'))
                # RSA 키 저장 후 RSA 암호화 객체 생성
                pub_key = RSA.import_key('\n'.join(lines[6:]))
                enc = PKCS1_OAEP.new(pub_key)
            
            else:
                return None

        # 대칭키 전송
        elif lines[1].split(':')[1] == 'AES-256-CBC':
            # 개인키를 이용하여 복호화 후 저장
            key = dec.decrypt(bytes.fromhex(lines[6]))
            iv = dec.decrypt(bytes.fromhex(lines[7]))

    # 메시지는 payload의 마지막 줄에 있음
    # 따라서 마지막 줄을 base64로 디코딩 후 대칭키를 이용하여 복호화
    elif command == 'MSGRECV':
        try:
            aes = AES.new(key, AES.MODE_CBC, iv)
            msg = aes.decrypt(base64.b64decode(lines[-1])).decode('utf-8')
            print('msg from ' + lines[2].split(':')[1] + ': ' + msg)
        # 에러 발생 -> 인코딩, 디코딩, 암복호화에서 문제가 발생한 경우 메시지 처리 종료
        except:
            return None

    print('\n--------payload---------\n' + payload)

def parse_command(value):
    # 사용자의 입력을 이용하여 페이로드 생성
    command = value.split()
    result = ''
    # 페이로드가 아닐 경우
    if len(command) < 2:
        return value

    # 연결 요청
    if command[0] == 'con':
            result = '3EPROTO CONNECT\nCredential: ' + command[1]

    # 연결 종료 요청
    elif command[0] == 'discon':
        result = '3EPROTO DISCONNECT\nCredential: ' + command[1]

    # 공개키 교환
    elif command[0] == 'pubkey':
        result = '3EPROTO KEYXCHG\nAlgo: RSA\nFrom: ' + command[1] + '\nTo: ' + command[2] + '\n\n' \
                + my_pub.decode('utf-8')

    elif command[0] == 'pubkeyrst':
        result = '3EPROTO KEYXCHGRST\nAlgo: RSA\nFrom: ' + command[1] + '\nTo: ' + command[2] + '\n\n' \
                + my_pub.decode('utf-8')
        
    # 대칭키 교환
    elif command[0] == 'key':
        result = '3EPROTO KEYXCHG\nAlgo: AES-256-CBC\nFrom: ' + command[1] + '\nTo: ' + command[2] + '\n\n' \
                + bytes.hex(enc.encrypt(my_key)) + '\n' + bytes.hex(enc.encrypt(my_iv))

    elif command[0] == 'keyrst':
        result = '3EPROTO KEYXCHGRST\nAlgo: AES-256-CBC\nFrom: ' + command[1] + '\nTo: ' + command[2] + '\n\n' \
                + bytes.hex(enc.encrypt(my_key)) + '\n' + bytes.hex(enc.encrypt(my_iv))

    # 메시지 전송
    elif command[0] == 'send':
        aes = AES.new(key, AES.MODE_CBC, iv)
        nonce = base64.b64encode(Random.get_random_bytes(3))
        result = '3EPROTO MSGSEND\nFrom: ' + command[1] + '\nTo: ' + command[2] + '\nNonce: '+ nonce.decode('utf-8') + '\n\n' \
                + base64.b64encode(aes.encrypt(pad(command[3].encode('utf-8'), Block_Size))).decode('utf-8')

    return result

reading_thread = threading.Thread(target=socket_read)
sending_thread = threading.Thread(target=socket_send)

reading_thread.start()
sending_thread.start()

reading_thread.join()
sending_thread.join()