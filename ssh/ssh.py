#!/usr/bin/env python3.11
from abuseipdb import report_abuse
import socket, sys, threading, paramiko, telegram

def error(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

if len(sys.argv) < 2:
    error(f"Usage: {sys.argv[0]} <port>\n")
    sys.exit(1)

HOST_KEY = paramiko.RSAKey(filename='./ssh/cpot.key')
SSH_PORT = int(sys.argv[1])
BACKLOG = 10
LOGFILE = './logs/ssh.log' 
LOGFILE_LOCK = threading.Lock()

NOTIFIER = telegram.Telegram()

last_reported_ip = ""

class SSHServerHandler(paramiko.ServerInterface):
    def __init__(self, addr):
        self.event = threading.Event()
        self.client_addr = addr

    def report(self, comment: str):
        global last_reported_ip
        ip = self.client_addr[0]
        if ip != last_reported_ip:
            print("Reporting: " + ip)
            if report_abuse(ip, comment) == 200:
                print("REPORTED IP ", ip)
                last_reported_ip = ip
            else:
                print('EROR reporting ip')

    def check_auth_password(self, username, password):
        LOGFILE_LOCK.acquire()
        try:
            atk = f"{self.client_addr[0]}:{username}:{password}\n"
            print(atk)
            NOTIFIER.send_notification(f"SSH BRUTER - {atk}")

            self.report(f"SSH brute force attempt at port {SSH_PORT}")

            with open(LOGFILE, "a+") as logfile:
                logfile.write(atk)
        finally:
            LOGFILE_LOCK.release()
        return paramiko.AUTH_FAILED


    def get_allowed_auths(self, username):
        return 'password'

def handleConnection(client, addr):
    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)

    server_handler = SSHServerHandler(addr)

    transport.start_server(server=server_handler)

    channel = transport.accept(1)
    if not channel is None:
        channel.close()

def main():
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', SSH_PORT))
        server_socket.listen(BACKLOG)
        print(f"[ssh] ssh listening on {SSH_PORT}")

        while(True):
            try:
                client_socket, client_addr = server_socket.accept()
                threading.Thread(target=handleConnection, args=(client_socket,client_addr)).start()
            except Exception as e:
                error("ERROR: Client handling")

    except Exception as e:
        error("ERROR: Failed to create socket")
        error(e)
        sys.exit(1)

main()
