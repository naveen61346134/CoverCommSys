import os
import sys
import socket
import platform
from threading import Thread, Event


FORMAT = "UTF-8"
RX_BUFFER = 4096
sys.setswitchinterval(0.005)
cCount = os.cpu_count()
uname = os.getlogin()
cs = list(platform.uname())
sysLog = f"{cs[0]} {cs[2]} {cs[3]} {cs[4]} {cCount} {uname}".encode(FORMAT)
shutdown = Event()
clientSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
addr = input("Enter server ip: ")
port = int(input("Enter port: "))
try:
    clientSoc.connect((addr, port))
    clientSoc.send(sysLog)
except ConnectionRefusedError:
    print("[-] Host machine refused to connect. Please check the IP!")
    exit(1)


def sendMsg():
    while not shutdown.is_set():
        try:
            msg = input(">>> ")
            clientSoc.send(msg.encode(FORMAT))
        except (KeyboardInterrupt, EOFError):
            print("[-] closing connection")
            shutdown.set()
        except ConnectionResetError:
            print("[-] Server has been shutdown!")
            shutdown.set()


def recieveMsg():
    while not shutdown.is_set():
        try:
            msg = clientSoc.recv(RX_BUFFER).decode(FORMAT)
            if not msg:
                print("[-] Server closed....")
                shutdown.set()
            else:
                print(msg)
        except ConnectionResetError:
            print("[-] Server has been shutdown!")
            shutdown.set()
        except KeyboardInterrupt:
            print("[-] closing connection")
            shutdown.set()
        except Exception as e:
            print(f"[-] Error occured: {e}")
            shutdown.set()


def main():
    init = clientSoc.recv(RX_BUFFER).decode(FORMAT)
    if init == "FULL":
        print("[-] Server is full.")
        exit(1)
    user = input("\nEnter username: ")
    clientSoc.send(user.encode(FORMAT))

    sendThread = Thread(
        target=sendMsg, daemon=True)
    sendThread.start()
    recieveThread = Thread(target=recieveMsg, daemon=True)
    recieveThread.start()

    sendThread.join()
    recieveThread.join()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[-] Closing connection!")
    finally:
        clientSoc.close()
        exit(0)
