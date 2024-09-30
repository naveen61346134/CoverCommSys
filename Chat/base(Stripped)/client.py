import socket
import threading

FORMAT = "UTF-8"
RX_BUFFER = 1024
shutdown = threading.Event()
clientSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
addr = input("Enter server ip: ")
port = 8080

try:
    clientSoc.connect((addr, port))
except ConnectionRefusedError:
    print("[-] Host machine refused to connect. Please check the IP!")
    exit(1)


def sendMsg():
    while not shutdown.is_set():
        try:
            msg = input().encode(FORMAT)
            clientSoc.send(msg)
        except KeyboardInterrupt:
            print("[-] closing connection")
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
        except KeyboardInterrupt:
            print("[-] closing connection")
            shutdown.set()
        except Exception as e:
            print(f"[-] Error occured: {e}")
            shutdown.set()


def main():
    user = input("\nEnter username: ").encode(FORMAT)
    clientSoc.send(user)

    sendThread = threading.Thread(
        target=sendMsg, daemon=True)
    sendThread.start()
    recieveThread = threading.Thread(target=recieveMsg, daemon=True)
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
