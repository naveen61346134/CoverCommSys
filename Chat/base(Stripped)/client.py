import base64
import string
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

chars = list(string.ascii_lowercase + string.ascii_uppercase +
             string.digits + string.punctuation + " " + "\n")
keyChars = list()


def recieveKey():
    global keyChars
    keyStr = clientSoc.recv(RX_BUFFER).decode(FORMAT)
    keyChars = list(base64.b64decode(keyStr).decode(FORMAT))
    print(f"[+] Recieved Encryption Key Size : {len(keyChars)}")


def encryptMsg(key: list, msg: str):
    global chars
    encList = [key[chars.index(char)] for char in msg]
    encMsg = "".join(encList)
    return encMsg


def decryptMsg(key: list, msg: str):
    global chars
    decList = [chars[key.index(char)] for char in msg]
    decMsg = "".join(decList)
    return decMsg


def sendMsg():
    while not shutdown.is_set():
        try:
            msg = input()
            encMsg = encryptMsg(keyChars, msg)
            clientSoc.send(encMsg.encode(FORMAT))
        except KeyboardInterrupt:
            print("[-] closing connection")
            shutdown.set()


def recieveMsg():
    while not shutdown.is_set():
        try:
            msg = clientSoc.recv(RX_BUFFER).decode(FORMAT)
            if msg == "FULL":
                print("[-] Server is full.")
                shutdown.set()
            decMsg = decryptMsg(keyChars, msg)

            if not msg:
                print("[-] Server closed....")
                shutdown.set()
            else:
                print(decMsg)
        except KeyboardInterrupt:
            print("[-] closing connection")
            shutdown.set()
        except ConnectionResetError:
            print("[-] Server has been shutdown!")
            shutdown.set()
        except Exception as e:
            print(f"[-] Error occured: {e}")
            shutdown.set()


def main():
    init = clientSoc.recv(RX_BUFFER).decode(FORMAT)
    if init == "FULL":
        print("[-] Server is full.")
        exit(1)
    elif init == "KEY":
        recieveKey()
    user = input("\nEnter username: ")
    clientSoc.send(encryptMsg(keyChars, user).encode(FORMAT))

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
