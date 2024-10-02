import base64
import string
import random
import socket
import threading

clients = []
maxClients = 2
FORMAT = "UTF-8"
RX_BUFFER = 1024
clientLock = threading.Lock()
shutdownServer = threading.Event()
print("[*] Starting tcp server up....")
hostIP = socket.gethostbyname(socket.gethostname())
port = 8080
serverAddr = (hostIP, port)
serverSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serverSoc.settimeout(1)
try:
    serverSoc.bind(serverAddr)
except OSError:
    print("Please close existing socket!")
    exit(1)
print(f"[+] Local Server up and running!")
serverSoc.listen(maxClients)

chars = list(string.ascii_lowercase + string.ascii_uppercase +
             string.digits + string.punctuation + " " + "\n")
keyChars = chars.copy()
random.shuffle(keyChars)


def sendKey(soc: socket.socket):
    kstr = "".join(keyChars)
    baseKey = base64.b64encode(kstr.encode(FORMAT)).decode(FORMAT)
    soc.send(baseKey.encode(FORMAT))


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


def broadcast(msg: str, user=None):
    with clientLock:
        for client in clients:
            if user != None:
                encMsg = encryptMsg(keyChars, f"[{user}]: {msg}")
                client.send(encMsg.encode(FORMAT))
            else:
                client.send(encryptMsg(keyChars, msg).encode(FORMAT))


def handleClient(cSoc: socket.socket):
    cSoc.send("KEY".encode(FORMAT))
    sendKey(cSoc)
    print(f"[+] Send Encryption Key Size: {len(keyChars)}")
    try:
        username = decryptMsg(keyChars, cSoc.recv(RX_BUFFER).decode(FORMAT))
    except ConnectionResetError:
        print("[-] Client disconnected!\n")
        clients.remove(cSoc)
        cSoc.close()
    print(f"[+] {username} joined the server")
    broadcast(f"[+] {username} joined the chat\n")
    while True:
        try:
            msg = cSoc.recv(RX_BUFFER).decode(FORMAT)
            decMsg = decryptMsg(keyChars, msg)
            broadcast(decMsg, username)
        except ConnectionResetError:
            print("[-] Client disconnected!\n")
            clients.remove(cSoc)
            cSoc.close()
        except:
            with clientLock:
                clients.remove(cSoc)
                cSoc.close()
            print(f"[*] {username} left the server")
            broadcast(f"{username} left the chat")
            break


def main():
    global clients
    while not shutdownServer.is_set():
        try:
            clientSoc, clinetIP = serverSoc.accept()
            if len(clients) >= maxClients:
                print(
                    f"\n[*] {clinetIP} trying to connect (MAX CLIENT ERROR)\n")
                clientSoc.send(
                    "FULL".encode(FORMAT))
                clientSoc.close()
                continue
            print(f"\n[+] Got connection from {clinetIP[0]}!")
            with clientLock:
                clients.append(clientSoc)
            clientThread = threading.Thread(
                target=handleClient, args=(clientSoc,))
            clientThread.start()
        except socket.timeout:
            continue
        except Exception as e:
            print(f"[-] Error occured: {e}")


if __name__ == "__main__":
    print(f"\n[+] Local Server listening on {hostIP}@{port}")
    try:
        main()
    except KeyboardInterrupt:
        shutdownServer.set()
    finally:
        with clientLock:
            if clients:
                print("[-] Closing off all clients")
                for client in clients:
                    client.close()
        serverSoc.close()
        print("[+] Server Closed!")
