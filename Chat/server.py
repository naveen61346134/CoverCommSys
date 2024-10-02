import socket
import logging
from random import shuffle
from base64 import b64encode
from threading import Thread, Lock, Event
from pyngrok import ngrok, conf, exception
from string import ascii_lowercase, ascii_uppercase, digits, punctuation


clients = []
clientSysData = open("clientSystem.log", "a")
maxClients = 2
FORMAT = "UTF-8"
RX_BUFFER = 1024
clientLock = Lock()
shutdownServer = Event()
logging.basicConfig(filename='server.log', level=logging.INFO)
conf.get_default().log_event_callback = lambda log: logging.info(log)
ngrok.set_auth_token("YOUR-TOKEN")

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

chars = list(ascii_lowercase + ascii_uppercase +
             digits + punctuation + " " + "\n")
keyChars = chars.copy()
shuffle(keyChars)


def sendKey(soc: socket.socket):
    kstr = "".join(keyChars)
    baseKey = b64encode(kstr.encode(FORMAT)).decode(FORMAT)
    print("\t[=]SENDING KEY")
    soc.send(baseKey.encode(FORMAT))
    print("\t[=]Waiting for log")
    info = soc.recv(RX_BUFFER).decode(FORMAT)
    print(decryptMsg(keyChars, info))
    return decryptMsg(keyChars, info)


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


def createTunnel():
    print("\n[*] Exposing local server to the internet")
    try:
        listener = ngrok.connect(f"{hostIP}:{port}", "tcp")
        ngrokIP, ngrokPort = listener.public_url.split("//")[1].split(":")
        ngrokIP = socket.gethostbyname(ngrokIP)
        ngrokPort = int(ngrokPort)
    except exception.PyngrokNgrokError:
        print("[-] No internet access!")
        exit(1)
    else:
        print(f"[+] Local Server listening on {ngrokIP}@{ngrokPort}")
        return listener


def broadcast(msg: str, user=None):
    with clientLock:
        for client in clients:
            if user != None:
                encMsg = encryptMsg(keyChars, f"[{user}]: {msg}")
                client.send(encMsg.encode(FORMAT))
            else:
                client.send(encryptMsg(keyChars, msg).encode(FORMAT))


def handleClient(cSoc: socket.socket, cIP):
    cSoc.send("KEY".encode(FORMAT))
    clientData = sendKey(cSoc)
    print(f"[+] Send Encryption Key Size: {len(keyChars)}")
    try:
        username = decryptMsg(keyChars, cSoc.recv(RX_BUFFER).decode(FORMAT))
    except ConnectionResetError:
        print("[-] Client disconnected!\n")
        clients.remove(cSoc)
        cSoc.close()
    clientSysData.write(f"{username}@{cIP} : {clientData}\n")
    clientSysData.flush()
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
            clientThread = Thread(
                target=handleClient, args=(clientSoc, clinetIP))
            clientThread.start()
        except socket.timeout:
            continue
        except Exception as e:
            print(f"[-] Error occured: {e}")


if __name__ == "__main__":
    ie = input("[*] Do you want to host the server on the internet[y/n]: ")
    listener = ""
    if ie not in ["n", "N"]:
        listener = createTunnel()
    else:
        print(f"\n[+] Local Server listening on {hostIP}@{port}")
    try:
        main()
    except KeyboardInterrupt:
        shutdownServer.set()
    finally:
        clientSysData.close()
        print("\n[-] Shutting down the server!")
        if isinstance(listener, ngrok.NgrokTunnel):
            ngrok.disconnect(listener.public_url)
            print("[-] Server seperated from internet!")
        with clientLock:
            if clients:
                print("[-] Closing off all clients")
                for client in clients:
                    client.close()
        serverSoc.close()
        print("[+] Server Closed!")
