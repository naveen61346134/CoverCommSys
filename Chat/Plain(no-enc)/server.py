import socket
import logging
from threading import Thread, Lock, Event
from pyngrok import ngrok, conf, exception


clients = []
clientSysData = open("clientSystem.log", "a")
maxClients = 2
FORMAT = "UTF-8"
RX_BUFFER = 1024
clientLock = Lock()
shutdownServer = Event()
logging.basicConfig(filename='server.log', level=logging.INFO)
conf.get_default().log_event_callback = lambda log: logging.info(log)
ngrok.set_auth_token("2mtaFzCesO4Y1dEVRNfc2gJwXHx_4sGVXErgUUV8Q7zG5DUAk")

print("[*] Starting tcp server up....")
hostIP = socket.gethostbyname(socket.gethostname())
port = 8080
serverAddr = (hostIP, port)
serverSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serverSoc.settimeout(3)
try:
    serverSoc.bind(serverAddr)
except OSError:
    print("Please close existing socket!")
    exit(1)
print(f"[+] Local Server up and running!")
serverSoc.listen(maxClients)


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
                client.send(f"[{user}]: {msg}".encode(FORMAT))
            else:
                client.send(msg.encode(FORMAT))


def handleClient(cSoc: socket.socket, cIP):
    try:
        clientData = cSoc.recv(RX_BUFFER).decode(FORMAT)
        username = cSoc.recv(RX_BUFFER).decode(FORMAT)
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
            broadcast(msg, username)
        except OSError as e:
            if e.errno == 10038:
                print("[-] Invalid socket operation.")
                exit(1)
            elif e.errno == 10054:
                print("[-] Client disconnected!")
                clients.remove(cSoc)
                cSoc.close()
            else:
                print(f"Unexpected error: {e}")
                exit(1)
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
            clientSoc.send("PASS".encode(FORMAT))
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
