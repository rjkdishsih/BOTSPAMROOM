import socket
import select
import threading
import time

SOCKS_VERSION = 5
USERNAME = "bot"
PASSWORD = "bot"

packet_to_send = bytes.fromhex(
    "0e15000000300ff19bf14439d9df909cca50a22e48cc7a7e8d4825b1801c95519faf9438d6ae87db5a66e6667fc587910f04acef835a"
)

trigger_code = "0515"  # الكود الذي نتحقق منه عند استقبال البيانات


def handle_client(connection):
    version, nmethods = connection.recv(2)
    methods = [connection.recv(1)[0] for _ in range(nmethods)]
    if 2 not in methods:
        connection.close()
        return

    connection.sendall(bytes([SOCKS_VERSION, 2]))
    if not verify(connection):
        return

    version, cmd, _, address_type = connection.recv(4)
    if address_type == 1:
        address = socket.inet_ntoa(connection.recv(4))
    elif address_type == 3:
        domain_length = connection.recv(1)[0]
        address = socket.gethostbyname(connection.recv(domain_length).decode())

    port = int.from_bytes(connection.recv(2), 'big', signed=False)
    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote.connect((address, port))

    bind_address = remote.getsockname()
    addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
    port = bind_address[1]
    reply = b"".join([
        SOCKS_VERSION.to_bytes(1, 'big'),
        int(0).to_bytes(1, 'big'),
        int(0).to_bytes(1, 'big'),
        int(1).to_bytes(1, 'big'),
        addr.to_bytes(4, 'big'),
        port.to_bytes(2, 'big')
    ])
    connection.sendall(reply)

    exchange_loop(connection, remote)


def verify(connection):
    version = connection.recv(1)[0]
    username_len = connection.recv(1)[0]
    username_received = connection.recv(username_len).decode()
    password_len = connection.recv(1)[0]
    password_received = connection.recv(password_len).decode()

    if username_received == USERNAME and password_received == PASSWORD:
        connection.sendall(bytes([version, 0]))
        return True

    connection.sendall(bytes([version, 0xFF]))
    connection.close()
    return False


def exchange_loop(client, remote):
    while True:
        try:
            r, _, _ = select.select([client, remote], [], [])
            if client in r:
                data = client.recv(4096)
                if not data:
                    break

                hex_data = data.hex()
                print(f"Received from client: {hex_data}")

                if trigger_code in hex_data:
                    print("Trigger code detected! Waiting 3 seconds before sending the packet...")
                    time.sleep(3)
                    client.sendall(packet_to_send)
                    print("Packet sent!")

                remote.sendall(data)

            if remote in r:
                data = remote.recv(4096)
                if not data:
                    break

                client.sendall(data)
        except Exception as e:
            print(f"Error in exchange_loop: {e}")
            break


def run(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen()
    print(f"Proxy running on {host}:{port}")

    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn,))
        t.start()


def start_bot():
    run("127.0.0.1", 3000)
if __name__ == "__main__":
    start_bot()
