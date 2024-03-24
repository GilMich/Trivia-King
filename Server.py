import socket as sock
import threading
import time
import netifaces
from random import choice


def get_local_ip():
    """
    Retrieves the local IP address of the machine.
    """
    s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
    s.connect(('10.255.255.255', 1))  # dummy connect
    ip = s.getsockname()[0]
    return ip


def get_default_broadcast():
    # Get the default gateway interface
    gws = netifaces.gateways()
    default_gateway = gws['default'][netifaces.AF_INET][1]
    # Get the addresses associated with the default interface
    addrs = netifaces.ifaddresses(default_gateway)
    # Get the IPv4 addresses
    ipv4_addrs = addrs[netifaces.AF_INET]
    # Get the first IPv4 address
    first_ipv4_addr = ipv4_addrs[0]
    # Get the broadcast address from the first IPv4 address info
    broadcast = first_ipv4_addr['broadcast']

    return broadcast


# Server UDP Broadcast

def udp_broadcast(server_port, server_name):
    broadcast_address = get_default_broadcast()
    port = 13117

    udp_socket = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
    udp_socket.setsockopt(sock.SOL_SOCKET, sock.SO_BROADCAST, 1)

    # Prepare the message according to the specified packet format
    magic_cookie = 0xabcddcba
    message_type = 0x2  # Offer message
    server_name_padded = server_name.ljust(32)  # Ensure the server name is 32 characters long
    message = magic_cookie.to_bytes(4, 'big') + message_type.to_bytes(1,
                                                                      'big') + server_name_padded.encode() + server_port.to_bytes(
        2, 'big')

    while True:
        ip = get_local_ip()
        udp_socket.sendto(message, (broadcast_address, port))
        print(f"Server started, listening on IP address: {ip}")
        time.sleep(1)


# Handle client
# def handle_client(client_socket):
#     try:
#         while True:
#             message = client_socket.recv(1024).decode()
#             if not message:
#                 break
#             # Process message
#     finally:
#         client_socket.close()
#
#
# # TCP Server
# def tcp_server():
#     server_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
#     server_socket.bind(('', 0))  # 0 means any available port
#     server_socket.listen()
#     print(f"Server started listening on {server_socket.getsockname()}")
#
#     while True:
#         client_socket, addr = server_socket.accept()
#         print(f"Connection from {addr}")
#         client_thread = threading.Thread(target=handle_client, args=(client_socket,))
#         client_thread.start()


# Main server function
def main_server():
    threading.Thread(target=udp_broadcast).start()
    udp_broadcast()


if __name__ == "__main__":
    udp_broadcast(13117, "Trivia King")
