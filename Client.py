import errno
import socket as sock
import threading
import time

import select
import Server
import struct

def unpack_packet(data):
    # Define the format string for unpacking the packet
    # '>'  stands for big-endian, meaning the first decoded part of the packet will be stored in the first variable basically meaning that encoding happens from left to right

    # 'I' for the 4-byte magic cookie
    # 'B' for the 1-byte message type
    # '32s' for the 32-byte server name
    # 'H' for the 2-byte port number
    packet_format = '>IB32sH'

    # Unpack the data according to the specified format
    magic_cookie, message_type, server_name_raw, server_port = struct.unpack(packet_format, data)

    # Decode the server name to a string, stripping null bytes
    server_name = server_name_raw.decode().strip('\x00 ')


    return magic_cookie, message_type, server_name, server_port


# UDP Listener for server broadcast
def listen_for_offers():
    print("Client started, listening for offer requests...")
    udp_socket = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
    udp_socket.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR,1)
    while True:
        try:
            udp_socket.bind(('', 13117))
            break
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                print("This port is already in use by a different process! trying to bind again...")
                time.sleep(2)
                continue
            else:
                print("An unrecognized error has occurred during binding, trying to bind again...")

    while True:
        data, addr = udp_socket.recvfrom(1024)    # Blocking method! it won't reach the next line until it detects a broadcast
        magic_cookie, message_type, server_name, server_port = unpack_packet(data)
        if magic_cookie != 0xabcddcba:
            print("No Magic cookie detected, my name is gil michalovich you killed my father and I reject this cookie!")
            continue
        if message_type != 0x2:
            print("wtf this is not an offer message!")
            continue
        print(f"Received offer from server '{server_name}'at address {addr[0]}, attempting to connect...")
        time.sleep(1)
# TCP Connection to server
# def connect_to_server(server_ip, server_port):
#     tcp_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
#     tcp_socket.connect((server_ip, server_port))
#     tcp_socket.sendall(b'Client name\n')
#     while True:
#         ready_sockets, _, _ = select.select([tcp_socket], [], [], 0.1)
#         for socket in ready_sockets:
#             message = socket.recv(1024).decode()
#             print(message)
#             # Handle message


# Main client function
if __name__ == "__main__":
    listen_for_offers()