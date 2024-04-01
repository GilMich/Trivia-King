import errno
import socket as sock
import threading
import time

import select
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
def looking_for_a_server():
    print("Client started, listening for offer requests...")
    udp_socket = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
    udp_socket.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
    try:
        udp_socket.bind(('', 13117))
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            print("This port is already in use by a different process! trying to bind again...")
            return -1
        else:
            print("An unrecognized error has occurred during binding, trying to bind again...")
            return -2

    # Blocking method! it won't reach the next line until it detects a broadcast
    data, addr = udp_socket.recvfrom(1024)
    magic_cookie, message_type, server_name, server_port = unpack_packet(data)

    if magic_cookie != 0xabcddcba:
        print("No Magic cookie, nice try hacker!")
        return -3

    if message_type != 0x2:
        print("wtf this is not an offer message!")
        return -4

    server_ip = addr[0]
    print(f"Received offer from server '{server_name}'at address {addr[0]}, attempting to connect...")
    return server_name, server_ip, server_port


def connect_to_server(server_ip, server_port):
    # Create a TCP/IP socket
    tcp_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)

    try:
        # Connect the socket to the server's address and port
        tcp_socket.connect((server_ip, server_port))
        print(f"Successfully connected to the server at {server_ip}:{server_port}")

        # Immediately sends the player name before the game started.
        message = "Gil\n"
        tcp_socket.sendall(message.encode())
        return tcp_socket
    except sock.error as e:
        print(f"Failed to connect to the server at {server_ip}:{server_port}: {e}")
        return None


# Main client function
if __name__ == "__main__":
    while True:
        result_from_looking = looking_for_a_server()
        # Error Handling
        if type(result_from_looking) == int:
            time.sleep(1)
            continue
        elif type(result_from_looking) == tuple:
            break
    server_name, server_ip, server_port = result_from_looking
    server_tcp_socket = connect_to_server(server_ip, server_port)
    while True:
        time.sleep(1)