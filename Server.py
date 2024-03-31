import socket
import socket as sock
import threading
import time
import netifaces
from random import choice
from concurrent.futures import ThreadPoolExecutor

active_clients = {}
last_connection_time = time.time()
time_lock = threading.Lock()


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


# Finds an available tcp port for the server to send to the client in the UDP broadcast message, on which the server will listen on, and the client will connect to.
def find_free_port():
    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as s:
        s.bind(('', 0))  # Binding to port 0 tells the OS to pick an available port
        return s.getsockname()[1]  # Return the port number assigned by the OS


def udp_broadcast(server_name, server_port, stop_event):
    broadcast_address = get_default_broadcast()

    # Sets a socekt instance for udp broadcasting
    udp_socket = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
    udp_socket.setsockopt(sock.SOL_SOCKET, sock.SO_BROADCAST, 1)

    # Prepare the message according to the specified packet format
    magic_cookie = 0xabcddcba
    message_type = 0x2  # Offer message
    server_name_padded = server_name.ljust(32)  # Ensure the server name is 32 characters long
    message = magic_cookie.to_bytes(4, 'big') + message_type.to_bytes(1,
                                                                      'big') + server_name_padded.encode() + server_port.to_bytes(
        2, 'big')

    # Broadcast
    while not stop_event.is_set():
        ip = get_local_ip()
        udp_socket.sendto(message, (broadcast_address, 13117))
        time.sleep(2)  # sleep to avoid busy waiting


def save_client_info(client_socket, client_address):
    global active_clients
    if client_address not in active_clients:
        # Receive data from the client
        received_data = client_socket.recv(1024)  # Adjust buffer size as needed
        client_name = received_data.decode('utf-8').rstrip('\n')
        active_clients[client_address] = {"name": client_name, "socket": client_socket}  # Might need a lock here in the future


def watch_for_inactivity(stop_event):
    global last_connection_time
    while not stop_event.is_set():
        with time_lock:
            elapsed = time.time() - last_connection_time
        if elapsed >= 10:
            print("Timeout reached without new connections. Stopping server.")
            stop_event.set()
            break
        else:
            # Sleep briefly to avoid busy waiting
            time.sleep(1)


def tcp_listener(server_port, stop_event):
    server_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    server_socket.bind(('', server_port))  # Bind to the specified port on all interfaces
    server_socket.listen()  # Listen for incoming connections
    server_socket.settimeout(10)  # timeout for accepting new requests
    print(f"Server is listening for TCP connections on port {server_port}")

    while not stop_event.is_set():
        try:
            client_socket, client_address = server_socket.accept()  # blocking method to accept new connection. if it waits here more than 10sec it will go to except
            print(f"Accepted a connection from {client_address}")
            with time_lock:
                global last_connection_time
                last_connection_time = time.time()
            # Handle the connection in a new thread
            threading.Thread(target=save_client_info, args=(client_socket, client_address)).start()
            threading.Thread(target=watch_for_inactivity, args=(stop_event,)).start()
        except socket.timeout:
            continue  # just loop back to check the stop event which will probably be set on.


if __name__ == "__main__":
    stop_event = threading.Event()
    server_port = find_free_port()
    # Initialize threads
    print(f"Server started, listening on IP address: {get_local_ip()}")
    udp_thread = threading.Thread(target=udp_broadcast, args=("Trivia King", server_port, stop_event))
    tcp_thread = threading.Thread(target=tcp_listener, args=(server_port, stop_event))

    # Start threads
    udp_thread.start()
    tcp_thread.start()

    # Wait for the stop_event to be set
    while not stop_event.is_set():
        stop_event.wait(timeout=5)  # wait to avoid busy waiting

    # Ensure both udp thread and tcp thread completed
    udp_thread.join()
    tcp_thread.join()

    print(active_clients)

    # Game mode !