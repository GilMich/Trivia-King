import errno
import socket as sock
import sys
import time
import struct
import threading
import queue


def handle_socket_error(exception, operation, function):
    """
    Handles exceptions raised during socket operations.

    Args:
    exception: The exception instance that was raised.
    operation: A string describing the socket operation during which the error occurred.
    function: A string indicating the function name where the error occurred.

    This function prints a detailed error message based on the type of socket exception, the operation, and the function where it happened.
    """
    error_type = type(exception).__name__
    error_message = str(exception)

    print(f"Error occurred in function '{function}' during {operation}.")
    print(f"Error Type: {error_type}")
    print(f"Error Details: {error_message}")

    if isinstance(exception, sock.timeout):
        print("This was a timeout error. Please check network conditions and retry.")
    elif isinstance(exception, sock.error):
        print("A general socket error occurred. Please check the socket operation and parameters.")
    elif isinstance(exception, sock.gaierror):
        print("An address-related error occurred. Please verify the network address details.")
    elif isinstance(exception, sock.herror):
        print("A host-related error occurred. Check DNS configurations and host availability.")
    else:
        print("An unexpected type of error occurred. Please consult system logs or network settings.")


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
    print(f'Received offer from server "{server_name}" at address {addr[0]}, attempting to connect...')
    return server_name, server_ip, server_port


def connect_to_server(server_ip, server_port) -> sock:
    # Create a TCP/IP socket
    tcp_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)

    try:
        # Connect the socket to the server's address and port
        tcp_socket.connect((server_ip, server_port))

    except sock.error as e:
        print(f"Failed to connect to the server at {server_ip}:{server_port}: {e}")
        return None

    print(f"Successfully connected to the server at {server_ip}:{server_port}")
    # Immediately sends the player name before the game started.
    player_name = input("Please enter your name: \n")
    name_message = f"{player_name}\n"
    tcp_socket.sendall(name_message.encode())

    return tcp_socket


def print_welcome_message(server_tcp_socket: sock) -> None:
    message_encoded = server_tcp_socket.recv(1024)
    message_decoded = message_encoded.decode('utf-8')
    print(message_decoded)


def print_trivia_question(server_tcp_socket: sock):
    message_encoded = server_tcp_socket.recv(1024)
    message_decoded = message_encoded.decode('utf-8')
    print(message_decoded)


def get_input(input_queue, valid_keys, stop_event):
    while not stop_event.is_set():
        user_input = input(
            "enter [1, t, y] for True, [0, f, n] for False:")  # user can screw up the program here if he doesn't hit enter the thread will stay alive forever
        if user_input in valid_keys:
            input_queue.put(user_input)
            break
        else:
            print("Invalid input. Please try again.")


def get_answer_from_user() -> bool | None:
    valid_true_keys = ["1", "t", "T", "y", "Y"]
    valid_false_keys = ["0", "f", 'F', 'n', 'N']
    valid_keys = valid_true_keys + valid_false_keys
    stop_event = threading.Event()
    # Function to get input from the user and put it in a queue in a separate thread

    # Create a queue
    input_queue = queue.Queue()

    # Start the thread
    input_thread = threading.Thread(target=get_input, args=(input_queue, valid_keys, stop_event))
    input_thread.start()
    try:
        # Try to get input within 10 seconds
        user_input = input_queue.get(block=True, timeout=20)
    except queue.Empty:
        # If no input was received within 10 seconds, print a message
        print("No input received within 10 seconds.")
        user_input = None
        # Set the stop event to stop the input thread
        stop_event.set()
    if user_input is None:
        return None

    elif user_input in valid_true_keys:
        return True

    elif user_input in valid_false_keys:
        return False


def send_answer_to_server(server_tcp_socket, user_answer):
    """
    Sends the user's answer to the server and checks if the operation was successful.
    Returns True if the message was sent successfully, False otherwise.
    """
    try:
        # Prepare the message
        if user_answer is None:
            message = "none"
        elif user_answer:
            message = "true"
        else:
            message = "false"

        # Send the message
        server_tcp_socket.sendall(message.encode())
        return True

    except sock.error as e:
        # Print the error and return False if an error occurred
        print(f"Failed to send answer to server: {e}")
        return False


# Main client function
if __name__ == "__main__":
    gameOn = True
    server_tcp_socket = None

    while gameOn:
        if server_tcp_socket is None:
            server_name, server_ip, server_port = looking_for_a_server()
            server_tcp_socket = connect_to_server(server_ip, server_port)
            if server_tcp_socket is None:
                time.sleep(1)
                continue  # If connection fails, restart the loop to try again
            print_welcome_message(server_tcp_socket)

        try:
            print_trivia_question(server_tcp_socket)
            user_answer = get_answer_from_user()
            if not send_answer_to_server(server_tcp_socket, user_answer):
                raise ConnectionError("Lost connection to the server. Attempting to reconnect...")

            user_input = input("Do you want to play another round? (yes/no): ")
            if user_input.lower() != "yes":
                gameOn = False
                break
            continue
        except (sock.error, ConnectionError) as e:
            print(e)
            if server_tcp_socket:
                server_tcp_socket.close()
            server_tcp_socket = None  # Reset the connection

    if server_tcp_socket:
        server_tcp_socket.close()
        print("Disconnected from the server.")

    # todo missing function to send the answer to the server