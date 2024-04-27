import errno
import socket as sock
import sys
import time
import struct
import threading
import queue


def print_red(message):
    print(f"\033[31m{message}\033[0m")


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


def connect_to_server(server_ip, server_port):
    """
    Establishes a TCP connection to the trivia game server at the specified IP address and port.

    Args:
        server_ip (str): The IP address of the server.
        server_port (int): The port number on which the server is listening.

    Returns:
        socket.socket: The connected TCP socket if successful, or None if the connection fails.
    """
    # Create a TCP/IP socket
    tcp_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    try:
        # Connect the socket to the server's address and port
        tcp_socket.connect((server_ip, server_port))
    except OSError as e:
        print(f"A {type(e)} occurred while trying to connect to the server with tcp: {e}\n")

    print(f"Successfully connected to the server at {server_ip}:{server_port} \n")
    # Immediately sends the player name after the connection is established
    player_name = input("Please enter your name: ")
    name_message = f"{player_name}\n"
    try:
        tcp_socket.sendall(name_message.encode())
    except OSError as e:
        print(f"A {type(e)} occurred while sending the player name: {e}\n")

    return tcp_socket


def print_welcome_message(server_tcp_socket):
    """
    Receives and prints the welcome message from the server.

    Args:
        server_tcp_socket (socket.socket): The TCP socket connected to the server.
    """
    try:
        message_encoded = server_tcp_socket.recv(1024)
        if not message_encoded:
            raise ConnectionError("Server disconnected, no data received.")

        message_decoded = message_encoded.decode('utf-8')
        print(message_decoded)
    except (ConnectionResetError, OSError) as e:
        print_red(f"Error occurred due to server disconnection or crash while trying to receive the welcome message.")
        raise
    except Exception as e:
        raise Exception(f"An unexpected error {type(e).__name__} occurred while trying to receive the welcome message.")


def print_trivia_question(server_tcp_socket):
    """
    Receives and prints the trivia question from the server.

    Args:
        server_tcp_socket (socket.socket): The TCP socket connected to the server.
    """
    try:
        message_encoded = server_tcp_socket.recv(1024)
        if not message_encoded:
            raise ConnectionError("Server closed the connection unexpectedly.")

        message_decoded = message_encoded.decode('utf-8')
        print(message_decoded)
    except (sock.error, ConnectionError) as e:
        print_red(f"Error occurred due to server disconnection or crash while trying to receive trivia question.")
        raise


def get_input(input_queue, valid_keys, stop_event):
    """
    Collects user input in a loop until a valid key is entered or a stop event is set.

    Args:
        input_queue (queue.Queue): The queue to which valid inputs are added.
        valid_keys (list[str]): A list of strings that are considered valid inputs.
        stop_event (threading.Event): An event that, when set, will break the loop and stop the function.
    """

    while not stop_event.is_set():
        try:
            user_input = input("Enter your response: ")
            if user_input in valid_keys:
                input_queue.put(user_input)
                break
            print("Invalid input. Please try again.")
        except UnicodeDecodeError as ude:
            print_red("Unicode decode error during user input")
            stop_event.set()  # Signal to end this thread due to input issues
            raise
        except Exception as e:
            print_red("General error during user input.")
            stop_event.set()  # Signal to end this thread for any other issues
            raise


def get_answer_from_user() -> bool | None:
    valid_true_keys = ["1", "t", "T", "y", "Y"]
    valid_false_keys = ["0", "f", 'F', 'n', 'N']
    valid_keys = valid_true_keys + valid_false_keys
    stop_event = threading.Event()

    input_queue = queue.Queue()
    input_thread = threading.Thread(target=get_input, args=(input_queue, valid_keys, stop_event))
    input_thread.start()

    try:
        user_input = input_queue.get(block=True, timeout=15)  # Reduced timeout to test quicker
    except queue.Empty:
        print("No input received within the time limit.")
        stop_event.set()  # Ensure we signal the thread to stop if it hasn't already
        input_thread.join(timeout=15)  # Wait for the thread to finish
        return None

    if user_input in valid_true_keys:
        return True
    elif user_input in valid_false_keys:
        return False
    else:
        return None


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
        handle_socket_error(e, "sending answer", "send_answer_to_server")
        return False


def print_message_from_server(server_tcp_socket):
    try:
        message_encoded = server_tcp_socket.recv(1024)  # Adjust buffer size if necessary
        if not message_encoded:
            print("Server has disconnected.")
            return None
        message = message_encoded.decode('utf-8')
        print(message)
    except sock.error as e:
        print(f"Error receiving message from server: {e}")
        return None



if __name__ == "__main__":
    server_tcp_socket = None
    while True:
        try:
            server_name, server_ip, server_port = looking_for_a_server()
            if not server_name:
                continue

            server_tcp_socket = connect_to_server(server_ip, server_port)
            if not server_tcp_socket:
                continue

            if not print_welcome_message(server_tcp_socket):
                raise Exception("Failed to receive welcome message.")
            if not print_trivia_question(server_tcp_socket):
                raise Exception("Failed to receive trivia question.")

            user_answer = get_answer_from_user()
            send_answer_to_server(server_tcp_socket, user_answer)

            print_message_from_server(server_tcp_socket)  # Winner message
            print_message_from_server(server_tcp_socket)  # Stats message

        except KeyboardInterrupt:
            print_red("Client is shutting down due to a keyboard interrupt.")
            break
        except Exception as e:
            print_red(f"Error details: {e}")
        finally:
            if server_tcp_socket:
                server_tcp_socket.close()
                print("Disconnected from the server.")
            time.sleep(2)  # Wait before trying to connect again
