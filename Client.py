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
    """
    Unpacks a server broadcast packet according to a predefined structure.
    The format string for unpacking the packet:
    '>'  stands for big-endian, meaning the first decoded part of the packet will be stored in the first variable basically meaning that encoding happens from left to right
    'I' for the 4-byte magic cookie
    'B' for the 1-byte message type
    '32s' for the 32-byte server name
    'H' for the 2-byte port number
    
    Args:
        data (bytes): The raw bytes received from the UDP broadcast.

    Returns:
        tuple: A tuple containing the unpacked magic_cookie, message_type, server_name, and server_port.
               Returns None if unpacking fails due to incorrect data format.
    """
    packet_format = '>IB32sH'  # Big-endian: int, byte, 32-byte string, short
    try:
        magic_cookie, message_type, server_name_raw, server_port = struct.unpack(packet_format, data)
        server_name = server_name_raw.decode('utf-8').strip('\x00')  # Decode and strip null bytes
        return magic_cookie, message_type, server_name, server_port
    except struct.error as e:
        print(f"Failed to unpack data due to: {e}")
        return None
    except UnicodeDecodeError as ude:
        print(f"Failed to decode server name: {ude}")
        return None
    

def looking_for_a_server():
    """
    Listens for UDP broadcasts to discover available trivia game servers. It binds to a specific port
    to receive server details such as server name, IP, and port.

    This function checks for issues like address already in use or invalid broadcast messages (wrong magic cookie or message type),
    and handles exceptions for socket operations and timeouts.

    Returns:
        tuple: Returns server details (name, IP, port) if a valid broadcast is received, otherwise None.
        None: Returned in case of errors such as socket binding issues, timeouts, or invalid data.
    """

    print("Client started, listening for offer requests...")
    udp_socket = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
    udp_socket.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
    try:
        udp_socket.bind(('', 13117))
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            print("Error while binding the socket: Address already in use. Please try again later.")
            return None
        else:
            print("An unrecognized error has occurred during binding, trying to bind again...")
            return None
    
    try:
        # Blocking method. it won't reach the next line until it detects a broadcast
        data, addr = udp_socket.recvfrom(1024)
    except sock.timeout as t:
        print("timeout receiving udp data packet from the server!")
        return None
    
    magic_cookie, message_type, server_name, server_port = unpack_packet(data)
    if magic_cookie != 0xabcddcba:
        print("Invalid magic cookie in udp packet! nice try hacker!")
        return None
    if message_type != 0x2:
        print("Invalid message type in udp packet!")
        return None

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
    Sends the user's answer to the server. This function handles the transmission of the user's
    answer as a string representation of boolean values 'true', 'false', or 'none' for undefined.

    Args:
        server_tcp_socket (socket.socket): The TCP socket connected to the server.
        user_answer (bool | None): The user's answer as a boolean or None if no answer was provided.
    """
    # Define the message based on the user's answer
    if user_answer is True:
        message = "true"
    elif user_answer is False:
        message = "false"
    else:
        message = "none"  # This handles None or any other unexpected value

    try:
        server_tcp_socket.sendall(message.encode('utf-8'))
    except sock.error:
        print_red(f"Failed to send answer to server.")
        raise


def print_message_from_server(server_tcp_socket):
    """
    Receives and prints a message from the server.

    Args:
        server_tcp_socket (socket.socket): The TCP socket connected to the server.
    """
    try:
        message_encoded = server_tcp_socket.recv(1024)  # Adjust buffer size if necessary
        if not message_encoded:
            raise ConnectionError("Server closed the connection unexpectedly.")

        message_decoded = message_encoded.decode('utf-8')
        print(message_decoded)
    except sock.error:
        print_red("Error receiving message from server.")
        raise
    except UnicodeDecodeError:
        # Specific exception for issues during the decoding process
        print_red("Unicode decode error.")
        raise
    except Exception:
        # A generic exception handler for any other unforeseen exceptions
        print_red(f"An unexpected error occurred while trying print message from server.")
        raise


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
