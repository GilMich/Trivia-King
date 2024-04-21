import errno
import socket
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

    This function prints a detailed error message based on the type of socket exception, the operation, and the function where it happened. All messages are printed in red.
    """
    error_type = type(exception).__name__
    error_message = str(exception)

    # Function to print messages in red
    def print_red(message):
        print(f"\033[31m{message}\033[0m")

    print_red(f"Error occurred in function '{function}' during {operation}.")
    print_red(f"Error Type: {error_type}")
    print_red(f"Error Details: {error_message}")

    if isinstance(exception, sock.timeout):
        print_red("This was a timeout error. Please check network conditions and retry.")
    elif isinstance(exception, sock.error):
        print_red("A general socket error occurred. Please check the socket operation and parameters.")
    elif isinstance(exception, sock.gaierror):
        print_red("An address-related error occurred. Please verify the network address details.")
    elif isinstance(exception, sock.herror):
        print_red("A host-related error occurred. Check DNS configurations and host availability.")
    else:
        print_red("An unexpected type of error occurred. Please consult system logs or network settings.")


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
            raise OSError("Error while binding the socket: Address already in use. Please try again later.") from e

        else:
            raise OSError("An unrecognized error has occurred during binding, trying to bind again...") from e
    try:
        data, addr = udp_socket.recvfrom(
            1024)  # Blocking method! it won't reach the next line until it detects a broadcast

    except sock.timeout as t:
        raise OSError(f"timeout receiving udp data packet from the server! ") from t
    magic_cookie, message_type, server_name, server_port = unpack_packet(data)

    if magic_cookie != 0xabcddcba:
        raise OSError("Invalid magic cookie in udp packet! nice try hacker!")

    if message_type != 0x2:
        raise OSError("Invalid message type in udp packet!")

    server_ip = addr[0]
    print(f'Received offer from server "{server_name}" at address {addr[0]}, attempting to connect...')
    return server_name, server_ip, server_port


def connect_to_server(server_ip, server_port):
    # Create a TCP/IP socket
    tcp_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    try:
        # Connect the socket to the server's address and port
        tcp_socket.connect((server_ip, server_port))
    except OSError as e:
        raise OSError(f"A {type(e)} occurred while trying to connect to the server with tcp : {e}\n") from e

    print(f"Successfully connected to the server at {server_ip}:{server_port} \n")
    # Immediately sends the player name after the connection is established
    player_name = input("Please enter your name: ")
    name_message = f"{player_name}\n"
    try:
        tcp_socket.sendall(name_message.encode())
    except OSError as e:
        raise OSError(f"A {type(e)} occurred while sending the player name: {e}\n") from e
    return tcp_socket


def print_welcome_message(server_tcp_socket):
    try:
        message_encoded = server_tcp_socket.recv(1024)
    except OSError as e:
        raise OSError(f"A {type(e)} occurred while trying to receive the welcome message: {e}\n") from e
    message_decoded = message_encoded.decode('utf-8')
    print(message_decoded)
    return True


def print_trivia_question(server_tcp_socket):
    try:
        message_encoded = server_tcp_socket.recv(1024)
    except OSError as e:
        raise OSError(f"A {type(e)} occurred while trying to receive the trivia question: {e}\n") from e

    message_decoded = message_encoded.decode('utf-8')
    print(message_decoded)
    return True


class InGameError(Exception):
    def __init__(self, message):
        super().__init__(message)


def get_input(input_queue, valid_keys, stop_event):
    while not stop_event.is_set():
        try:
            user_input = input("Enter [1, t, y] for True, [0, f, n] for False: \n")
            if user_input in valid_keys:
                input_queue.put(user_input)
                break
            else:
                print("Invalid input. Please try again.\n")
        except UnicodeDecodeError as ude:
            print(f"Unicode decode error during user input: {ude}\n")
            stop_event.set()  # Signal to end this thread due to input issues
            break
        except Exception as e:
            print(f"Error of type : {type(e)} during getting user input: {e}\n")
            stop_event.set()  # Signal to end this thread for any other issues
            break


def get_answer_from_user() -> bool | None:
    valid_true_keys = ["1", "t", "T", "y", "Y"]
    valid_false_keys = ["0", "f", 'F', 'n', 'N']
    valid_keys = valid_true_keys + valid_false_keys
    stop_event = threading.Event()

    input_queue = queue.Queue()
    input_thread = threading.Thread(target=get_input, args=(input_queue, valid_keys, stop_event))
    input_thread.daemon = True
    input_thread.start()

    try:
        user_input = input_queue.get(block=True, timeout=10)  # Reduced timeout to test quicker
    except queue.Empty:
        print("No input received within the time limit.\n")
        stop_event.set()  # Ensure we signal the thread to stop if it hasn't already
        # input_thread.join(timeout=0.1)  # Dont wait for the thread to finish
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
    # Prepare the message
    if user_answer is None:
        message = "none"
    elif user_answer:
        message = "true"
    else:
        message = "false"
    # Send the message
    try:
        server_tcp_socket.sendall(message.encode())
    except ConnectionResetError as cre:
        raise OSError(f"{type(cre)} Server disconnected or crashed while trying to send the answer.\n") from cre
    except OSError as e:
        raise InGameError(f"Error occurred while sending the answer to the server: {e}\n") from e



def print_results_from_server(server_tcp_socket):
    server_tcp_socket.settimeout(5)  # Set a timeout for receiving messages
    try:
        winner_message_encoded = server_tcp_socket.recv(1024)  # Adjust buffer size if necessary
        winner_message = winner_message_encoded.decode('utf-8')
        print(winner_message)
        stats_message_encoded = server_tcp_socket.recv(1024)  # Adjust buffer size if necessary
        stats_message = stats_message_encoded.decode('utf-8')
        print(stats_message)
    except OSError as e:
        raise OSError(f"Error {type(e)} occurred while receiving game results from server: {e}") from e


# Main client function
if __name__ == "__main__":
    server_tcp_socket = None
    while True:
        try:
            server_name, server_ip, server_port = looking_for_a_server()
            server_tcp_socket = connect_to_server(server_ip, server_port)
            if not server_tcp_socket:
                continue
            print_welcome_message(server_tcp_socket)
            print_trivia_question(server_tcp_socket)
            user_answer = get_answer_from_user()
            try:
                result_sending_to_server = send_answer_to_server(server_tcp_socket, user_answer)
            except InGameError as ige:
                print(ige)
            print_results_from_server(server_tcp_socket)

        except ConnectionResetError as cre:
            print("Server disconnected unexpectedly, looking for new server...")
            continue

        except KeyboardInterrupt:
            print("Client is shutting down due to a keyboard interrupt.")
            break
        except OSError as e:
            print("Error:", e)
        finally:
            if server_tcp_socket:
                server_tcp_socket.close()
                print("Disconnected from the server.")
            time.sleep(2)  # Wait before trying to connect again
