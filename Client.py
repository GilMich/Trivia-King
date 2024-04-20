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
    # Create a TCP/IP socket
    tcp_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    # try:
    # Connect the socket to the server's address and port
    tcp_socket.connect((server_ip, server_port))
    print(f"Successfully connected to the server at {server_ip}:{server_port}")

    # Immediately sends the player name after the connection is established
    player_name = input("Please enter your name: ")
    name_message = f"{player_name}\n"
    tcp_socket.sendall(name_message.encode())
    return tcp_socket

    # except sock.error as e:
    #     handle_socket_error(e, "connect to server", "connect_to_server")
    #     if tcp_socket:
    #         tcp_socket.close()  # Ensure the socket is closed if an error occurs
    #     return None


def print_welcome_message(server_tcp_socket):
    try:
        message_encoded = server_tcp_socket.recv(1024)
        message_decoded = message_encoded.decode('utf-8')
        print(message_decoded)
    except sock.error as e:
        handle_socket_error(e, "receiving welcome message", "print_welcome_message")
        return False  # Return False if an error occurred
    return True


def print_trivia_question(server_tcp_socket):
    try:
        message_encoded = server_tcp_socket.recv(1024)
        if not message_encoded:
            raise sock.error("Server closed connection")
        message_decoded = message_encoded.decode('utf-8')
        print(message_decoded)
    except sock.error as e:
        handle_socket_error(e, "receiving trivia question", "print_trivia_question")
        return False  # Return False if an error occurred
    return True


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
        user_input = "None"
        # Set the stop event to stop the input thread
        stop_event.set()
    # if user_input is None:
    #     return None

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



# Main client function
if __name__ == "__main__":
    server_tcp_socket = None
    while True:
        try:
            server_name, server_ip, server_port = looking_for_a_server()
            if server_name:
                server_tcp_socket = connect_to_server(server_ip, server_port)
                if server_tcp_socket:
                    if not print_welcome_message(server_tcp_socket):
                        raise Exception("Failed to receive welcome message.")
                    if not print_trivia_question(server_tcp_socket):
                        raise Exception("Failed to receive trivia question.")
                    user_answer = get_answer_from_user()
                    if not send_answer_to_server(server_tcp_socket, user_answer):
                        raise Exception("Failed to send answer.")

                    print_message_from_server(server_tcp_socket) # print winner message
                    print_message_from_server(server_tcp_socket) # print stats message
                    # server_tcp_socket.close()
                    # server_tcp_socket = None
        except KeyboardInterrupt:
            print("Client is shutting down due to a keyboard interrupt.")

        except Exception as e:
            print("Connection error:", e)

        finally:
            if server_tcp_socket:
                server_tcp_socket.close()
                print("Disconnected from the server.")
        # time.sleep(5)  # Adjust timing as needed

        # if not print_welcome_message(server_tcp_socket) or not print_trivia_question(server_tcp_socket):
        #     if server_tcp_socket:
        #         server_tcp_socket.close()
        #     server_tcp_socket = None
        #     continue  # Skip further actions and attempt to reconnect
        #
        # user_answer = get_answer_from_user()
        # if not send_answer_to_server(server_tcp_socket, user_answer):
        #     if server_tcp_socket:
        #         server_tcp_socket.close()
        #     server_tcp_socket = None  # Reset the connection

        # if server_tcp_socket:
        #     server_tcp_socket.close()
        #     print("Disconnected from the server.")

    # todo missing function to send the answer to the server