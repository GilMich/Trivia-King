import socket
import socket as sock
import threading
import time
import netifaces
import random
from tabulate import tabulate
import json

clients_dict = {}
last_connection_time = 99999999999
time_lock = threading.Lock()
clients_lock = threading.Lock()
server_name = "Trivia King"
trivia_topic = "The Olympics"


# ------------- CHECKED ----------------
def load_trivia_questions(file_path):
    """
    Loads trivia questions from a JSON file.

    Args:
        file_path (str): Path to the file containing trivia questions in JSON format.

    Returns:
        list: A list of trivia questions loaded from the file.

    Raises:
        FileNotFoundError: If the file specified does not exist.
        json.JSONDecodeError: If the file is not a valid JSON.
    """
    try:
        with open(file_path, 'r') as file:
            questions = json.load(file)
    except FileNotFoundError as e:
        raise FileNotFoundError(f"The file {file_path} does not exist.") from e
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Error decoding JSON from {file_path}.", file_path, e.pos) from e

    return questions


def handle_socket_error(exception, function):
    """
    Handles exceptions raised during socket operations.

    Args:
    exception: The exception instance that was raised.
    function: A string indicating the function name where the error occurred.

    This function prints a detailed error message based on the type of socket exception, the operation, and the function where it happened.
    """
    error_type = type(exception).__name__
    error_message = str(exception)

    # ANSI escape code for yellow
    yellow_text_color = '\033[93m'
    reset_color = '\033[0m'  # Reset to default terminal color

    print(f"{yellow_text_color}Error in: '{function}' function{reset_color} ")
    print(f"{yellow_text_color}Error Type: {error_type}{reset_color}")
    print(f"{yellow_text_color}Error Details: {error_message}{reset_color}")


# ------------- CHECKED ----------------
def get_local_ip():
    """
    Retrieves the local IP address of the machine by creating a dummy UDP connection.
    This does not actually establish a connection but is used to determine the IP address
    that would be used to reach a specific remote address.

    Returns:
        str: The local IP address.
    """
    with sock.socket(sock.AF_INET, sock.SOCK_DGRAM) as s:
        s.connect(('10.255.255.255', 1))  # dummy connect
        ip = s.getsockname()[0]
    return ip


# ------------- CHECKED ----------------
def get_default_broadcast():
    """
    Retrieves the default broadcast address for the default network interface.

    Returns:
        str: The broadcast address of the default network interface.

    Raises:
        ValueError: If no default gateway or broadcast address is found.
    """
    try:
        # Retrieve the default gateway details for IPv4 connections
        default_gateway_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        # Retrieve IPv4 addresses for the default gateway interface
        ipv4_addresses = netifaces.ifaddresses(default_gateway_interface)[netifaces.AF_INET]
        broadcast_address = ipv4_addresses[0]['broadcast']
        return broadcast_address

    except KeyError as e:
        # Convert KeyError to a more understandable ValueError
        e = ValueError(f"Failed to retrieve necessary network interface details: {e}")
        handle_socket_error(e, "get_default_broadcast")


# ------------- CHECKED ----------------
def find_free_port():
    """
    Finds and returns an available network port on the local machine by asking the OS to assign a free port.

    Returns:
        int: A free port number assigned by the operating system.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temp_socket:
        temp_socket.bind(('', 0))  # Binding to port 0 lets the OS choose a free port
        assigned_port = temp_socket.getsockname()[1]  # Retrieve the port number assigned by the OS
        return assigned_port


# ------------- CHECKED ----------------
def udp_broadcast(server_name, server_port, stop_event):
    """
    Continuously broadcasts UDP packets containing server information until a stop event is triggered.

    Args:
        server_name (str): Name of the server to broadcast.
        server_port (int): Port number on which the server will listen for TCP connections.
        stop_event (threading.Event): An event to stop the broadcast when set.
    """
    broadcast_address = get_default_broadcast()
    # Message setup
    magic_cookie = 0xabcddcba
    message_type = 0x2  # Offer message type
    server_name_padded = server_name.ljust(32)  # Pad server name to ensure it is 32 characters
    message = magic_cookie.to_bytes(4, 'big') + message_type.to_bytes(1, 'big') + \
              server_name_padded.encode() + server_port.to_bytes(2, 'big')

    # Set up and start broadcasting
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while not stop_event.is_set():
            udp_socket.sendto(message, (broadcast_address, 13117))
            time.sleep(2)  # Sleep to manage loop frequency and reduce network congestion


# ------------- CHECKED ----------------
def save_client_info(client_socket, client_address):
    """
    Receives data from a client socket to update global client records.

    If successful, decodes the data, updates the client's details in the global dictionary, and
    refreshes the last interaction timestamp. Logs an error and exits early if data reception fails.

    Args:
        client_socket (socket.socket): The client's socket connection.
        client_address (tuple): The client's address.

    Globals:
        last_connection_time (float): Timestamp of the last client interaction.
    """
    global last_connection_time
    if client_address not in clients_dict:
        try:
            received_data = client_socket.recv(1024)  # Adjust buffer size as needed
            if not received_data:
                e = ValueError("No data received from client.")
                handle_socket_error(e, "save_client_info")

            client_name = received_data.decode('utf-8').rstrip('\n')
            clients_dict[client_address] = {
                "name": client_name,
                "socket": client_socket,
                "is_client_active": True,
                "client_answers": [],
                "answers_times": []
            }
            last_connection_time = time.time()
        except Exception as e:
            handle_socket_error(e, "save_client_info")


# ------------- CHECKED ----------------
def watch_for_inactivity(stop_event, timeout=10):
    """
    Monitors the time elapsed since the last client interaction and sets a stop event
    if the timeout is exceeded to indicate inactivity.

    Args:
        stop_event (threading.Event): An event to set when the timeout is reached.
        timeout (int, optional): The number of seconds to wait before considering inactive. Default is 10 seconds.

    Globals:
        last_connection_time (float): The last recorded time of client interaction.
    """
    global last_connection_time
    while not stop_event.is_set():
        with time_lock:
            elapsed = time.time() - last_connection_time
        if elapsed >= timeout:
            stop_event.set()
            break
        time.sleep(1)  # Sleep briefly to avoid busy waiting


def tcp_listener(server_port, stop_event):
    server_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    # Set SO_REUSEADDR to 1 to allow the immediate reuse of the port
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', server_port))  # Bind to the specified port on all interfaces

    server_socket.listen()  # Listen for incoming connections
    server_socket.settimeout(10)  # timeout for accepting new requests
    print(f"Server is listening for TCP connections on port {server_port}")
    global last_connection_time
    while not stop_event.is_set():
        try:
            client_socket, client_address = server_socket.accept()  # blocking method to accept new connection. if it waits here more than 10sec it will go to except
            print(f"\n\033[32mAccepted\033[0m a connection from {client_address}")
            threading.Thread(target=save_client_info, args=(client_socket, client_address)).start()
            threading.Thread(target=watch_for_inactivity, args=(stop_event,)).start()

        except Exception as e:
            if isinstance(e, sock.timeout):
                continue
            else:
                handle_socket_error(e, "tcp_listening")
        continue  # if a client already connected while waiting for another one, the stop event will be true here. if nobody connected we will just keep waiting


# ------------- CHECKED ----------------
def welcome_message(server_name, trivia_topic):
    """
    Sends a welcome message to all connected clients.

    Args:
        server_name (str): Name of the server.
        trivia_topic (str): Topic for the trivia session.

    Returns:
        int: -1 if no clients are connected, otherwise returns None.
    """
    if not clients_dict:
        print("No clients connected to the server.")
        return -1

    # Create a formatted welcome message with instructions
    instructions = "Please respond to each question by typing '1', 't', or 'y' for True and '0', 'f', or 'n' for False."
    message = f"\nWelcome to the {server_name} server, where we are answering trivia questions about {trivia_topic}.\n{instructions}\n"

    # Append each client's name to the message
    for index, (address, client_info) in enumerate(clients_dict.items(), start=1):
        message += f"Player {index}: {client_info['name']}\n"

    # Encode the message once
    message_encoded = message.encode('utf-8')

    # Send the encoded message to all clients
    for client in clients_dict.values():
        client["socket"].sendall(message_encoded)
    print(message)


# ------------- CHECKED ----------------
def send_trivia_question(questions) -> bool:
    """
    Sends a randomly selected trivia question to all connected clients.

    Args:
        questions (list): A list of dictionaries, each containing a 'question' and its 'answer'.

    Returns:
        bool: The correct answer to the randomly selected trivia question (True or False).
    """
    random_question = random.choice(questions)
    trivia_question = random_question['question']
    trivia_answer = random_question['answer']

    # Construct the message to send
    message = f"True or False: {trivia_question}"

    # Send the question to each connected client and handle potential errors
    for client in clients_dict.values():
        try:
            client["socket"].sendall(message.encode('utf-8'))
        except Exception as e:
            # Log the error and continue to attempt to send to other clients
            handle_socket_error(e,  "sending_trivia_question")
    return trivia_answer


# ------------- CHECKED ----------------
def get_answer_from_client(client_socket, client_address, trivia_sending_time):
    """
    Receives and processes the trivia answer from a connected client, logging their response time.

    Args:
        client_socket (socket.socket): The socket through which the client is connected.
        client_address (tuple): The address of the client.
        trivia_sending_time (float): The timestamp when the trivia question was sent.

    Globals:
        clients_dict (dict): Records of connected clients, storing their answers and response times.
    """
    client_socket.settimeout(15)
    try:
        client_answer_encoded = client_socket.recv(1024)
        if not client_answer_encoded:
            e = ValueError("No data received; client may have disconnected")
            handle_socket_error(e, "get_answer_from_client")

        client_time_to_answer = round((time.time() - trivia_sending_time), 2)
        clients_dict[client_address]["answers_times"].append(client_time_to_answer)

        client_answer_decoded = client_answer_encoded.decode('utf-8').strip().lower()
        if client_answer_decoded in ["true", "false"]:
            answer_value = 1 if client_answer_decoded == "true" else 0
            clients_dict[client_address]["client_answers"].append(answer_value)
        else:
            print(f"Invalid answer received: {client_answer_decoded}")
            e = ValueError(f"Invalid answer received: {client_answer_decoded}")
            handle_socket_error(e, "get_answer_from_client")

    except (socket.timeout, BlockingIOError, socket.error) as e:
        print(f"Error receiving client response: {e}")
        clients_dict[client_address]["client_answers"].append(-1)
        clients_dict[client_address]["answers_times"].append(0)

    except Exception as e:
        print(f"Unexpected error: {e}")
        clients_dict[client_address]["client_answers"].append(-1)
        clients_dict[client_address]["answers_times"].append(0)


def get_all_answers(trivia_sending_time: float):
    list_of_threads = []
    for client_address in clients_dict.keys():
        client_socket = clients_dict[client_address]["socket"]
        thread = threading.Thread(target=get_answer_from_client,
                                  args=(client_socket, client_address, trivia_sending_time))
        thread.start()
        list_of_threads.append(thread)  # Store the thread reference in the list
    time.sleep(5)
    # Wait for all threads to complete
    for thread in list_of_threads:
        thread.join(timeout=10)


def calculate_winner(correct_answer: bool) -> tuple | None:
    """ this function will go over the dictionary and check who is the player
    that answered correctly first, if exists. if no one answered correctly, it will return None """

    min_timestamp = 99999999999
    min_client_address = None
    for client_address in clients_dict.keys():
        client_answer = clients_dict[client_address]["client_answers"][-1]
        client_time = clients_dict[client_address]["answers_times"][-1]
        if client_answer < 0:  # Skip clients who didn't answer
            continue
        if client_answer == correct_answer and client_time < min_timestamp:
            min_client_address = client_address
            min_timestamp = client_time
    if min_client_address is None:
        return None

    return min_client_address


def send_winner_message(winner_address):
    if winner_address is None:
        message = "No one answered correctly this time. Better luck next time!"
    else:
        winner_name = clients_dict[winner_address]["name"]
        message = f"{winner_name} won! {winner_name} answered correctly first with a time of {clients_dict[winner_address]['answers_times'][-1]} seconds."
    for client in clients_dict.values():
        try:
            client["socket"].sendall(message.encode('utf-8'))
        except Exception as e:
            handle_socket_error(e, "send_winner_message")
            continue


def send_statistics_to_all_clients(correct_answer):
    headers = ["Player Name", "Answer", "Time"]
    table_data = []

    for addr, info in clients_dict.items():
        if info['is_client_active']:  # Ensure we only send to active clients
            name = info['name']
            if info['client_answers'][-1] == 1:
                client_answer = "True"
            elif info['client_answers'][-1] == 0:
                client_answer = "False"
            else:
                client_answer = "No answer"
            client_time = info['answers_times'][-1]
            # average_time = total_time / count_times if count_times > 0 else 0
            # Append player data to the table list
            table_data.append([name, client_answer, f"{client_time:.2f} seconds"])

    # Create a table using tabulate
    stats_table = tabulate(table_data, headers=headers, tablefmt="pretty")

    # Add a title to the table
    title = "Game Statistics:"
    # Prepending the title centered with newline for separation
    formatted_table = f"\n{title}\n{stats_table}\n"

    # Encode and send
    stats_message_encoded = formatted_table.encode('utf-8')
    for addr, info in clients_dict.items():
        if info['is_client_active']:
            try:
                info['socket'].sendall(stats_message_encoded)
            except Exception as e:
                info['is_client_active'] = False
                handle_socket_error(e, "send_statistics")


def close_all_client_sockets():
    for client_info in clients_dict.values():
        client_socket = client_info['socket']
        if client_socket:
            try:
                client_socket.close()
            except Exception as e:
                print(f"Failed to close client socket: {e}")
    clients_dict.clear()


# new code
def client_handler(client_socket, client_address):
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                raise ConnectionError("Client disconnected")
            print(f"Received data from {client_address}: {data.decode()}")
            client_socket.sendall("Response".encode())
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        remove_client(client_address)  # Clean up client from the server's list
        client_socket.close()
        print(f"Connection with {client_address} has been closed.")


def monitor_clients():
    while True:
        time.sleep(3)
        for client_address, client_info in list(clients_dict.items()):
            if not is_client_alive(client_info['socket']):
                remove_client(client_address)


def is_client_alive(sock) -> bool:
    try:
        # this is a non-blocking call
        sock.setblocking(0)
        data = sock.recv(16)
        sock.setblocking(1)
        if not data:
            return False
        return True
    except BlockingIOError:
        return True  # No data, but still connected

    except Exception:
        return False


def remove_client(client_address):
    if client_address in clients_dict:
        client_info = clients_dict.pop(client_address, None)
        if client_info and client_info['socket']:
            try:
                client_info['socket'].shutdown(socket.SHUT_RDWR)
                client_info['socket'].close()
            except Exception as e:
                print(f"Error closing socket for {client_address}: {e}")
        print(f"\033[31mRemoved\033[0m client {client_address} from active clients.")


# def game_loop():
#     threading.Thread(target=monitor_clients, daemon=True).start()
#
# check why its not working with stop_event.wait(timeout=10) instead of time.sleep(10)
if __name__ == "__main__":
    threading.Thread(target=monitor_clients, daemon=True).start()

    while True:
        last_connection_time = 99999999999
        try:
            questions = load_trivia_questions("olympics_trivia_questions.json")
        except Exception as e:
            print(f"Failed to load questions: {e}")
            break
        server_port = find_free_port()
        print(f"Server started, listening on IP address: {get_local_ip()}")
        stop_event = threading.Event()
        # clients_dict = {}

        udp_thread = threading.Thread(target=udp_broadcast, args=(server_name, server_port, stop_event))
        tcp_thread = threading.Thread(target=tcp_listener, args=(server_port, stop_event))

        # Start threads
        udp_thread.start()
        tcp_thread.start()

        try:
            # Wait for the stop_event to be set
            while not stop_event.is_set():
                time.sleep(1)  # Reduced wait timeout for more responsive handling

            if not any(client['is_client_active'] for client in clients_dict.values()):
                continue

            # if any(client['currently_listening_to_client'] for client in clients_dict.values()):
            # print("clients dict stat: ", clients_dict)
            print("Starting new game round...")
            udp_thread.join()
            tcp_thread.join()

            return_value_welcome = welcome_message(server_name, trivia_topic)
            if return_value_welcome == -1:
                continue
            correct_answer = send_trivia_question(questions)
            time.sleep(1)  # Adjust timing as needed
            trivia_sending_time = time.time()
            get_all_answers(trivia_sending_time)
            time.sleep(1)
            winner_client_address = calculate_winner(correct_answer)
            send_winner_message(winner_client_address)
            send_statistics_to_all_clients(clients_dict)  # Call after a round to update clients
            time.sleep(1)  # Adjust timing as needed
            print("Round ends")
            # continue

            close_all_client_sockets()
            # clients_dict.clear()
            print("Server shutdown completed.")
            # Clearing and reinitializing for a new round
            time.sleep(2)

        except KeyboardInterrupt:
            print("Shutting down the server.")
            stop_event.set()
        # finally:
        #     # Cleanup
        #     udp_thread.join()
        #     tcp_thread.join()
        #
        #     close_all_client_sockets()
        #     # clients_dict.clear()
        #     print("Server shutdown completed.")
        #     # Clearing and reinitializing for a new round
        #     time.sleep(5)
