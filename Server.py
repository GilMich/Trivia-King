import errno
import socket
import socket as sock
import netifaces
import random
from tabulate import tabulate
import json
import threading
import time


# Last update 17:39
clients_dict = {}
last_connection_time = float('inf')
time_lock = threading.Lock()
server_name = "Trivia King"
trivia_topic = "The Olympics"
trivia_questions_path = "olympics_trivia_questions.json"


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

    This function prints a detailed error message based on the type of socket exception, the operation,
    and the function where it happened.
    """

    # Function to print messages in red with ANSI
    def print_red(message):
        print(f"\033[31m{message}\033[0m")

    error_type = type(exception).__name__
    error_message = str(exception)

    print_red(f"Error in: '{function}' function ")
    print_red(f"Error Type: {error_type}")
    print_red(f"Error Details: {error_message}")


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


def get_default_broadcast():
    """
    Retrieves the default broadcast address for the default network interface.

    Returns:
        str: The broadcast address of the default network interface.
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


# def udp_broadcast(server_name, server_port, stop_event):
#     print(server_name, "!")
#     broadcast_address = get_default_broadcast()
#     # Sets a socekt instance for udp broadcasting
#     udp_socket = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
#     udp_socket.setsockopt(sock.SOL_SOCKET, sock.SO_BROADCAST, 1)
#
#     # Prepare the message according to the specified packet format
#     magic_cookie = 0xabcddcba
#     message_type = 0x2  # Offer message
#     server_name_padded = server_name.ljust(32)  # Ensure the server name is 32 characters long
#     print(server_name_padded, "!padd")
#
#     message = magic_cookie.to_bytes(4, 'big') + message_type.to_bytes(1,
#                                                                       'big') + server_name_padded.encode() + server_port.to_bytes(
#         2, 'big')
#
#     # Broadcast
#     while not stop_event.is_set():
#         ip = get_local_ip()
#         udp_socket.sendto(message, (broadcast_address, 13117))
#         time.sleep(2)  # sleep to avoid busy waiting


def save_client_info(client_socket, client_address):
    """
    Receives data from a client socket to update global client records.

    If successful, decodes the data, updates the client's details in the global dictionary, and
    refreshes the last interaction timestamp. Logs an error and exits early if data reception fails.

    Args:
        client_socket (socket.socket): The client's socket connection.
        client_address (tuple): The client's address.

    Globals:
        clients_dict (dict): Records of connected clients.
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
            client_socket, client_address = server_socket.accept()  # blocking method to accept new connection
            print(f"\n\033[32mAccepted\033[0m a connection from {client_address}")
            threading.Thread(target=save_client_info, args=(client_socket, client_address)).start()
            threading.Thread(target=watch_for_inactivity, args=(stop_event,)).start()

        except Exception as e:
            if isinstance(e, sock.timeout):
                continue
            else:
                handle_socket_error(e, "tcp_listening")
        continue  # if a client already connected while waiting for another one, the stop event will be true here


def welcome_message(server_name, trivia_topic):
    """
    Sends a welcome message to all connected clients.

    Args:
        server_name (str): Name of the server.
        trivia_topic (str): Topic for the trivia session.
    """
    instructions = "Please respond to each question by typing '1', 't', or 'y' for True and '0', 'f', or 'n' for False."
    olympic_rings = get_olympic_rings()
    message = f"\n{olympic_rings}\nWelcome to the {server_name} server, where we are answering trivia questions about {trivia_topic}.\n{instructions}\n"
    # Append each client's name to the message
    for index, (address, client_info) in enumerate(clients_dict.items(), start=1):
        message += f"Player {index}: {client_info['name']}\n"
    # Encode the message once
    message_encoded = message.encode('utf-8')

    # Send the encoded message to all clients
    for client in clients_dict.values():
        try:
            client["socket"].sendall(message_encoded)
        except sock.error as e:
            print(f"Failed to send message to {client['name']} due to a socket error: {e}")

    if clients_dict:
        print(message)


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
            handle_socket_error(e, "sending_trivia_question")
    print(message)
    return trivia_answer


def get_answer_from_client(client_socket, client_address, trivia_sending_time):
    """
    Receives and processes the trivia answer from a connected client, logging their response time.

    Args:
        client_socket (socket.socket): The socket through which the client is connected.
        client_address (tuple): The address of the client.
        trivia_sending_time (float): The timestamp when the trivia question was sent.

    Globals:
        clients_dict (dict): A dictionary containing client information.
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
        handle_socket_error(e, "get_answer_from_client")
        clients_dict[client_address]["client_answers"].append(-1)
        clients_dict[client_address]["answers_times"].append(0)

    except Exception as e:
        print(f"Unexpected error: \n", handle_socket_error(e, "get_answer_from_client"))
        clients_dict[client_address]["client_answers"].append(-1)
        clients_dict[client_address]["answers_times"].append(0)


def get_all_answers(trivia_sending_time: float):
    """
    Starts threads to collect answers from all clients and waits for them to complete.

    Args:
        trivia_sending_time (float): The timestamp when the trivia question was sent.

    Globals:
        clients_dict (dict): A dictionary containing the socket and other details for each client.
    """
    list_of_threads = []
    for client_address, client_info in clients_dict.items():
        thread = threading.Thread(target=get_answer_from_client,
                                  args=(client_info["socket"], client_address, trivia_sending_time))

        thread.start()
        list_of_threads.append(thread)  # Store the thread reference in the list
    time.sleep(5)
    # Wait for all threads to complete
    for thread in list_of_threads:
        thread.join(timeout=10)


def calculate_winner(correct_answer: bool) -> tuple | None:
    """Determines the winner of a trivia round.

    Iterates over the client records to find the first client who answered correctly in the shortest time.

    Args:
        correct_answer (bool): The correct answer to the trivia question.

    Returns:
        tuple | None: The address of the winning client, or None if no correct answers were given.
    """
    min_timestamp = float('inf')
    winner = None
    for client_address in clients_dict.keys():
        client_answer = clients_dict[client_address]["client_answers"][-1]
        client_response_time = clients_dict[client_address]["answers_times"][-1]
        if client_answer < 0:  # Skip clients who didn't answer
            continue
        if client_answer == correct_answer and client_response_time < min_timestamp:
            winner = client_address
            min_timestamp = client_response_time

    return winner


def send_winner_message(winner_address):
    """Sends a message to all clients announcing the winner of the trivia round or that no correct answers were received

    Args:
        winner_address (tuple | None): The address of the winning client, or None if no winner.
    """

    if winner_address is None:
        message = "No one answered correctly this time. Better luck next time!"
    else:
        winner_name = clients_dict[winner_address]["name"]
        message = f"The player {winner_name} won the game! answered correctly first with a time of {clients_dict[winner_address]['answers_times'][-1]} seconds."
    for client in clients_dict.values():
        try:
            client["socket"].sendall(message.encode('utf-8'))
        except Exception as e:
            handle_socket_error(e, "send_winner_message")
            continue
    print(message)


def build_statistics_table():
    """
    Constructs a statistics table from client data.

    Globals:
        clients_dict (dict): A dictionary containing the socket and other details for each client.

    Returns:
        str: A formatted table with client statistics.
    """
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
            # Append player data to the table list
            table_data.append([name, client_answer, f"{client_time:.2f} seconds"])

    # Create a table using tabulate
    stats_table = tabulate(table_data, headers=headers, tablefmt="pretty")

    # Add a title to the table
    title = "Game Statistics:"
    # Prepending the title centered with newline for separation
    formatted_table = f"\n{title}\n{stats_table}\n"
    return formatted_table


def send_statistics_to_all_clients():
    formatted_table = build_statistics_table()

    # Encode and send
    stats_message_encoded = formatted_table.encode('utf-8')
    for addr, info in clients_dict.items():
        if info['is_client_active']:
            try:
                info['socket'].sendall(stats_message_encoded)
            except Exception as e:
                info['is_client_active'] = False
                handle_socket_error(e, "send_statistics")
    print(formatted_table)


def close_all_client_sockets():
    """
    Closes all client sockets and clears the client dictionary. This function is typically called
    to clean up resources at the end of a game round or when the server is shutting down.

    Globals:
        clients_dict (dict): A dictionary of client information, including sockets.
    """
    for client_info in clients_dict.values():
        client_socket = client_info['socket']
        if client_socket:
            try:
                client_socket.close()
            except Exception as e:
                print(f"Failed to close client socket: {e}")
    clients_dict.clear()


def client_handler(client_socket, client_address):
    """
    Handles incoming data from a connected client. If the client disconnects or an error occurs,
    the client is removed from the server.

    Args:
        client_socket (socket.socket): The socket object for the client.
        client_address (tuple): The address of the client.

    Cleanup:
        Closes the client socket and removes the client from the server's client list.
    """
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
    """
    Continuously checks the health of client connections and removes any clients that have
    disconnected. This function runs in a separate thread to ensure active monitoring without
    blocking other server operations.

    Usage:
        Should be run in a daemon thread to continually monitor client status.
    """
    while True:
        time.sleep(3)

        for client_address, client_info in list(clients_dict.items()):
            if not is_client_alive(client_info['socket']):
                remove_client(client_address)


def is_client_alive(sock):
    """
    Checks if a client socket is still active by attempting a non-blocking read.
    Returns True if the socket is active, or False if it is not.

    Args:
        sock (socket.socket): The socket to check.

    Returns:
        bool: True if the socket is active, False otherwise.
    """
    try:
        sock.setblocking(False)  # Ensure non-blocking mode is set
        data = sock.recv(16)  # Attempt to read a small amount of data
        sock.setblocking(True)  # Reset to blocking mode if necessary

        return bool(data)  # If data is received, socket is active; if not, it's still open but idle

    except BlockingIOError:
        # No data, but still connected
        return True
    except (socket.error, Exception) as e:
        # Handle specific socket errors and general exceptions to determine if the socket is closed
        if isinstance(e, socket.error) and e.errno == errno.ECONNRESET:
            return False
        return False  # Assume any other exception means the socket is not active


def remove_client(client_address):
    """
    Removes a client from the server's list of active clients and closes their socket.

    Args:
        client_address (tuple): The address of the client to remove.

    Globals:
        clients_dict (dict): A dictionary of client information, used to manage connected clients.
    """
    if client_address in clients_dict:
        client_info = clients_dict.pop(client_address, None)
        if client_info and client_info['socket']:
            try:
                client_info['socket'].shutdown(socket.SHUT_RDWR)
                client_info['socket'].close()
            except Exception as e:
                print(f"Error closing socket for {client_address}: {e}")
        print(f"\033[31mRemoved\033[0m client {client_address} from active clients.")

def get_olympic_rings():
    """
    Generates a string representation of the Olympic Rings using Unicode circle characters
    and ANSI escape codes for colored output. This creates a visually appealing representation
    of the Olympic rings.

    Returns:
        str: A string containing the colored Olympic Rings.
    """

    olympic_rings_colored = """
    \033[34m      ooooo\033[0m      \033[30mooooo\033[0m      \033[31mooooo\033[0m
    \033[34m    o       o\033[0m  \033[30mo       o\033[0m  \033[31mo       o\033[0m
    \033[34m   o         o\033[0m\033[30mo         o\033[0m\033[31mo         o\033[0m
    \033[34m   o         o\033[0m\033[30mo         o\033[0m\033[31mo         o\033[0m
    \033[34m    o       o\033[0m  \033[30mo       o\033[0m  \033[31mo       o\033[0m
    \033[34m      ooooo\033[0m      \033[30mooooo\033[0m      \033[31mooooo\033[0m
                 \033[33mooooo\033[0m      \033[32mooooo\033[0m
               \033[33mo       o\033[0m  \033[32mo       o\033[0m
              \033[33mo         o\033[0m\033[32mo         o\033[0m
              \033[33mo         o\033[0m\033[32mo         o\033[0m
               \033[33mo       o\033[0m  \033[32mo       o\033[0m
                 \033[33mooooo\033[0m      \033[32mooooo\033[0m
    """
    return olympic_rings_colored


# check why it's not working with stop_event.wait(timeout=10) instead of time.sleep(10)
def game_loop():
    """
    Coordinates the main game operations of a trivia game server, including question loading, server broadcasting,
    client management, trivia round execution, and cleanup activities.

    This function runs in a continuous loop to handle multiple game rounds and ensures graceful shutdown
    on keyboard interrupts or other stop signals. It actively monitors client connectivity,
    terminating rounds early if clients disconnect during critical stages of gameplay.
    """
    global last_connection_time

    # Start a daemon thread to monitor client connections and handle disconnections
    threading.Thread(target=monitor_clients, daemon=True).start()
    stop_event = udp_thread = tcp_thread = None

    while True:
        try:
            questions = load_trivia_questions(trivia_questions_path)
            # Find an available network port
            server_port = find_free_port()
            print(f"Server started, listening on IP address: {get_local_ip()}")
            # Create an event to signal when to stop the server operations
            stop_event = threading.Event()

            # Start UDP and TCP server threads for broadcasting and listening for client connections
            udp_thread = threading.Thread(target=udp_broadcast, args=(server_name, server_port, stop_event))
            tcp_thread = threading.Thread(target=tcp_listener, args=(server_port, stop_event))
            udp_thread.start()
            tcp_thread.start()

            # Wait until the stop event is triggered or manually stopped
            while not stop_event.is_set():
                time.sleep(1)

            # Check if clients are connected; skip round if no clients are present
            if not clients_dict:
                continue

            print("Starting new game...")
            welcome_message(server_name, trivia_topic)
            if not clients_dict:  # Check after sending welcome message
                print("No clients connected after welcome message. Ending the round early.")
                continue

            correct_answer = send_trivia_question(questions)
            if not clients_dict:  # Check after sending trivia question
                print("No clients connected after sending trivia question. Ending the round early.")
                continue

            # Record the time when the question was sent to measure response times and then collect answers from clients
            trivia_sending_time = time.time()
            get_all_answers(trivia_sending_time)
            if not clients_dict:  # Check after getting answers
                print("No clients connected after collecting answers. Ending the round early.")
                continue

            # Determine the winner of the trivia round and send the winning message to all clients
            winner_client_address = calculate_winner(correct_answer)
            send_winner_message(winner_client_address)

            # Send game statistics to all clients
            send_statistics_to_all_clients()
            print("Round ends")

        except KeyboardInterrupt:
            print("Shutting down the server due to keyboard interrupt.")
            stop_event.set()

        except Exception as e:
            print(e)

        finally:
            if udp_thread:
                udp_thread.join()

            if tcp_thread:
                tcp_thread.join()

            close_all_client_sockets()
            last_connection_time = float('inf')
            print("Server shutdown completed.\n\n")
            time.sleep(2)  # Clearing and reinitializing for a new round


if __name__ == "__main__":
    game_loop()
