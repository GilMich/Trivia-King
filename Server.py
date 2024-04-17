import socket
import socket as sock
import threading
import time
import netifaces
import random

clients_dict = {}
last_connection_time = time.time()
user_successfully_connected = False
time_lock = threading.Lock()
clients_lock = threading.Lock()
server_name = "Trivia King"
trivia_topic = "The Olympics"

def handle_socket_error(e, sock: socket, operation: str):
    """
     Handle exceptions for socket operations and print client IP involved.

     Parameters:
         :param sock: The socket instance involved in the operation.
         :param e: (Exception): The exception instance caught during socket operations.
         :param operation: (str): The operation during which the exception was caught ('connect', 'accept', etc.).

     Returns:
            None
     """
    client_info = ''
    try:
        if operation == 'accept' and sock:
            # For accept, we need to check the last connected client, but it's usually not available directly
            # because the exception prevents establishment of the connection.
            client_info = 'Unknown.'
        elif sock:
            # Get information about the connected peer
            client_info = sock.gethostname()
        else:
            client_info = 'Unknown.'
    except sock.error:
        # If get-hostname() fails, the socket is likely not connected
        client_info = 'Unknown.'

    base_error_message = f" Error during: {operation} with: {client_info}: {e}"

    if isinstance(e, sock.timeout):
        print(f" Timeout with {client_info} during {operation}.")
    elif isinstance(e, sock.error):
        print( base_error_message)
    elif isinstance(e, BlockingIOError):
        print(f"Non-blocking operation could not complete with {client_info} during {operation}.")
    elif isinstance(e, ConnectionResetError):
        print(f"Connection reset by the peer {client_info} during {operation}.")
    elif isinstance(e, OSError):
        print(base_error_message)
    else:
        print(f"An unexpected error occurred with {client_info} during {operation}.")


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


def save_client_info(client_socket, client_address, stop_event):    #todo need to edit return value to bool or int indicating error
    global clients_dict
    global last_connection_time
    global user_successfully_connected
    while not stop_event.is_set():
        # Receive data from the client
        client_socket.settimeout(20)
        try:
            received_data = client_socket.recv(1024)  # Adjust buffer size as needed
        except Exception as e:
            handle_socket_error(e  , client_socket, "recv")
            continue

        client_name = received_data.decode('utf-8').rstrip('\n')
        if client_name not in clients_dict.keys():
            clients_dict[client_name] = {"address": client_address, "socket": client_socket, "client_answers": [], "answers_time": [], "rounds_won": 0}
            client_socket.sendall(f"Welcome {client_name}, please wait for all clients to join...\n".encode('utf-8'))
            with time_lock:
                user_successfully_connected = True
                last_connection_time = time.time()
            break # break the loop if the name is unique
        else:
            try:
                client_socket.sendall(f"The name {client_name} is already taken, please choose another one.\n".encode('utf-8'))
            except Exception as e:
                handle_socket_error(e, client_socket, "sendall")
            continue


        # todo handle at the client side


def watch_for_inactivity(stop_event):
    global last_connection_time
    while not stop_event.is_set():
        with time_lock:
            elapsed = time.time() - last_connection_time
        if elapsed >= 10 and user_successfully_connected:
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
    global last_connection_time
    while not stop_event.is_set():
        try:
            client_socket, client_address = server_socket.accept()  # blocking method to accept new connection. if it waits here more than 10sec it will go to except
            print(f"Accepted a connection from {client_address}")
            # Handle the connection in a new thread
            threading.Thread(target=save_client_info, args=(client_socket, client_address,stop_event)).start()
            threading.Thread(target=watch_for_inactivity, args=(stop_event,)).start()
        except Exception as e:
            handle_socket_error(e, server_socket, "accept")

        continue  # if a client already connected while waiting for another one, the stop event will be true here. if nobody connected we will just keep waiting


def welcome_message(server_name, trivia_topic, clients_dict):
    message = f"welcome to the {server_name} server where we will be answering trivia questions about {trivia_topic}.\n"
    # It's a good practice to list keys to avoid RuntimeError for changing dict size during iteration
    for client_index, client_name in enumerate(list(clients_dict.keys()), start=1):
        message += f"Player {client_index}: {client_name}\n"
    message_encoded = message.encode('utf-8')
    for client in clients_dict.values():
        client["socket"].sendall(message_encoded)
    print(message)


def send_trivia_question() -> bool:
    random_trivia = random.choice(olympics_trivia_questions)
    trivia_question = random_trivia[0]
    trivia_answer = random_trivia[1]
    message = "True or False: " + trivia_question + "\n"
    for client_name in clients_dict.keys():
        try:
            clients_dict[client_name]["socket"].sendall(message.encode('utf-8'))
        except Exception as e:
            print(f"Error sending trivia question to {client_name}: {e}")

    return trivia_answer


def get_answer_from_client(client_address, client_socket, question_start_time)
    client_socket.settimeout(15)
    try:
        client_answer_encoded = client_socket.recv(1024)
    except socket.timeout:
        clients_dict[client_address]["client_answers"].append(None)
        return

    clients_dict[client_address]["answers_time"].append(time.time())
    client_answer_decoded = client_answer_encoded.decode('utf-8')
    if "true" in client_answer_decoded:
        clients_dict[client_address]["client_answers"].append(True)

    elif "false" in client_answer_decoded:
        clients_dict[client_address]["client_answers"].append(False)

    else:
        print("alon gay")  # this shouldn't happen


def get_all_answers(question_start_time: float):
    for client_address in clients_dict.keys():
        client_socket = clients_dict[client_address]["socket"]
        threading.Thread(target=get_answer_from_client, args=(client_address, client_socket,question_start_time)).start()


def calculate_winner(correct_answer: bool) -> tuple | None:
    """ this function will go over the dictionary and check who is the player
    that answered correctly first, if exists. if no one answered correctly, it will return None """

    min_timestamp = 99999999999
    min_client_address = None
    for client_address in clients_dict.keys():
        client_answer = clients_dict[client_address]["client_answers"][-1]
        if client_answer == correct_answer:
            if clients_dict[client_address]["answers_time"][-1] < min_timestamp:
                min_timestamp = clients_dict[client_address]["answers_time"][-1]
                min_client = client_address
    if min_client_address is None:
        return None
    else:
        return min_client_address


olympics_trivia_questions = [
    ("Has the United States ever hosted the Summer Olympics?", True),
    ("Is the motto of the Olympics 'Faster, Higher, Stronger, Together'?", True),
    ("Did the ancient Olympics originate in France?", False),
    ("Are the Olympic rings colors black, green, red, yellow, and blue?", True),
    ("Is golf an Olympic sport?", True),
    ("Were the first modern Olympics held in 1896?", True),
    ("Has every country in the world participated in the Olympics at least once?", False),
    ("Are the Winter and Summer Olympics held in the same year?", False),
    ("Did the original Olympic Games include women as participants?", False),
    ("Is swimming a part of the Winter Olympics?", False),
    ("Has Tokyo hosted the Summer Olympics more than once?", True),
    ("Is the Olympic flame lit in Olympia, Greece, before each Games?", True),
    ("Did Michael Phelps took the most gold medals in a single olympic in olympics history?", True),
    ("Does the city hosting the Olympics also host the Paralympics shortly after?", True),
    ("Was the marathon originally 26.2 miles when introduced to the Olympics?", False),
    ("Do the Olympics take place every two years?", False),
    ("Has a single country ever swept all medals in an Olympic event?", True),
    ("Is figure skating a part of the Summer Olympics?", False),
    ("Are Olympic gold medals made entirely of gold?", False),
    ("Did the Olympic Games continue during World War II?", False)
]

if __name__ == "__main__":
    stop_event = threading.Event()
    server_port = find_free_port()
    # Initialize threads
    print(f"Server started, listening on IP address: {get_local_ip()}")
    udp_thread = threading.Thread(target=udp_broadcast, args=(server_name, server_port, stop_event))
    tcp_thread = threading.Thread(target=tcp_listener, args=(server_port, stop_event))

    # Start threads
    udp_thread.start()
    tcp_thread.start()

    # Wait for the stop_event to be set
    while not stop_event.is_set():
        stop_event.wait(timeout=10)  # wait to avoid busy waiting

    # Ensure both udp thread and tcp thread completed
    udp_thread.join()
    tcp_thread.join()

    # Game mode !

    # Server sends welcome message to all the players:
    welcome_message(server_name, trivia_topic, clients_dict)

    trivia_answer = send_trivia_question()
    question_start_time = time.time()
    get_all_answers()
    winner_address = calculate_winner(trivia_answer)
    print()

    # ------------------------------------------------------- game - loop --------------------------------------------------------------------------- #
    # TODO
    # TODO implement functionality to determine the first (!) one who answers correctly if exists using a timestamp... need to test
    # TODO show how many seconds passed since the question was sent until every player answered for those who answered correctly
    # TODO save for every player how many rounds won in a row
    # TODO implement function to re-send trivia question if no one answered correctly.
    # TODO collect interesting statistics when the game finished
    # TODO
    # ----------------------------------------------------------------------------------------------------------------------------------------------- #

    # TODO check how to use ANSI color


