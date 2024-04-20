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


def load_trivia_questions(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)


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


# Finds an available tcp port for the server to send to the client in the UDP broadcast message,
# on which the server will listen on, and the client will connect to.
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
    global clients_dict
    global last_connection_time
    if client_address not in clients_dict:
        try:
            received_data = client_socket.recv(1024)  # Adjust buffer size as needed
        except Exception as e:
            handle_socket_error(e, "receiving data", "save_client_info")
            return

        client_name = received_data.decode('utf-8').rstrip('\n')
        clients_dict[client_address] = {"name": client_name,
                                        "socket": client_socket,
                                        "currently_listening_to_client": True,
                                        "client_answers": [],
                                        "answers_times": []}
        last_connection_time = time.time()
    # if the client is already in the dictionary, do nothing. the client is already connected from previous round.


def watch_for_inactivity(stop_event):
    global last_connection_time
    while not stop_event.is_set():
        with time_lock:
            elapsed = time.time() - last_connection_time
        if elapsed >= 10:
            stop_event.set()
            break
        else:
            # Sleep briefly to avoid busy waiting
            time.sleep(1)


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
                handle_socket_error(e, "accepting new connections", "tcp_listening")
        continue  # if a client already connected while waiting for another one, the stop event will be true here. if nobody connected we will just keep waiting


def welcome_message(server_name, trivia_topic, clients_dict):
    message = f"Welcome to the {server_name} server, where we are be answering trivia questions about {trivia_topic}.\n"
    # It's a good practice to list keys to avoid RuntimeError for changing dict size during iteration
    for client_tuple in enumerate(list(clients_dict.keys()), start=1):
        client_info = clients_dict[client_tuple[1]]
        message += f"Player {client_tuple[0]}: {client_info['name']}\n"
    message_encoded = message.encode('utf-8')
    for client in clients_dict.values():
        client["socket"].sendall(message_encoded)
    print(message)


def send_trivia_question(questions) -> bool:
    random_question = random.choice(questions)
    trivia_question = random_question['question']
    trivia_answer = random_question['answer']

    message = "True or False: " + trivia_question
    for client in clients_dict.values():
        try:
            client["socket"].sendall(message.encode('utf-8'))
        except Exception as e:
            handle_socket_error(e, "sendall", "sending_trivia_question")
            continue
    return trivia_answer


def get_answer_from_client(client_address, client_socket, trivia_sending_time):
    client_socket.settimeout(15)
    try:
        client_answer_encoded = client_socket.recv(1024)
        # todo check if client answer = "none"
        client_time_to_answer = round((time.time() - trivia_sending_time), 2)
    except Exception as e:
        handle_socket_error(e, "receiving data", "get_answer_from_client")
        clients_dict[client_address]["client_answers"].append(0)  # if the client didn't answer, put in 0 to mark that
        clients_dict[client_address]["answers_times"].append('didnt answer')  # Put a default high time to indicate no response
        return
    clients_dict[client_address]["answers_times"].append(client_time_to_answer)
    client_answer_decoded = client_answer_encoded.decode('utf-8')
    if "true" in client_answer_decoded:
        with clients_lock:
            clients_dict[client_address]["client_answers"].append(True)
    elif "false" in client_answer_decoded:
        with clients_lock:
            clients_dict[client_address]["client_answers"].append(False)
    else:
        print("Invalid answer received. Bug maybe?")
        return


def get_all_answers(trivia_sending_time: float):
    list_of_threads = []
    for client_address in clients_dict.keys():
        client_socket = clients_dict[client_address]["socket"]
        thread = threading.Thread(target=get_answer_from_client,
                                  args=(client_address, client_socket, trivia_sending_time))
        thread.start()
        list_of_threads.append(thread)  # Store the thread reference in the list

    # Wait for all threads to complete
    for thread in list_of_threads:
        thread.join()


def calculate_winner(correct_answer: bool) -> tuple | None:
    """ this function will go over the dictionary and check who is the player
    that answered correctly first, if exists. if no one answered correctly, it will return None """

    min_timestamp = 99999999999
    min_client_address = None
    for client_address in clients_dict.keys():
        client_answer = clients_dict[client_address]["client_answers"][-1]
        client_time = clients_dict[client_address]["answers_times"][-1]
        if client_answer == 0:  # Skip clients who didn't answer
            continue
        if client_answer == correct_answer and client_time < min_timestamp:
            min_client_address = client_address
            min_timestamp = client_time
    if min_client_address is None:
        return None
    else:
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
            handle_socket_error(e, "sendall", "send_winner_message")
            continue


# def remove_client(client_address, clients_dict):
#     if client_address in clients_dict:
#         clients_dict[client_address]['currently_listening_to_client'] = False  # Mark the client as inactive instead of deleting
#         print(f"Client {clients_dict[client_address]['name']} disconnected.")


def send_statistics_to_all_clients(clients_dict):
    headers = ["Player Name", "Correct Answers", "Average Time"]
    table_data = []

    for addr, info in clients_dict.items():
        if info['currently_listening_to_client']:  # Ensure we only send to active clients
            name = info['name']
            correct_answers = sum(1 for answer in info['client_answers'] if answer)
            total_time = sum(info['answers_times'])
            count_times = len(info['answers_times'])
            average_time = total_time / count_times if count_times > 0 else 0
            # Append player data to the table list
            table_data.append([name, correct_answers, f"{average_time:.2f} seconds"])

    # Create a table using tabulate
    stats_table = tabulate(table_data, headers=headers, tablefmt="pretty")

    # Add a title to the table
    title = "Game Statistics:"
    # Prepending the title centered with newline for separation
    formatted_table = f"\n{title}\n{stats_table}\n"

    # Encode and send
    stats_message_encoded = formatted_table.encode('utf-8')
    for addr, info in clients_dict.items():
        if info['currently_listening_to_client']:
            try:
                info['socket'].sendall(stats_message_encoded)
            except Exception as e:
                handle_socket_error(e, "sendall", "send_statistics_to_all_clients")
                info['currently_listening_to_client'] = False  # Mark client as inactive if sending fails


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
        time.sleep(1)
        for client_address, client_info in list(clients_dict.items()):
            if not is_client_alive(client_info['socket']):
                remove_client(client_address)


def is_client_alive(sock):
    try:
        # this is a non-blocking call
        sock.setblocking(0)
        data = sock.recv(16)
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


questions = [
    {"question": "Has the United States ever hosted the Summer Olympics?", "answer": True},
    {"question": "Is the motto of the Olympics 'Faster, Higher, Stronger, Together'?", "answer": True},
    {"question": "Did the ancient Olympics originate in France?", "answer": False},
    {"question": "Are the Olympic rings colors black, green, red, yellow, and blue?", "answer": True},
    {"question": "Is golf an Olympic sport?", "answer": True},
    {"question": "Were the first modern Olympics held in 1896?", "answer": True},
    {"question": "Has every country in the world participated in the Olympics at least once?", "answer": False},
    {"question": "Are the Winter and Summer Olympics held in the same year?", "answer": False},
    {"question": "Did the original Olympic Games include women as participants?", "answer": False},
    {"question": "Is swimming a part of the Winter Olympics?", "answer": False},
    {"question": "Has Tokyo hosted the Summer Olympics more than once?", "answer": True},
    {"question": "Is the Olympic flame lit in Olympia, Greece, before each Games?", "answer": True},
    {"question": "Did Michael Phelps take the most gold medals in a single Olympics in Olympics history?",
     "answer": True},
    {"question": "Does the city hosting the Olympics also host the Paralympics shortly after?", "answer": True},
    {"question": "Was the marathon originally 26.2 miles when introduced to the Olympics?", "answer": False},
    {"question": "Do the Olympics take place every two years?", "answer": False},
    {"question": "Has a single country ever swept all medals in an Olympic event?", "answer": True},
    {"question": "Is figure skating a part of the Summer Olympics?", "answer": False},
    {"question": "Are Olympic gold medals made entirely of gold?", "answer": False},
    {"question": "Did the Olympic Games continue during World War II?", "answer": False}
]
# def game_loop():
#     threading.Thread(target=monitor_clients, daemon=True).start()
#
# check why its not working with stop_event.wait(timeout=10) instead of time.sleep(10)
if __name__ == "__main__":
    threading.Thread(target=monitor_clients, daemon=True).start()

    while True:
        last_connection_time = 99999999999
        questions = load_trivia_questions("olympics_trivia_questions.json")
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
                time.sleep(5)  # Reduced wait timeout for more responsive handling
                print("Server running...")

            if not any(client['currently_listening_to_client'] for client in clients_dict.values()):
                continue

            # if any(client['currently_listening_to_client'] for client in clients_dict.values()):
            # print("clients dict stat: ", clients_dict)
            print("Starting new game round...")
            udp_thread.join()
            tcp_thread.join()

            welcome_message(server_name, trivia_topic, clients_dict)
            correct_answer = send_trivia_question(questions)
            time.sleep(2)  # Adjust timing as needed
            trivia_sending_time = time.time()
            get_all_answers(trivia_sending_time)
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
    # ------------------------------------------------------- game - loop --------------------------------------------------------------------------- #

    # TODO send first random question to all the players - the clients (new function) - need to test this

    # TODO another function to receive inputs from the players while still liestening and saving all the users input *multi threaded - need to test this

    # TODO collect interesting statistics when the game finished

    # ----------------------------------------------------------------------------------------------------------------------------------------------- #

    # TODO check how to use ANSI color
