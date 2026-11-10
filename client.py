# client

import socket
import json
import threading
from time import sleep

username = "user1"
NUM_BYTES = 2048
SERVER_PORT = 4000
SERVER_ADDR = '127.0.0.1'

msg_buffer = []


def connect_to_server() -> socket:
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((SERVER_ADDR, SERVER_PORT))

    msg_from = username 
    msg_type = "connect"

    #send connection message to server
    message = json.dumps(
        {
            "from": msg_from,
            "type": msg_type,
        }
    )

    tcp.sendall(message.encode("utf-8"))
    print("Successfully connected to server.")
    
    return(tcp)



def close_connection(tcp: socket):
    message = json.dumps(
        {
            "from": username,
            "type": "quit",
        }
    )

    tcp.sendall(message.encode("utf-8"))

    tcp.close()



def send_message(tcp: socket) -> str:
    """
    Sends a message and waits for a response. 
    Returns 'q' if the user is quitting the program.
    Returns 'c' if the connection was closed.
    Returns an empty string otherwise.
    """

    msg_text = "hi"
    msg_to = "user1"
    msg_from = username
    msg_type = "message"

    print("\n = = = = = = = = = = send a message  = = = = = = = = = =")
    msg_to = input("Enter the recipient's username, 'v' to view inbox, or 'q' to quit:\t")
    msg_to = msg_to.strip()
    if (msg_to == "q"):
        return "q"
    if (msg_to == "v"):
        return "v"

    msg_text = input("Enter a message to send, 'v' to view inbox, or 'q' to quit:\t")
    msg_text = msg_text.strip()
    if (msg_text == "q"):
        return "q"
    if (msg_text == "v"):
        return "v"

    print()

    message = json.dumps(
        {
            "to": msg_to,
            "from": msg_from,
            "type": msg_type,
            "message": msg_text
        }
    )

    try:
        tcp.sendall(message.encode("utf-8"))
    except:
        print("The connection to the server was closed. Attempting to restart the connection.")
        return('c')

    print("Sent message.")

    return " "



def listen_thread(conn: socket):
    """
    Listens for messages from the server and adds them to a buffer.
    """

    while True:
        try:
            data = tcp.recv(NUM_BYTES)
        except:
            break
        
        if data:
            msg_output = ""
            data_json = json.loads(data.decode("utf-8"))
            msg_output += "message from " + data_json["from"] + ": \t\""
            msg_output += data_json["message"] + "\""

            msg_buffer.append(msg_output)



if __name__ == "__main__":

    username = input("Enter your username:\t")
    username = username.strip()
    
    tcp = connect_to_server()

    t_listen = threading.Thread(target = listen_thread, args=(tcp,))
    t_listen.start()

    ret_val = " "

    print("Waiting for confirmation message from server...")
    if len(msg_buffer) < 1:
        sleep(1)

    #print message from server listing online users
    output = msg_buffer.pop()
    print(output)

    while ret_val != "q" and ret_val != "c":

        if ret_val == "v":
        #print any messages in the buffer
            if (len(msg_buffer) > 0):
                print("\n = = = = = = = = = = = = = inbox  = = = = = = = = = = = = =")
            else:
                print("You have no new messages.")

            while len(msg_buffer) > 0:   
                output = msg_buffer.pop(0)
                print(output)

        #allow the user to send a message
        ret_val = send_message(tcp)

    print("Stopping the program.")
    t_listen.join(1)
    close_connection(tcp)
    exit()