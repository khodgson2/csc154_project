
"""
Client program
See README.md for instructions on running the program.
See msg_format.txt for information about how messages are formatted.

def connect_to_server():
    Connects to the server, sends a message with the user's username and public key, and returns 
    the socket of the tcp connection to the server.

def close_connection(): 
    Sends a message to the server to inform it that the user is closing the 
    connection, then closes the connection.

def send_message():
    gets user input and returns a char describing the user input. If the user has chosen
    to send a message, creates a message to another user and sends it to the server.

def find_user_pub_key():
    gets a user's public key by searching the contacts list and sending a public key request 
    to the server 

def listen_thread():
    Is run as a thread. Listens for messages, stores them to msg_buffer, creates entries in 
    the contacts list for users, and handles responses to public key requests

def print_msgs():
    prints all the messages in the buffer. If a message is a regular message from another user,
    it decrypts and verifies the message first.

"""

import socket
import json
import base64
import threading
from secure_message import (
    generate_keypair,
    sender_encrypt_and_sign,
    receiver_decrypt_and_verify,
    b64,
)
from time import sleep
from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization


username = "user1"
NUM_BYTES = 2048
SERVER_PORT = 4000
SERVER_ADDR = '127.0.0.1'

msg_buffer = []     # messages that were received by listen_thread
contacts = []       #list of contacts to keep track of users' public keys, sequence numbers

@dataclass
class contact:
    username: str           #the sender's username
    public_key: str     #initialized to "" if a contact is created without public key
    other_seq_num: int      #the other sender's sequence number. Initialized to 0
    my_seq_num: int         #this process' sequence number. initialized to 0



def connect_to_server() -> socket:
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((SERVER_ADDR, SERVER_PORT))

    msg_from = username 
    msg_type = "connect"

    #send connection message to server
    message = {
        "from": msg_from,
        "type": msg_type,
        "pub_key": base64.b64encode(
            public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        ).decode()
    }
    message_json = json.dumps(message)

    tcp.sendall(message_json.encode("utf-8"))
    print("Successfully connected to server.")
    
    return(tcp)



def close_connection(tcp: socket):
    message = json.dumps(
        {
            "from": username,
            "type": "quit",
        }
    )
    try:
        tcp.sendall(message.encode("utf-8"))
    except:
        return

    tcp.close()



def send_message(tcp: socket) -> str:
    """
    Sends a message. 
    Returns 'q' if the user is quitting the program.
    Returns 'c' if the connection was closed.
    Returns an empty string otherwise.
    """

    usr_contact = None
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

    recipient_pub_key = find_user_pub_key(msg_to.strip(), tcp)
    if recipient_pub_key is None:
        print("Error: Could not find " + msg_to + "'s public key.")
        return 

    #encrypt
    encrypted_msg = sender_encrypt_and_sign(msg_text, msg_from, msg_to, 
                                            recipient_pub_key, private_key)

    #increment sequence number
    #get user's contact, which exists if user's public key was found
    for c in contacts:
        if c.username == msg_to:
            usr_contact = c
            break

    contact_index = contacts.index(usr_contact)
    contacts[contact_index].my_seq_num += 1 

    message = json.dumps(
        {
            "to": msg_to,
            "from": msg_from,
            "seq_num": usr_contact.my_seq_num,
            "type": msg_type,
            "message": encrypted_msg
        }
    )

    try:
        tcp.sendall(message.encode("utf-8"))
    except:
        print("The connection to the server was closed.")
        return('c')

    print("Sent message.")

    return " "


def find_user_pub_key(uname: str, tcp:socket):
    """
    Tries to find a user's public key by first searching the list of stored public keys,
    then by sending a message to the server
    """

    usr_pub_key = None

    #try to find user in existing contacts
    for c in contacts:
        if c.username == uname and c.public_key != "":
            decoded_key = serialization.load_pem_public_key(
                base64.decodebytes(bytes(c.public_key, "utf-8")))
            return decoded_key

    #if user's record wasn't found, ask server for public key
    message = json.dumps(
        {
            "to": uname,
            "from": username,
            "type": "public key request"
        }
        )
    try:
        tcp.sendall(message.encode("utf-8"))
    except:
        print("The connection to the server was closed.")
        usr_pub_key = None

    # wait for the listening thread to get a response and add the 
    # contact to the list. It would probably be better to wait using condition
    # variables instead of sleep here
    sleep(1)
    #search the list of contacts again
    for c in contacts:
        if c.username == uname and c.public_key != "":
            usr_pub_key = c.public_key
            break

    # return None if public key wasnt found
    if usr_pub_key is None:
        return None

    #otherwise, decode public key
    decoded_key = serialization.load_pem_public_key(
        base64.decodebytes(bytes(usr_pub_key, "utf-8")))
    return decoded_key



def listen_thread(tcp: socket):
    """
    Listens for messages from the server and adds them to a buffer.
    """

    while True:
        try:
            data = tcp.recv(NUM_BYTES)
        except:
            break
        
        if data:
            # create json from message
            msg_output = ""
            data_json = json.loads(data.decode("utf-8"))
            data_dict = dict(data_json)

            #if the message is from a user, try to find their entry in contacts list
            if not (data_dict["from"] == "server" or data_dict["from"] == "error"):
                sender_contact = None
            
                for c in contacts:
                    if c.username == data_dict["from"]: 
                        sender_contact = c
                        break

                #create a contact for this user if none exists
                if (sender_contact is None) and (data_dict["type"] == "message"):
                    sender_contact = contact(username = data_dict["from"], public_key = "",
                                             other_seq_num = 0, my_seq_num = 0)
                    contacts.append(sender_contact)

                # if the message is a regular message from another user,
                # update and verify the sequence number
                if (sender_contact is not None) and (data_dict["type"] == "message"):
                    contact_index = contacts.index(sender_contact)
                    contacts[contact_index].other_seq_num += 1
                    #if sequence num is incorrect, store an error message 
                    if contacts[contact_index].other_seq_num != data_dict["seq_num"]:
                        data_dict["message"] = "Error: received message from " + data_dict["from"] + " with" \
                        " an invalid sequence number."
                        data_dict["from"] = "error"

            # handle response to a public key request
            if data_dict["type"] == "public key response":
                #if sender isn't in contacts, add them to the contacts list
                if sender_contact is None:
                    sender_contact = contact(username = data_dict["from"].strip(),
                                             public_key = data_dict["message"].strip(), 
                                             my_seq_num = 0, other_seq_num = 0)
                    contacts.append(sender_contact)
                else:
                    #add public key to existing contact
                    contact_index = contacts.index(sender_contact)
                    contacts[contact_index].public_key = data_dict["message"].strip()

             #store message in buffer
            if data_dict["type"] == "message" or data_dict["type"] == "error":
                msg_buffer.append(data_dict)



def print_msgs(conn: socket):
    """
    Decrypts and prints messages in the buffer.
    """

    msg_output = ""
    while msg_buffer:
        msg_output = ""
        msg = msg_buffer.pop(0)

        #decrypt message first if from user
        if not (msg["from"] == "server" or msg["from"] == "error"):
            #get sender's public key
            sender_pub_key = find_user_pub_key(msg["from"], conn)

            if sender_pub_key is None:
                msg_output = "Error decrypting message from " + msg["from"] +":"
                msg_output +=  " sender's public key could not be found."

            #if sender's public key was found, decrypt message and print text
            else:
                decrypted_msg = receiver_decrypt_and_verify(msg["message"], msg["from"],
                    msg["to"], private_key, sender_pub_key)

                msg_output += "message from " + msg["from"] + ": \t\""
                msg_output += decrypted_msg + "\"" + "\t|\tsequence number: " + str(msg["seq_num"])

        #if message is from server or is error message, it doesn't need to be decrypted
        else:
            msg_output += "message from " + msg["from"] + ": \t\"" + msg["message"] + "\""

        print(msg_output)




if __name__ == "__main__":

    username = input("Enter your username:\t")
    username = username.strip()

    password = input("Enter a password to use for RSA key generation:\t")
    password = password.strip()
    password = bytes(password, encoding="utf-8")

    # generate key pair
    print("Generating keys...")
    private_key, public_key = generate_keypair(username, password)

    tcp = connect_to_server()

    t_listen = threading.Thread(target = listen_thread, args=(tcp,))
    t_listen.start()

    ret_val = " "

    print("Waiting for confirmation message from server...")
    if len(msg_buffer) < 1:
        sleep(1)

    #print message from server listing online users
    if msg_buffer:
        print_msgs(tcp)

    while ret_val != "q" and ret_val != "c":

        if ret_val == "v":
        #print any messages in the buffer
            if (msg_buffer):
                print("\n = = = = = = = = = = = = = inbox  = = = = = = = = = = = = =")
            else:
                print("You have no new messages.")

            print_msgs(tcp)

        #allow the user to send a message
        ret_val = send_message(tcp)

    print("Stopping the program.")
    t_listen.join(1)
    close_connection(tcp)
    exit()