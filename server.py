"""
Server program
See README.md for instructions on running the program.
See msg_format.txt for information about how messages are formatted.

def conn_thread(): 
    Is run as a thread that handles one user's connection. Listens for messages, responds to public
    key requests for other users' keys, and forwards messages to their recipients.

def start_listening():
    Listens on port 4000 and creates new threads for user connections.

def send_message():
    Sends a message and applies tamper options.
"""

from dataclasses import dataclass
import socket
import threading
import json
import base64


@dataclass
class client_record:
    username: str
    public_key: str
    connection: socket
    is_online: bool

@dataclass 
class msg_record:
    msg_to: str
    msg_from: str
    message: str

client_records = []     #list of user records
threads = []            #list of threads created to handle user connections
msg_records = []    #list of message records

port_num: int
START_PORT_NUM = 4000
NUM_BYTES = 2048



def conn_thread(record: client_record, tamper_flags: dict):
    """
    A thread for an individual user's connection.
    """

    print("Thread started for user: " + record.username)

    #create a list of users who are currently online
    online_users = "Online users: "
    for rec in client_records:
        if rec.is_online == True:
            online_users += "'" + rec.username + "' "

    #send user the list of currently online users
    send_message(conn=record.connection, msg_to=record.username, 
                         msg_from = "server", 
                         msg="You are connected to the server. "
                         + online_users)

    #main loop of listening for and responding to messages

    while True:
        try:
            data = record.connection.recv(NUM_BYTES)
        except:
            print("Error connecting to " + record.username)
            break

        if not data:
            break

        data_json = json.loads(data.decode("utf-8"))

        #handle public key requests

        if data_json["type"] == "public key request":
            to_rec = None
            for rec in client_records:
                if rec.username == data_json["to"].strip():
                    to_rec = rec
                    break
            if to_rec is not None:
                send_message(conn=record.connection, msg_to=record.username, 
                         msg_from = data_json["to"], 
                         msg_type="public key response",
                         msg=to_rec.public_key)
                print("Responded to public key request by " + record.username + " for " 
                      + data_json["to"] + "'s key")
            else: 
                send_message(conn=record.connection, msg_to=record.username, 
                             msg_from = "server", msg="Could not get " +
                               data_json["to"] + "'s public key.",
                             msg_type="error")

        # handle normal messages to other users

        if data_json["type"] == "message":
            #print the user's message
            print("Received message from " + data_json["from"] + " to "
              + data_json["to"] + ":")
            print(data_json["message"])
            print()

            #save the message
            msg_rec = msg_record(msg_to=data_json["to"], msg_from=data_json["from"], 
                              message=data_json["message"])
            msg_records.append(msg_rec)
        
            # attempt to find a record for the message's recipient
            to_rec = None
            for rec in client_records:
                if rec.username and data_json["to"]:
                    if rec.username == data_json["to"]:
                        to_rec = rec
                        break
            
            # send message to recipient
            if (to_rec) and (to_rec.connection) and (to_rec.is_online == True) and data_json["message"]:
                tamper_flags = send_message(conn=to_rec.connection, msg_to=data_json["to"],
                         msg_from=data_json["from"], msg=data_json["message"], 
                         seq_num=data_json["seq_num"],
                         tamper_flags = tamper_flags)

            #if no user exists, send error message to user
            else: 
                send_message(conn=record.connection, msg_to=record.username, 
                         msg_from = "server", 
                         msg="Error: could not send message to "
                         + data_json["to"] + ".")


    print("Closing connection to " + record.username + ".")
    record.is_online = False
    record.connection.close()
    record.connection = None



def start_listening(tamper_flags:dict):
    """
    Listens on port 4000 and creates threads for new connections.
    """

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port_num = START_PORT_NUM
    tcp.bind(('127.0.0.1', port_num))
    tcp.listen()

    print("Listening on port " + str(port_num) + ".")
    
    while True:

        #accept a connection
        conn, addr = tcp.accept()
        data = conn.recv(port_num)
        if not data:
            break

        data_json = json.loads(data)

        #close connection if message type isn't "connect"
        if (not data_json["type"]) or (data_json["type"] != "connect"):
            conn.close()

        # update old record for client if one exists
        client_rec = None
        for record in client_records:
            if record.username and data_json["from"]:
                if record.username == data_json["from"]:
                    client_rec = record
                    client_rec.connection = conn
                    client_rec.public_key = data_json["pub_key"]
                    break

        #add a record for the client if none exists
        if client_rec is None:
            client_rec = client_record(username = data_json["from"],
                                       public_key = data_json["pub_key"],
                                        connection = conn, is_online = False)
            client_records.append(client_rec)

        #create a thread for this connection
        if client_rec.is_online == False:
            client_rec.is_online = True
            t = threading.Thread(target = conn_thread, args = (client_rec,tamper_flags,))
            threads.append(t)
            t.start()

    for t in threads:
        t.join()
    for rec in client_records:
        rec.connection.close()



def send_message(conn:socket, msg_to:str, msg_from:str, msg, msg_type = "message",
                 tamper_flags = {"flip_bit": False, "send_to_wrong_user":False,
                                 "change_header": False, "resend_message": False}, 
                                 seq_num = 0):
    """
    Sends the arguments in a JSON string and applies tamper options. 
    """

    msg_dict = {
            "to": msg_to,
            "from": msg_from,
            "seq_num": seq_num,
            "type": msg_type,
            "message":msg
        }

    # if the message was sent by a user and tamper options were selected,
    # then set flag to false to indicate that option has been applied 
    if not (msg_from == "server" or msg_from == "error") and msg_type == "message": 
        if tamper_flags["flip_bit"] == True:
            #flip the first bit of the ciphertext
            ct = bytearray(msg["ciphertext"], "utf-8")
            ct[0] ^= 1
            msg_dict["message"]["ciphertext"] = base64.b64encode(ct).decode()

            print("\n1 bit of the message has been flipped.")
            tamper_flags["flip_bit"] = False

        elif tamper_flags["resend_message"] == True:
            #send message an extra time
            msg_json = json.dumps(msg_dict)
            conn.sendall(msg_json.encode("utf-8"))

            print("\nThe message will be sent twice.\n")
            tamper_flags["resend_message"] = False

        elif tamper_flags["send_to_wrong_user"] == True:
            #find a user that isn't the recipient and send the message on their connection
            for c in client_records:
                if c.username != msg_to:
                    new_recipient = c.username
                    conn = c.connection
                    break

            print("\nThe message will be sent to " + new_recipient + ". If there is only one user, " \
            "this option will not be applied.\n")
            tamper_flags["send_to_wrong_user"] = False

        elif tamper_flags["change_header"] == True:
            msg_dict["to"] = msg_from
            print("The recipient of the message has been modified.")
            tamper_flags["change_header"] = False 

    #send the message
    msg_json = json.dumps(msg_dict)

    try:
        conn.sendall(msg_json.encode("utf-8"))
        print("Sent or forwarded message from " + msg_from + " to " + msg_to + ".")
    except:
        print("Connection error.")

    return tamper_flags
        



if __name__ == "__main__":

    #get user input to determine whether server tampers with messages

    flip_bit = change_header = send_to_wrong_user = resend_message = False

    if input("Should the server behave maliciously? (y/n): ").strip().lower() == "y":
        print("Please specify which malicious actions the server should take.")
        print("The server will apply one option to each message until all selected options")
        print ("have been applied.")
        flip_bit = (input("Should the server flip a bit in a message's ciphertext? (y/n): ")
                     .strip().lower() == "y")
        send_to_wrong_user = (input("Should the server send a message to the wrong user? (y/n): ")
                             .strip().lower() == "y")
        resend_message = (input("Should the server send a message twice? (y/n): ")
                                     .strip().lower() == "y")
        change_header = (input("Should the server change a message's header? (y/n): ")
                                             .strip().lower() == "y")

    tamper_flags = {
        "flip_bit": flip_bit,
        "send_to_wrong_user": send_to_wrong_user,
        "resend_message": resend_message,
        "change_header": change_header 
    }

    #start the server
    print("\nStarting server...")
    start_listening(tamper_flags)