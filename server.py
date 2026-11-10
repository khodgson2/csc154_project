# server

from dataclasses import dataclass
import socket
import threading
import json


@dataclass
class client_record:
    username: str
    public_key: str
    connection: socket
    is_online: bool


client_records = []
threads = []

port_num: int
START_PORT_NUM = 4000
NUM_BYTES = 2048



def conn_thread(record: client_record):
    print("Thread started for user: " + record.username)

    #create a list of users who are currently online
    online_users = "Online users: "
    for rec in client_records:
        if rec.is_online == True:
            online_users += rec.username + ", "

    #send user the list of currently online users
    send_message(conn=record.connection, msg_to=record.username, 
                         msg_from = "server", 
                         msg="You are connected to the server.\n "
                         + online_users)

    while True:
        try:
            data = record.connection.recv(NUM_BYTES)
        except:
            print("Error connecting to " + record.username)
            break

        if not data:
            break

        data_json = json.loads(data.decode("utf-8"))

        #quit loop and close connection if user is quitting or if necessary fields aren't
        #present in data
        if (not data_json["type"]) or data_json["type"] == "quit":
            break
        if (not data_json["to"]) or (not data_json["from"]) or (not data_json["message"]):
            break

        #print the user's message
        print("Received message from " + data_json["from"] + " to "
              + data_json["to"] + ":")
        print(data_json["message"])
        print()
        
        # attempt to find a record for the message's recipient
        to_rec = None
        for rec in client_records:
            if rec.username and data_json["to"]:
                if rec.username == data_json["to"]:
                    to_rec = rec
                    break
            
        # send message to recipient
        if (to_rec) and (to_rec.connection) and (to_rec.is_online == True) and data_json["message"]:
            send_message(conn=to_rec.connection, msg_to=data_json["to"],
                         msg_from=data_json["from"], msg=data_json["message"])

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



def start_listening():
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
        print(json.dumps(data_json))

        #close connection if message type isn't "connect"
        if (not data_json["type"]) or (data_json["type"] != "connect"):
            conn.close()

        # attempt to find a record for this client
        client_rec = None
        for record in client_records:
            if record.username and data_json["from"]:
                if record.username == data_json["from"]:
                    client_rec = record
                    break

        #add a record for the client if none exists
        if client_rec is None:
            client_rec = client_record(username = data_json["from"],
                                       public_key = 'a',
                                        connection = conn, is_online = False)
            client_records.append(client_rec)

        # if record existed for old connection, set connection to new one
        if client_rec.connection is None:
            client_rec.connection = conn

        #create a thread for this connection
        if client_rec.is_online == False:
            client_rec.is_online = True
            t = threading.Thread(target = conn_thread, args = (client_rec,))
            threads.append(t)
            t.start()

    for t in threads:
        t.join()
    for rec in client_records:
        rec.connection.close()



def send_message(conn:socket, msg_to:str, msg_from:str, msg:str):
    msg_json = json.dumps(
        {
            "to": msg_to,
            "from": msg_from,
            "message":msg
        }
    )
    conn.sendall(msg_json.encode("utf-8"))



def run_server():
    start_listening()



if __name__ == "__main__":
    run_server()
