# CSC154 Project: Secure Chat Application
Kyra Hodgson
Fall  2026

This project requires the cryptography module. To install it, run:
    pip install cryptography

How to run the server application:

1. Run 'py server.py' from a terminal in the project directory.
2. Enter 'y' or 'n' to the prompt to choose whether or not the server should tamper with messages. If you enter 'y' to the first prompt, the program will display additional prompts that allow you to choose how the server will tamper with messages. If any of these options are selected, the server will apply 1 selected option to each message that is sent until all options have been applied. 
3. After you have responded to the prompts in step 2, the server will start running on port 4000. When a server receives a message, it will print the contents of the message to the terminal.

How to run the client application:

1. Start the server program.
2. Run 'py client.py' from a terminal in the project directory. 
3. Enter a username and password.
4. The program will generate an RSA key pair, connect to the server, and display a list of all users who are currently online. 
5. To send a message, enter the username of the user whom you want to send a message to. Then, enter the message when prompted. 
To quit the program, enter 'q'. 
To view unread messages in your inbox, enter 'v'. Messages are not automatically displayed when they are received.