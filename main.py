import socket
import threading
import sys
import random
import math
import tkinter as tk
from tkinter import messagebox

from all import *

public_key, private_key = None, None

# Server class for handling client connections
class Server:
    def __init__(self, host, port, gui):
        self.host = host
        self.port = port
        self.server_socket = None
        self.client_socket = None
        self.is_connected = False
        self.gui = gui
        self.stop_event = threading.Event()  # Event to signal thread termination

    def start(self):
        # Create a server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            # Bind the server socket to the specified host and port
            self.server_socket.bind((self.host, self.port))

            # Listen for incoming connections
            self.server_socket.listen(1)
            print("Server started. Waiting for a client connection...")

            # Accept client connection
            self.client_socket, client_address = self.server_socket.accept()
            global public_key, private_key
            public_key, private_key = generate_keypair(17, 23)
            self.send(str(private_key))
            print("Client connected:", client_address)

            # Update connection status
            self.is_connected = True

            # Start a new thread for receiving messages from the client
            receive_thread = threading.Thread(target=self.receive)
            receive_thread.daemon = True
            receive_thread.start()
            self.gui.update_connection_status(True)
        except socket.error as e:
            print("Server error:", str(e))
            self.stop()
            raise ConnectionError(str(e))

    def stop(self):
        # Set the stop event to signal the receive thread to stop
        self.stop_event.set()

        # Close the client socket
        self.client_socket.close()

        self.is_connected = False

        # Close the server socket
        self.server_socket.close()
        print("Server stopped.")
        self.gui.update_connection_status(False)

    def send(self, message):
        try:
            # Send the message to the client
            self.client_socket.send(message.encode())
        except socket.error as e:
            print("Send error:", str(e))

    def receive(self):
        while self.is_connected:
            try:
                # Receive data from the client
                data = self.client_socket.recv(5096).decode()

                if data:
                    # Process the received data
                    process_received_data(data, self.gui)
                else:
                    # Connection closed by the client
                    self.stop()
                    break
            except socket.error as e:
                print("Receive error:", str(e))
                self.stop()

# Client class for connecting to the server
class Client:
    def __init__(self, host, port, gui):
        self.host = host
        self.port = port
        self.client_socket = None
        self.is_connected = False
        self.gui = gui
        self.stop_event = threading.Event()  # Event to signal thread termination

    def connect(self):
        # Create a client socket
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # Connect to the server
            self.client_socket.connect((self.host, self.port))
            print("Connected to the server:", self.host, self.port)
            # Receive data from the server
            data = self.client_socket.recv(5096).decode()
            global private_key
            #data = "(A, B)" -> data = (A, B)
            data = data[1:-1].split(", ")
            private_key = (int(data[0]), int(data[1]))

            # Update connection status
            self.is_connected = True

            # Start a new thread for receiving messages from the server
            receive_thread = threading.Thread(target=self.receive)
            receive_thread.daemon = True
            receive_thread.start()
            self.gui.update_connection_status(True)
        except socket.error as e:
            print("Connection error:", str(e))
            self.disconnect()
            raise ConnectionError(str(e))

    def disconnect(self):
        if self.is_connected:
            # Set the stop event to signal the receive thread to stop
            self.stop_event.set()

            # Close the client socket
            self.client_socket.close()
            print("Disconnected from the server.")
            self.gui.update_connection_status(False)
        self.is_connected = False

    def send(self, message):
        try:
            # Send the message to the server
            self.client_socket.send(message.encode())
        except socket.error as e:
            print("Send error:", str(e))

    def receive(self):
        while self.is_connected:
            try:
                # Receive data from the server
                data = self.client_socket.recv(5096).decode()

                if data:
                    # Process the received data
                    process_received_data(data, self.gui)
                else:
                    # Connection closed by the server
                    self.disconnect()
                    break
            except socket.error as e:
                print("Receive error:", str(e))
                self.disconnect()

# GUI class
class GUI:
    def __init__(self, title, width, height):
        self.title = title
        self.width = width
        self.height = height
        self.server = None
        self.client = None
        self.root = None
        self.message_entry = None
        self.result_label = None
        self.text_area = None
        self.canvas = None
        self.connection_status = None
        self.ip_entry = None

    def set_text(self, text):
        self.message_entry.delete(0,tk.END)
        self.message_entry.insert(0,text)
        return
    
    def start(self):
        # Create the root window
        self.root = tk.Tk()
        self.root.title(self.title)
        self.root.geometry(f"{self.width}x{self.height}")

        # Create a frame to hold the label and entry field
        frame = tk.Frame(self.root)
        frame.pack(padx=5, pady=5)

        # Create the ip text label
        ip_label = tk.Label(frame, text="Enter the IP Address:")
        ip_label.pack(side=tk.LEFT)

        # Create the IP entry field
        self.ip_entry = tk.Entry(frame)
        self.ip_entry.pack(side=tk.LEFT, anchor=tk.CENTER)

        # Create a frame to hold the label and entry field
        frame = tk.Frame(self.root)
        frame.pack(padx=5, pady=5)

        # Create the text message label
        message_label = tk.Label(frame, text="Enter the Message:")
        message_label.pack(side=tk.LEFT)

        # Create the message entry field
        self.message_entry = tk.Entry(frame, width=40)
        self.message_entry.pack(side=tk.LEFT, anchor=tk.CENTER)

        # Create the text area
        self.text_area = tk.Text(self.root, height=10)
        self.text_area.pack(pady=1, expand=True)

        # Create the connection status indicator
        self.connection_status = tk.Canvas(self.root, width=20, height=20)
        self.connection_status.pack(pady=1)
        self.connection_status.configure(bg="red")

        # Create the buttons
        server_button = tk.Button(self.root, text="Start Server", command=self.start_server)
        server_button.pack(pady=10)

        client_button = tk.Button(self.root, text="Connect Client", command=self.connect_client)
        client_button.pack(pady=5)

        sender_text_label = tk.Label(self.root, text="Sender steps:")
        sender_text_label.pack()
        # Create button to apply RSA encryption and decryption   
        encrypt_button = tk.Button(self.root, text="Apply RSA Encryption", command=self.apply_rsa_encrypt)
        encrypt_button.pack()

        # Create buttons to perform the conversion and show the waveform
        convert_button = tk.Button(self.root, text="Convert to Binary", command=self.convert_to_binary)
        convert_button.pack()
        
        # Create buttons to apply differential Manchester encoding and decoding
        encode_button = tk.Button(self.root, text="Apply Differential Manchester Encoding", command=self.apply_differential_manchester)
        encode_button.pack()

        send_button = tk.Button(self.root, text="Send", command=self.send_message)
        send_button.pack(pady=5)

        receiver_text_label = tk.Label(self.root, text="Receiver steps:")
        receiver_text_label.pack()

        decode_button = tk.Button(self.root, text="Apply Differential Manchester Decoding", command=self.apply_differential_manchester_decode)
        decode_button.pack()

        revert_button = tk.Button(self.root, text="Convert to Text", command=self.convert_to_text)
        revert_button.pack()

        decrypt_button = tk.Button(self.root, text="Apply RSA Decryption", command=self.apply_rsa_decrypt)
        decrypt_button.pack()

        # Create a label to display the encrypted/decrypted data
        result_text_label = tk.Label(self.root, text="Result:")
        result_text_label.pack(fill="both")
        self.result_label = tk.Label(self.root, text="")
        self.result_label.pack(fill="both")

        waveform_button = tk.Button(self.root, text="Show Binary Waveform", command=self.show_binary_waveform)
        waveform_button.pack()


        # Create a canvas to display the scrollable waveform
        frame=tk.Frame(self.root,width=300,height=300)
        frame.pack(expand=True) #.grid(row=0,column=0)
        self.canvas=tk.Canvas(frame,bg='#FFFFFF',width=500,height=100,scrollregion=(0,0,5000,0))
        hbar=tk.Scrollbar(frame, orient="horizontal")
        hbar.pack(side="bottom",fill="x")
        hbar.config(command=self.canvas.xview)
        self.canvas.config(width=500,height=100)
        self.canvas.config(xscrollcommand=hbar.set)
        self.canvas.pack(side="left",expand=True)

        # Start the GUI event loop
        self.root.protocol("WM_DELETE_WINDOW", self.stop_gui)  # Bind window close event
        self.root.mainloop()

    def update_connection_status(self, is_connected):
        if is_connected:
            self.connection_status.configure(bg="green")
        else:
            self.connection_status.configure(bg="red")
            if self.server:
                self.server = None
            if self.client:
                self.client = None

    def start_server(self):
        if not self.server:
            SERVER = socket.gethostbyname(socket.gethostname())
            print("listening on " + SERVER + ":5050")
            try:
                self.server = Server(SERVER, 5050, self)
                self.server.start()
                self.append_text("Server started.")
            except socket.error as e:
                print("Server start error:", str(e))
                self.append_text("Server not started.")
                self.server = None
        else:
            messagebox.showinfo("Server", "Server is already running.")

    def connect_client(self):
        if not self.client:
            try:
                SERVER = socket.gethostbyname(socket.gethostname())
                self.client = Client(self.ip_entry.get(), 5050, self)
                self.client.connect()
                self.append_text("Client connected.")
            except socket.error as e:
                print("Client connection error:", str(e))
                self.append_text("Client not connected.")
                self.client = None
        else:
            messagebox.showinfo("Client", "Client is already connected.")

    def send_message(self):
        message = self.result_label.cget("text")
        if self.server and self.server.is_connected:
            self.server.send(message)
        elif self.client and self.client.is_connected:
            self.client.send(message)
        else:
            messagebox.showinfo("Error", "No active connection.")
        self.append_text(f"Me: {message}")
        self.message_entry.delete(0, tk.END)

    def append_text(self, text):
        self.text_area.insert(tk.END, text + "\n")
        self.text_area.see(tk.END)

    def stop_gui(self):
        if self.server:
            self.server.stop()
            self.server = None
        if self.client:
            self.client.disconnect()
            self.client = None
        self.root.destroy()
    
    def apply_rsa_encrypt(self):
        global public_key
        input_text = self.message_entry.get()

        if not input_text:
            messagebox.showwarning("Error", "Please convert a string to binary.")
            return

        # Convert the input text to a list of chars
        input_text = list(input_text)

        # Encrypt the input text using the public key
        encrypted_data = rsa_encrypt(input_text, public_key)

        # Convert the encrypted data to a string
        encrypted_data = ''.join(str(bit) + ' ' for bit in encrypted_data)

        # Display the encrypted data
        self.result_label.config(text=encrypted_data)

    def apply_rsa_decrypt(self):
        global private_key
        # Get the encrypted data from the label
        encrypted_data = self.result_label.cget("text")

        if not encrypted_data:
            messagebox.showwarning("Error", "Please encrypt a string.")
            return

        # Convert the encrypted data to a list of integers
        encrypted_data = encrypted_data.split()
        encrypted_data = [int(bit) for bit in encrypted_data]

        # Decrypt the encrypted data using the private key
        decrypted_data = rsa_decrypt(encrypted_data, private_key)

        # Display the decrypted data
        self.result_label.config(text=decrypted_data)

    def convert_to_binary(self):
        input_text = self.result_label.cget("text")

        if not input_text:
            messagebox.showwarning("Error", "Please enter a string.")
            return

        binary_result = ''.join(format(ord(char), '08b') for char in input_text)
        self.result_label.config(text=binary_result)

    def convert_to_text(self):
        # Get the binary result from the label
        binary_result = self.result_label.cget("text")

        if not binary_result:
            messagebox.showwarning("Error", "Please convert a string to binary.")
            return

        # Convert the binary result to a list of integers
        binary_result = binary_result.replace(" ", "")
        binary_result = [binary_result[i:i + 8] for i in range(0, len(binary_result), 8)]
        binary_result = [int(byte, 2) for byte in binary_result]

        # Convert the binary result to a string
        text_result = ''.join(chr(byte) for byte in binary_result)

        # Display the text result
        self.result_label.config(text=text_result)


    def apply_differential_manchester(self):
        # Get the binary result from the label
        binary_result = self.result_label.cget("text")

        if not binary_result:
            messagebox.showwarning("Error", "Please convert a string to binary.")
            return

        # Convert the binary result to a list of integers
        binary_result = binary_result.replace(" ", "")
        binary_result = [int(bit) for bit in binary_result]

        # Apply differential Manchester encoding
        encoded_data = differential_manchester_encode(binary_result)

        # Convert the encoded data to a string
        encoded_data = ''.join(str(bit) for bit in encoded_data)

        # Display the encoded data
        self.result_label.config(text=encoded_data)

    def apply_differential_manchester_decode(self):
        # Get the binary result from the label
        binary_result = self.message_entry.get()

        if not binary_result:
            messagebox.showwarning("Error", "Please convert a string to binary.")
            return

        # Convert the binary result to a list of integers
        binary_result = binary_result.replace(" ", "")
        binary_result = [int(bit) for bit in binary_result]

        # Apply differential Manchester encoding
        decoded_data = differential_manchester_decode(binary_result)

        # Convert the encoded data to a string
        decoded_data = ''.join(str(bit) for bit in decoded_data)

        # Display the encoded data
        self.result_label.config(text=decoded_data)

    def show_binary_waveform(self):
        bits = self.result_label.cget("text")
        waveform_width = 10  # Width of each bit in the waveform
        waveform_height = 80  # Height of the waveform

        self.canvas.delete("waveform")  # Clear the canvas

        # Draw the waveform
        x = 10
        last_bit = 1
        for bit in bits:
            if bit == '1':
                self.canvas.create_line(x, 10, x+waveform_width, 10, fill="black", tags="waveform")
            else:
                self.canvas.create_line(x, waveform_height, x+waveform_width, waveform_height, fill="black", tags="waveform")
            if last_bit != bit:
                self.canvas.create_line(x, 10, x, waveform_height, fill="black", tags="waveform")
            x += waveform_width
            last_bit = bit

def process_received_data(data, gui):
    # Process the received data here
    # You can modify this function to handle the received data as per your requirements
    print("Received:", data)
    gui.append_text(f"Other: {data}")
    gui.set_text(data)

gui = GUI("Chat with Differential Manchester", 400, 1000)
gui.start()

quit()
