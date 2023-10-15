import socket
import random
from _thread import *
import datetime

def check_FIN(msg):
    # print("In check FIN: the msg is ", msg)
    #msg["ACK"]
    return msg["FIN"] == "1".encode()

def check_ACK(msg):
    #print ("In check ACK: the msg is ", msg)
    # ACK = msg[25:26]
    return msg["ACK"] == "1".encode()

#Created new thread and new data socket for server (port number is randomly generated in the welcome socket)
def new_socket_thread(addr, port):

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as data_socket:
        #bind the socket to a OS port
        data_socket.bind((addr, port))
        print("New Socket is created in new thread")
        i = 0
        while True:
            i += 1
            data_message, addr_new_socket = data_socket.recvfrom(1024)
            prased_message = prase_full_message(data_message)
            tmp = prased_message["dest_port"]
            prased_message["dest_port"] = prased_message["src_port"]
            prased_message["src_port"] = tmp
            prased_message["SYN"] = "0".encode()
            prased_message["ACK"] = "1".encode()
            temp = prased_message["sequence"]
            prased_message["sequence"] = prased_message["ack_num"]
            prased_message["ack_num"] = temp

            new_ack_length = '{:08x}'.format(int(prased_message["ack_num"].decode(),16) + len(prased_message["DATA"].decode().encode('utf-8')) )
            prased_message["ack_num"] = (str(new_ack_length)).encode()
            if (check_FIN(prased_message)):  # if FIN ==1
                prased_message["ACK"] = "1".encode()
                build_header_message(prased_message)
                data_socket.sendto(build_header_message(prased_message).encode(), addr_new_socket)
                print("received a FIN bit, now close to data_socket from server end!")
                data_socket.close()
                break
            #print("Data prased after header is '", prased_message["DATA"].decode(), "' i=", i)
            print("Server received message has Data'", prased_message["DATA"].decode(), "' count=", i)
            send_message = build_full_message(prased_message, 0)
            data_socket.sendto(send_message.encode(), addr_new_socket)

    return # when you return, you close the thread

def prase_welcome_message(message):
    # source port: 16 : client port
    # dest port 16 : server port
    # sequence : 32
    # ack num : 32
    # SYN : 4
    # ACK : 4
    # FIN: 4
    message_info = {
        "src_port": [],
        "dest_port": [],
        "sequence": [],
        "ack_num": [],
        "SYN": [],
        "ACK": [],
        "FIN": []
    }

    src_port = message[0:4]
    dest_port = message[4:8]
    sequence = message[8:16]
    ack_num = message[16:24]
    SYN = message[24:25]
    ACK = message[25:26]
    FIN = message[26:27]
    message_info["src_port"] = src_port
    message_info["dest_port"] = dest_port
    message_info["sequence"] = sequence
    message_info["ack_num"] = ack_num
    message_info["SYN"] = SYN
    message_info["ACK"] = ACK
    message_info["FIN"] = FIN

    return message_info

def prase_full_message(message):
    # source port: 16 : client port
    # dest port 16 : server port
    # sequence : 32
    # ack num : 32
    # SYN : 4
    # ACK : 4
    # FIN: 4
    message_info = {
        "src_port": [],
        "dest_port": [],
        "sequence": [],
        "ack_num": [],
        "SYN": [],
        "ACK": [],
        "FIN": [],
        "DATA":[]
    }

    src_port = message[0:4]
    dest_port = message[4:8]
    sequence = message[8:16]
    ack_num = message[16:24]
    SYN = message[24:25]
    ACK = message[25:26]
    FIN = message[26:27]
    DATA = message[27:]
    message_info["src_port"] = src_port
    message_info["dest_port"] = dest_port
    message_info["sequence"] = sequence
    message_info["ack_num"] = ack_num
    message_info["SYN"] = SYN
    message_info["ACK"] = ACK
    message_info["FIN"] = FIN
    message_info["DATA"] = DATA
    return message_info

def build_header_message(prased_message):
    message = prased_message["src_port"].decode()+prased_message["dest_port"].decode()+ \
              prased_message["sequence"].decode() + prased_message["ack_num"].decode()
    #ack_num = '{:08x}'.format(int(prased_message["ack_num"].decode()))
    message_2=prased_message["SYN"].decode()\
              + prased_message["ACK"].decode() + prased_message["FIN"].decode()

    message = message+message_2
    return message

def build_full_message(prased_message, client):
    if client:
        Data = "Ping"
    else:
        Data = "Pong"

    message = prased_message["src_port"].decode() + prased_message["dest_port"].decode() + \
              prased_message["sequence"].decode() + prased_message["ack_num"].decode()

    message_2 = prased_message["SYN"].decode() \
                + prased_message["ACK"].decode() + prased_message["FIN"].decode()

    message = message+ message_2+Data
    return message

# Server welcome socket for three way handshake and created new thread for data socket
class welcome_socket:
    welcome_port = 8000 #initial welcome port number (change if received from client)

  #def __init__(self, host, port_number):
    def __init__(self, port):
        self.welcome_port = port #welcome port
        #print("Welcome Socket is initialized, port number",self.welcome_port )

#accept() create the server_socket for the host connection
    def accept(self,host_addr):
        port = 1024 + random.randint(0, 500)
        self.host_addr = host_addr
        # welcome socket receive message
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wel_socket:
            # bind the address from welcome socket
            wel_socket.bind((host_addr, self.welcome_port))

        # Three way handshake
            # First Receive
            message, addr = wel_socket.recvfrom(1024)
            #print("Server/ first receive in Three-way handshake:", message)
            prased_message = prase_welcome_message(message)
            #print("Prase message:", prased_message)

            #Set the ACK=1, Server port= port
            #print ("port number: ", port)
            prased_message["dest_port"] = prased_message["src_port"]
            prased_message["src_port"] = str(port).encode()
            # prased_message["dest_port"] = str(addr[1]).encode()
            # new_ack_length = '{:08x}'.format(int(prased_message["ack_num"].decode()) + 1)
            new_ack_length = '{:08x}'.format(int(prased_message["sequence"].decode(),16) + 1)
            prased_message["ack_num"] = (str(new_ack_length)).encode()
            prased_message["sequence"] = "00000000".encode()
            prased_message["ACK"]= "1".encode()


            # Send back
            send_back_message = build_header_message(prased_message)
            #print("Server/ send back in Three-way handshake: ", send_back_message)

        # Parallel create the data_socket
            start_new_thread(new_socket_thread, (host_addr, port,))
            # Send back
            wel_socket.sendto(send_back_message.encode(), (addr))

            # Second Receive
            sec_message, sec_addr = wel_socket.recvfrom(1024)
            #print("Server/ second receive in Three-way handshake", sec_message)
            print("Finish Three way handshake")

# Help recording each log
class log_file_class:
    Source = ""
    Destination = ""
    Message_Type = "" #SYN, SYN/ACK, ACK, DATA, FIN
    Message_Length = ""
    time=""
    output = ""

    def __init__(self, prased_message, time):
        self.Source = str(int(prased_message["src_port"].decode(),16))
        self.Destination = str(int(prased_message["dest_port"].decode(),16))
        decode_x = prased_message["DATA"].decode()
        x_to_string = decode_x.encode('utf-8')
        length = len(x_to_string)
        self.Message_Length = length
        self.Message_Type = self.log_check_type(prased_message)

        time_stamp = datetime.datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S')
        self.time = str(time)
        string_len = str(self.Message_Length)
        self.output = self.Source +"|"+ self.Destination +"|" + self.Message_Type  +"|"+ string_len + "|" +self.time


    # Checking the flag portion to determine the message type
    def log_check_type(self,prased_message):
        if int(prased_message["SYN"].decode()) != 0:
            if int(prased_message["ACK"].decode()) !=0:
                return "SYN/ACK"
            else:
                return "SYN"

        if int(prased_message["ACK"].decode()) != 0:
            return "ACK"
        if int(prased_message["FIN"].decode()) == 1:
            return "FIN"

        return "DATA"
