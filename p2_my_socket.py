
import random
import socket
from _thread import *
from time import sleep
import time
import os.path
#import datetime
def check_FIN(msg):
    # print("In check FIN: the msg is ", msg)
    #msg["ACK"]
    return msg["FIN"] == "1".encode()

def check_ACK(msg):
    #print ("In check ACK: the msg is ", msg)
    # ACK = msg[25:26]
    return msg["ACK"] == "1".encode()

def new_socket_thread(args, port):
    lose_prob = args.packet_loss_percentage
    round_trip_jitter = args.round_trip_jitter
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as data_socket:
        #bind the socket to a OS port
        data_socket.bind((args.ip, port))
        i = 0
        packet_lost = 0
        packet_sent = 0
        time_start = time.time()
        data_amount = 0
        time_out_count = 0
        output_dict = {} # output dictionary
        try:
            while True:
                i += 1
                data_message, addr_new_socket = data_socket.recvfrom(1024)
                data_socket.settimeout(5.0)
                time_end = time.time()

                lose_index = random.randint(0, 100)

                if lose_index <= lose_prob:
                    # Do not send back
                    #print("Packet is lost, do not send ACK")
                    packet_lost += 1
                else:

                    rtj_index = random.random()
                    if rtj_index >= round_trip_jitter:
                        sleep(rtj_index)

                    # Send back the ACK
                    # check if the message ends here
                    prased_message = prase_full_message(data_message)
                    data_amount += len(prased_message["DATA"].decode())
                    num = int(prased_message["sequence"].decode(), 16)
                    if num not in output_dict.keys():
                        output_dict[int(prased_message["sequence"].decode(), 16)] = prased_message["DATA"].decode()

                    tmp = prased_message["dest_port"]
                    prased_message["dest_port"] = prased_message["src_port"]
                    prased_message["src_port"] = tmp
                    prased_message["SYN"] = "0".encode()
                    prased_message["ACK"] = "1".encode()
                    temp = prased_message["sequence"]
                    prased_message["sequence"] = prased_message["ack_num"]
                    prased_message["ack_num"] = temp
                    new_ack_length = '{:08x}'.format(
                        int(prased_message["ack_num"].decode(), 16) + len(prased_message["DATA"].decode().encode('utf-8')))
                    prased_message["ack_num"] = (str(new_ack_length)).encode()
                    if (check_FIN(prased_message)):  # if FIN ==1
                        prased_message["ACK"] = "1".encode()
                        build_header_message(prased_message)
                        data_socket.sendto(build_header_message(prased_message).encode(), addr_new_socket)
                        packet_sent += 1
                        print("received a FIN bit, now close to data_socket from server end!")
                        time_end = time.time()
                        data_socket.close()

                        file_index = str(int(prased_message["dest_port"].decode(),16))
                        file_name = file_index + "/output.txt"

                        os.makedirs(os.path.dirname(file_name), exist_ok=True)
                        with open(file_name, "w") as f:
                            for key in sorted(output_dict):
                                f.write(output_dict[key])
                        f.close()

                        print("The total time taken to transfer the file in seconds:  ", time_end - time_start)
                        print("Total bandwidth acheived for each file (in bytes/seconds): ",
                              data_amount / (time_end - time_start))
                        print("packet loss observed: ", packet_lost/packet_sent)
                        break
                    print("Data received prased after header is '", prased_message["DATA"].decode(), "' i=", i)

                    send_message = build_header_message(prased_message)
                    data_socket.sendto(send_message.encode(), addr_new_socket)
                    packet_sent += 1

        except socket.timeout:
            time_out_count +=1
            if (time_out_count >=3):
                # close anyway
                time_end = time.time()
                data_socket.close()

                # dict1 = OrderedDict(sorted( v.items()))
                file_index = str(int(prased_message["source_port"].decode(), 16))
                file_name = file_index + args.output

                os.makedirs(os.path.dirname(file_name), exist_ok=True)
                with open(file_name, "w") as f:
                    for key in sorted(output_dict):
                        f.write(output_dict[key])
                print("The total time taken to transfer the file in seconds:  ", time_end - time_start)
                print("Total bandwidth acheived for each file (in bytes/seconds): ",
                      data_amount / (time_end - time_start))
                print("packet loss observed: ", packet_lost/packet_sent)
                f.close()


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


class welcome_socket:
    welcome_port = 8000


  #def __init__(self, host, port_number):
    def __init__(self, port):
        self.welcome_port = port #welcome port
        print("Welcome Socket is initialized, port number",self.welcome_port )

#accept() create the server_socket for the host connection
    def accept(self,args):
        port = 1024 + random.randint(0, 500)
        self.host_addr = args.ip
        # welcome socket receive message
        lose_prob = args.packet_loss_percentage
        round_trip_jitter = args.round_trip_jitter
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wel_socket:
            # bind the address from welcome socket
            wel_socket.bind((args.ip, self.welcome_port))
            lose_index = random.randint(0,100)
            message, addr = wel_socket.recvfrom(1024)
            if lose_index <= lose_prob:
                # Do not send back
                print("Packet is lost, do not send ACK")
            else:
                rtj_index = random.random()
                if rtj_index >= round_trip_jitter:
                    sleep(rtj_index)
                #     #Send back the ACK
                #         #check if the message ends here
                # Three way handshake
                # First Receive
                # message, addr = wel_socket.recvfrom(1024)
                print("Server/ first receive in Three-way handshake:", message)
                prased_message = prase_welcome_message(message)
                print("Prase message:", prased_message)

                # Set the ACK=1,
                print("port number: ", port)
                prased_message["dest_port"] = prased_message["src_port"]
                prased_message["src_port"] = str(port).encode()
                # ack_num +1 since it only contains a header
                new_ack_length = '{:08x}'.format(int(prased_message["sequence"].decode(), 16) + 1)
                prased_message["ack_num"] = (str(new_ack_length)).encode()
                random_sequence = '{:08x}'.format(random.randint(0, 4129057982))
                prased_message["sequence"] = (str(random_sequence)).encode()  # generate sequence num for server
                prased_message["ACK"] = "1".encode()

                # Send back
                send_back_message = build_header_message(prased_message)
                print("Server/ send back in Three-way handshake: ", send_back_message)

                # Parallel create the data_socket
                start_new_thread(new_socket_thread, (args, port,))

                # Send back
                wel_socket.sendto(send_back_message.encode(), (addr))

                # Second Receive
                sec_message, sec_addr = wel_socket.recvfrom(1024)
                print("Server/ second receive in Three-way handshake", sec_message)
                print("Finish Three way handshake")

class my_data_socket:
    port=8000
    host_addr=""
    #my_socket
    def __init__(self, host_addr, port):
        self.port = port #welcome port
        self.host_addr = host_addr
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as data_socket:
            data_socket.bind((host_addr, self.port))
            self.my_socket = data_socket
        print("DATA Socket is initialized, port number",self.port )

    def recv(self):
        data_message, data_addr = self.my_socket.recvfrom(4096)
        return data_message

class log_file_class:
    Source = ""
    Destination = ""
    Message_Type = "" #SYN, SYN/ACK, ACK, DATA, FIN
    Message_Length = 0
    time=0.0
    output = ""

    def __init__(self, prased_message, time):
        self.Source = str(int(prased_message["src_port"].decode(),16))
        self.Destination = str(int(prased_message["dest_port"].decode(),16))
        decode_x = prased_message["DATA"].decode()
        x_to_string = decode_x.encode('utf-8')
        length = len(x_to_string)
        self.Message_Length = length
        self.Message_Type = self.log_check_type(prased_message)

        #time_stamp = datetime.datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S')
        self.time = str(time)
        string_len = str(self.Message_Length)
        self.output = self.Source +"|"+ self.Destination +"|" + self.Message_Type  +"|"+ string_len + "|" +self.time


#Do we need add three way handshake?
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

class timer:
    time_out_interval = 1.0
    Sample_RTT = 0.0
    Dev_RTT = 0.0
    Estimated_RTT = 1.0
    alpha = 0.0
    beta = 0.0

    def __init__(self, alpha, beta):
        self.alpha = alpha #set up initial value
        self.beta = beta # set up initial value
        #self.cal_Sample_RTT(first_packet_sent_time,first_ack_received_time)
        #self.Estimated_RTT = self.Sample_RTT


    def cal_Sample_RTT(self,packet_sent_time, ack_received_time):
        self.Sample_RTT=ack_received_time-packet_sent_time

    def cal_estimatedRTT(self):
        x = (1-self.alpha) * self.Estimated_RTT
        y = self.alpha * self.Sample_RTT
        self.Estimated_RTT = x+y

    def cal_Dev_RTT(self):
        x = (1-self.beta) * self.Dev_RTT
        y = self.beta * abs(self.Sample_RTT - self.Estimated_RTT)
        self.Dev_RTT = x+y

    def cal_timeout_interval(self):
        self.time_out_interval = self.Estimated_RTT + 4*self.Dev_RTT
        if self.time_out_interval  <= 1:
            self.time_out_interval = 1

    def update_timer(self,packet_sent_time, ack_received_time):
        self.cal_Sample_RTT(packet_sent_time, ack_received_time)
        self.cal_estimatedRTT()
        self.cal_Dev_RTT()
        self.cal_timeout_interval()


