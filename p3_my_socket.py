# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.
import random
import socket
from _thread import *
from time import sleep
import datetime
import os.path
import time
from collections import OrderedDict

def check_FIN(msg):
    #print ("In check ACK: the msg is ", msg)
    # ACK = msg[25:26]
    return msg["FIN"] == "1".encode()


def check_congestion(msg, BDP):
    #print ("In check ACK: the msg is ", msg)
    # ACK = msg[25:26]

    return msg["window_size"] > str(BDP/1000).encode()

def prase_welcome_message(message):
    # source port: 16 : client port
    # dest port 16 : server port
    # sequence : 32
    # ack num : 32
    # SYN : 4
    # ACK : 4
    # FIN: 4
    # window_size: 16
    message_info = {
        "src_port": [],
        "dest_port": [],
        "sequence": [],
        "ack_num": [],
        "SYN": [],
        "ACK": [],
        "FIN": [],
        "window_size": [],

    }

    src_port = message[0:4]
    dest_port = message[4:8]
    sequence = message[8:16]
    ack_num = message[16:24]
    SYN = message[24:25]
    ACK = message[25:26]
    FIN = message[26:27]
    window_size = message[27:31]

    message_info["src_port"] = src_port
    message_info["dest_port"] = dest_port
    message_info["sequence"] = sequence
    message_info["ack_num"] = ack_num
    message_info["SYN"] = SYN
    message_info["ACK"] = ACK
    message_info["FIN"] = FIN
    message_info["window_size"] = window_size

    return message_info

def prase_full_message(message):
    # source port: 16
    # dest port 16
    # sequence : 32
    # ack num : 32
    # SYN : 4
    # ACK : 4
    # FIN: 4
    # window_size: 16

    message_info = {
        "src_port": [],
        "dest_port": [],
        "sequence": [],
        "ack_num": [],
        "SYN": [],
        "ACK": [],
        "FIN": [],
        "window_size": [],
        "DATA":[]
    }

    src_port = message[0:4]
    dest_port = message[4:8]
    sequence = message[8:16]
    ack_num = message[16:24]
    SYN = message[24:25]
    ACK = message[25:26]
    FIN = message[26:27]
    window_size = message[27:31]
    DATA = message[31:]
    message_info["src_port"] = src_port
    message_info["dest_port"] = dest_port
    message_info["sequence"] = sequence
    message_info["ack_num"] = ack_num
    message_info["SYN"] = SYN
    message_info["ACK"] = ACK
    message_info["FIN"] = FIN
    message_info["window_size"] = window_size
    message_info["DATA"] = DATA
    return message_info

def update_window_size(message, window_size):
    message_info = {
        "src_port": [],
        "dest_port": [],
        "sequence": [],
        "ack_num": [],
        "SYN": [],
        "ACK": [],
        "FIN": [],
        "window_size": [],
        "DATA": []
    }

    src_port = message[0:4]
    dest_port = message[4:8]
    sequence = message[8:16]
    ack_num = message[16:24]
    SYN = message[24:25]
    ACK = message[25:26]
    FIN = message[26:27]

    DATA = message[31:]

    message_info["src_port"] = src_port
    message_info["dest_port"] = dest_port
    message_info["sequence"] = sequence
    message_info["ack_num"] = ack_num
    message_info["SYN"] = SYN
    message_info["ACK"] = ACK
    message_info["FIN"] = FIN
    message_info["window_size"] = window_size
    message_info["DATA"] = DATA

    new_message = message_info["src_port"].encode() + message_info["dest_port"].encode() +\
                  message_info["sequence"].encode()+message_info["ack_num"].encode()+\
                    message_info["SYN"].encode()+message_info["ACK"].encode()+ message_info["FIN"].encode()+ \
                  message_info["window_size"].encode()+ message_info["DATA"].encode()
    return new_message.decode()

def build_header_message(prased_message):
    message = prased_message["src_port"].decode()+prased_message["dest_port"].decode()+ \
              prased_message["sequence"].decode() + prased_message["ack_num"].decode() \
              +prased_message["SYN"].decode()\
              + prased_message["ACK"].decode() + prased_message["FIN"].decode()\
              + prased_message["window_size"].decode()

    return message

def find_ack_num(stored_buffer):

    for i in range (1,len(stored_buffer)):
        if (stored_buffer[i]-stored_buffer[i-1] > 1000):
            return stored_buffer[i-1]

    return stored_buffer[len(stored_buffer)-1]

def new_socket_thread(args, port):
    lose_prob = args.packet_loss_percentage
    round_trip_jitter = args.round_trip_jitter
    BDP = args.bdp
    output_dict = {} # output dictionary
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as data_socket:
        #bind the socket to a OS port
        data_socket.bind((args.ip, port))
        i = 0
        stored_buffer = []
        time_out_count = 0
        packet_lost = 0
        packet_sent = 0
        time_start = time.time()
        data_amount =0
        try:
            while True:
                i += 1
                data_socket.settimeout(5.0)
                data_message, addr_new_socket = data_socket.recvfrom(1024)
                time_end = time.time()
                time_out_count = 0
                prased_message = prase_full_message(data_message)
                # buffer.append(0)
                if (check_congestion(prased_message, BDP)):

                    real_lose_prob = lose_prob * 3
                else:

                    real_lose_prob = lose_prob

                lose_index = random.randint(0, 100)

                if lose_index <= real_lose_prob:
                    # Do not send back
                    # packet is lost and stored in the lost_buffer
                    # if prased_message["sequence"].decode() not in lost_buffer:
                    # lost_buffer.append(prased_message["sequence"].decode())
                    packet_lost += 1
                    print("Packet is lost, do not send ACK")

                else:
                    data_amount += len(prased_message["DATA"].decode())
                    rtj_index = random.random()
                    if rtj_index >= round_trip_jitter:
                        if (check_congestion(prased_message, BDP)):
                            sleep(rtj_index * 3)
                        else:
                            sleep(rtj_index)
                    # Send back the ACK
                    # check if the message ends here
                    # check sequence number in the lost Buffer
                    # if prased_message["sequence"].decode() in lost_buffer:
                    # lost_buffer.remove(prased_message["sequence"].decode())
                    if int(prased_message["sequence"].decode(), 16) not in stored_buffer:
                        stored_buffer.append(int(prased_message["sequence"].decode(), 16))
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

                    stored_buffer.sort()
                    # compare which is larger, the last element store_buffer and the current ack (the sequence num before switching)
                    send_back_ack_num = '{:08x}'.format(find_ack_num(stored_buffer) + 1000)
                    prased_message["ack_num"] = str(send_back_ack_num).encode()

                    if (check_FIN(prased_message)):  # if FIN ==1
                        prased_message["ACK"] = "1".encode()
                        build_header_message(prased_message)
                        data_socket.sendto(build_header_message(prased_message).encode(), addr_new_socket)
                        packet_sent += 1
                        print("received a FIN bit, now close to data_socket from server end!")
                        data_socket.close()


                        file_index = str(int(prased_message["dest_port"].decode(), 16))
                        file_name = file_index + "/output.txt"

                        os.makedirs(os.path.dirname(file_name), exist_ok=True)
                        with open(file_name, "w") as f:
                            for key in sorted(output_dict):
                                f.write(output_dict[key])
                        f.close()
                        time_end = time.time()
                        print ("The total time taken to transfer the file in seconds:  ", time_end - time_start)
                        print ("Total bandwidth acheived for each file (in bytes/seconds): ", data_amount/(time_end - time_start))
                        print ("packet loss observed: ", packet_lost/packet_sent)
                        break
                    # print("Data prased after header is '", prased_message["DATA"].decode(), "' i=", i)

                    send_message = build_header_message(prased_message)
                    data_socket.sendto(send_message.encode(), addr_new_socket)
                    packet_sent += 1

        except socket.timeout:
            time_out_count +=1
            if (time_out_count >=3):
                # close anyway
                data_socket.close()

                # dict1 = OrderedDict(sorted( v.items()))
                file_index = str(int(prased_message["dest_port"].decode(), 16))
                file_name = file_index + "/output.txt"

                os.makedirs(os.path.dirname(file_name), exist_ok=True)
                with open(file_name, "w") as f:
                    for key in sorted(output_dict):
                        f.write(output_dict[key])
                time_end = time.time()
                print("The total time taken to transfer the file in seconds:  ", time_end - time_start)
                print("Total bandwidth acheived for each file (in bytes/seconds): ",
                      data_amount / (time_end - time_start))
                print("packet loss observed: ", packet_lost / packet_sent)
                f.close()
    return


class welcome_socket:
    welcome_port = 8000


  #def __init__(self, host, port_number):
    def __init__(self, port):
        self.welcome_port = port #welcome port
        print("Welcome Socket is initialized, port number",self.welcome_port )

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
                #
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


class log_file_class:
    Source = ""
    Destination = ""
    Message_Type = "" #SYN, SYN/ACK, ACK, DATA, FIN
    Message_Length = ""
    time=""
    state=""
    cwnd=""
    output = ""

    def __init__(self, prased_message, time, slow_start):
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

        if slow_start:
            self.state = "slow start"
        else:
            self.state = "congestion avoidance"
        cwnd_hex = prased_message["window_size"].decode()
        self.cwnd = str(int(cwnd_hex,16))

        self.output = self.Source +"|"+ self.Destination +"|" + self.Message_Type  +"|"+ string_len +"|" +self.state + "|"+ self.cwnd + "|" +self.time


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

    def update_state(self, welcome):
        string_len = str(self.Message_Length)
        if welcome:
            self.output = self.Source +"|"+ self.Destination +"|" + self.Message_Type  +"|"+ string_len +"|" +"N/A" + "|"+ self.cwnd + "|" +self.time


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
        if (self.time_out_interval<1.0):
            self.time_out_interval = 1.0

    def update_timer(self,packet_sent_time, ack_received_time):
        self.cal_Sample_RTT(packet_sent_time, ack_received_time)
        self.cal_estimatedRTT()
        self.cal_Dev_RTT()
        self.cal_timeout_interval()
