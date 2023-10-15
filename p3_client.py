import socket
from argparse import ArgumentParser
import random
import p3_my_socket
from p3_my_socket import timer

import time



def parse_args():
    # parse the command line arguments
    args = ArgumentParser()
    args.add_argument('--dest_ip', default="127.0.0.1")
    args.add_argument('--dest_port', default=8000, type=int)
    args.add_argument('--tcp_version', default="tahoe")
    args.add_argument('--input', default="big.txt")
    return args.parse_args()

# source port: 16 : client port
# dest port 16 : server port
# sequence : 32
# ack num : 32
# SYN : 4
# ACK : 4
# FIN: 4
# Window_size : 16
def build_welcome_message(client_port, server_port):
    source_port = client_port # need to be updated
    source_port = '{:04x}'.format(source_port)
    dest_port = server_port  # need to be updated
    dest_port = '{:04x}'.format(dest_port)
    sequence = '{:08x}'.format(random.randint(0,4129057982))
    acknowledge = '{:08x}'.format(0)
    SYN = '{:01x}'.format(1)
    ACK = '{:01x}'.format(0)
    FIN = '{:01x}'.format(0)
    Window_size = '{:04x}'.format(1)

    message = source_port + dest_port + sequence + acknowledge + SYN + ACK + FIN + Window_size
    return message

def check_ACK(msg):
    #print ("In check ACK: the msg is ", msg)
    # ACK = msg[25:26]
    return msg["ACK"] == "1".encode()

def read_in_chunks(f, chunk_size):
    while True:
        data = f.read(chunk_size)
        if not data:
            break
        yield data

def update_log_file (log_file, message, slow_start, welcome):
    cur_time = time.time()
    prased_log_info = p3_my_socket.prase_full_message(message)
    log_content = p3_my_socket.log_file_class(prased_log_info, cur_time, slow_start)
    if welcome:
        log_content.update_state(welcome)
    dict = {cur_time: log_content.output}
    log_file.append(dict)
    return

def client_three_way_handshake(args, log_file, message, timer_, time_out):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        # First Send with SYN=1

        time_start = time.time()

        client_socket.sendto(message.encode(), (args.dest_ip, args.dest_port))
        client_socket.settimeout(time_out)

        slow_start = True
        update_log_file(log_file, message.encode(), slow_start,True)
        # First Receive
        i = 1
        while True:
            try:  # Did received from server welcome socket
                message, addr = client_socket.recvfrom(1024)
                time_end = time.time()

                update_log_file(log_file, message,slow_start,True)

                prased_message = p3_my_socket.prase_full_message(message)
                print("Client/ first receive in Three-way handshake: ", prased_message)
                break
            except socket.timeout:  # if not received, resend
                print("did not receive, resend")

                client_socket.sendto(message.encode(), (args.dest_ip, args.dest_port))
                client_socket.settimeout(time_out)

                update_log_file(log_file, message.encode(), slow_start,True)
                i += 1

        if (i == 1):  # only send msg once and get the response
            # Also, TCP never computes a SampleRTT for a segment that has been retransmitted;
            timer_.update_timer(time_start, time_end)
            time_out = timer_.time_out_interval
        # else, do not update timeout
        data_port = 1024 + random.randint(0, 500)
        prased_message["dest_port"] = prased_message["src_port"]
        prased_message["src_port"] = str(data_port).encode()
        prased_message["SYN"] = "0".encode()
        prased_message["ACK"] = "1".encode()
        # length = len(message.decode().encode('utf-8'))
        tmp = prased_message["sequence"]
        prased_message["sequence"] = prased_message["ack_num"]
        initial_seqeunce = prased_message["ack_num"]
        prased_message["ack_num"] = tmp
        new_ack_length = '{:08x}'.format(int(prased_message["ack_num"].decode(), 16) + 1)
        prased_message["ack_num"] = (str(new_ack_length)).encode()
        send_message = p3_my_socket.build_header_message(prased_message)
        print("cient's second sendto message: ", send_message)

        # Second Send
        # do not need to recieve ack for the second send message
        client_socket.sendto(send_message.encode(), (args.dest_ip, args.dest_port))

        update_log_file(log_file, send_message.encode(),slow_start,True)
        # Three way handshake finished
        print("Three way handshake finished")

    prased_message["ACK"] = "0".encode()
    return prased_message, data_port, initial_seqeunce

def update_send_message(prased_message):
    tmp = prased_message["dest_port"]
    prased_message["dest_port"] = prased_message["src_port"]
    prased_message["src_port"] = tmp
    prased_message["SYN"] = "0".encode()
    prased_message["ACK"] = "0".encode()
    temp = prased_message["sequence"]
    prased_message["sequence"] = prased_message["ack_num"]
    prased_message["ack_num"] = temp
    new_ack_length = '{:08x}'.format(int(prased_message["ack_num"].decode(), 16) + 1)
    prased_message["ack_num"] = (str(new_ack_length)).encode()

    return prased_message

def create_log_file(log_file, data_port):
    file_index = str(data_port)
    file_name = "logfile_client_" + file_index + ".txt"
    f = open(file_name, "w")
    for log in log_file:
        for key, value in log.items():
            # print (value)
            # print (value.type())
            #f.write(str(key))
            #f.write("|")
            f.write(str(value))
            f.write("\n")
    f.close()

def chunk_file(f,chunk_size):
    # input = f.read()
    # temp = len(input)
    packet_list = []
    for piece in read_in_chunks(f, chunk_size):
        packet_list.append(piece)
        # num = (len(piece))
    return packet_list

def TCP_Tahoe (cur_threshold, cur_window_size, timeout, duplicate_ack):
    if (timeout or duplicate_ack):
        new_threshold = cur_window_size // 2
        new_window_size = 1

    elif (cur_window_size >= cur_threshold):
        new_threshold = cur_threshold
        new_window_size = cur_window_size +1
    else: # exponential growth
        new_threshold = cur_threshold
        new_window_size = cur_window_size *2
    if (new_threshold == 0):
        new_threshold =1

    return new_threshold, new_window_size

def TCP_Reno (cur_threshold, cur_window_size, timeout, duplicate_ack):
    if (timeout):
        new_threshold = cur_window_size // 2
        new_window_size = 1
    elif (duplicate_ack):
        new_threshold = cur_window_size // 2 + 3
        new_window_size = new_threshold
    elif (cur_window_size >= cur_threshold):
        new_threshold = cur_threshold
        new_window_size = cur_window_size + 1
    else:  # exponential growth
        new_threshold = cur_threshold
        new_window_size = cur_window_size *2

    if (new_threshold == 0):
        new_threshold =1
    return new_threshold, new_window_size

def find_resend_packet_index (ack_list):
    for i in range(0, len(ack_list)):
        if (ack_list[i] == 0):
            return i
    return len(ack_list)

def check_state(window_size, ssh):
    if window_size <= ssh:
        return True
    else:
        return False

def window_size_log(window_record_log, window_size):
    cur_time = time.time()
    dict={cur_time:window_size}
    window_record_log.append(dict)
    return
def create_window_file(window_log_file, data_port):
    file_index = str(data_port)
    file_name = "window_record_" + file_index + ".txt"
    f = open(file_name, "w")
    for log in window_record_log:
        for key, value in log.items():
            # print (value)
            # print (value.type())
            f.write(str(key))
            f.write("|")
            f.write(str(value))
            f.write("\n")
    f.close()

if __name__ == '__main__':
    args = parse_args()
    interrupt = False

    # First send message to welcome socket (SYN=1)
    message = build_welcome_message(0, args.dest_port)
    log_file = []
    window_record_log=[]
    timer_ = timer(0.125,0.25)
    time_out = timer_.time_out_interval
    slow_start = True

    prased_message, data_port, initial_sequence = client_three_way_handshake(args, log_file, message, timer_, time_out)
    initial_sequence  =  int(initial_sequence.decode(),base=16)
    time_out = timer_.time_out_interval
    send_message = p3_my_socket.build_header_message(prased_message)

    read_size = 1000 - len(send_message)
    with open(args.input) as file:
        packet_list = chunk_file(file, read_size)
    acknowledgements = [0 for i in packet_list]

    # initial_seqeunce = int(prased_message["sequence"].decode(),16)
    for i in range (0,len(packet_list)):
        new_sequence_hex = initial_sequence + 1000*i
        prased_message["sequence"] = ('{:08x}'.format(new_sequence_hex)).encode()
        send_message = p3_my_socket.build_header_message(prased_message)
        packet_list[i] = send_message + packet_list[i]


    # Created Data Socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_data_socket:
        my_addr=(args.dest_ip,int(prased_message["dest_port"].decode()))
        window_size = 1
        window_size_log(window_record_log, window_size)
        ssthreshold = 16
        slide_window_amount = 0
        duplicate = False
        timeOut = False
        cur_wait_count = 0
        window_start = 0
        window_end = window_size - window_start
        send_count = 0
        time_out = timer_.time_out_interval
        slow_start = True
        resend_list = [False for i in packet_list]
        try:
            while True:
                tmp = 0
                client_data_socket.settimeout(timer_.time_out_interval)
                time_start = time.time()
                for i in range(0, window_size - cur_wait_count):
                    # change winodw size
                    temp = '{:04x}'.format(window_size)
                    if (send_count < len(packet_list)):
                        packet_list[send_count] =p3_my_socket.update_window_size(packet_list[send_count], temp)
                        client_data_socket.sendto(packet_list[send_count].encode(), my_addr)

                        slow_start=check_state(window_size, ssthreshold)
                        update_log_file(log_file, packet_list[send_count].encode(), slow_start, False)

                        print ("send_count", send_count)
                        tmp += 1
                        send_count += 1
                    else:
                        break


                cur_wait_count += tmp
                tmp = 0
                try:
                    response, _ = client_data_socket.recvfrom(1024)
                    slow_start = check_state(window_size, ssthreshold)
                    update_log_file(log_file, response, slow_start, False)

                    # update timeout
                    time_end = time.time()
                    timer_.update_timer(time_start, time_end)
                    time_out = timer_.time_out_interval

                    parsed_message = p3_my_socket.prase_full_message(response)
                    ack_num = (int(parsed_message["ack_num"].decode(), 16))
                    packet_index = ((int(parsed_message["ack_num"].decode(), 16) - initial_sequence) // 1000) -1
                    resend_list[packet_index] = False
                    cur_wait_count -= 1
                    # check and update the ack

                    if (acknowledgements[packet_index] == 0):
                        for i in range(0,packet_index+1):
                            acknowledgements[i] = 1
                    else:
                        acknowledgements[packet_index] += 1
                        # if duplicate, resend
                        if (acknowledgements[packet_index] >= 3):
                            if (resend_list[packet_index+1] == False):
                                resend_list[packet_index+1] = True
                                duplicate = True
                                acknowledgements[packet_index] = 1
                                client_data_socket.sendto(packet_list[packet_index+1].encode(), my_addr)
                                print ("the packet ",packet_index+1, "resend by duplicate ack" )


                    # get one positive acknowledgement, reset window_size
                    if (args.tcp_version == "Tahoe" or args.tcp_version == "tahoe"):
                        ssthreshold, window_size = TCP_Tahoe(ssthreshold, window_size, timeOut,duplicate)
                        window_size_log(window_record_log, window_size)
                        #print (ssthreshold,window_size)
                    else:
                        ssthreshold, window_size = TCP_Reno(ssthreshold, window_size, timeOut,duplicate)
                        window_size_log(window_record_log, window_size)
                        #print(ssthreshold, window_size)
                    duplicate = False
                    # slide the widnow
                    window_start +=1
                    window_end = window_start + window_size



                except socket.timeout:
                    timeOut = True
                    # find the correct pakcets to resend it
                    index = find_resend_packet_index(acknowledgements)
                    print("resend the packets")
                    print ("index:", index)
                    client_data_socket.sendto(packet_list[index].encode(), my_addr)

                    slow_start = check_state(window_size, ssthreshold)
                    update_log_file(log_file, packet_list[index].encode(),slow_start, False)
                    if (args.tcp_version ==  "Tahoe"  or args.tcp_version ==  "tahoe"):
                        ssthreshold, window_size = TCP_Tahoe(ssthreshold, window_size, timeOut,duplicate)
                        window_size_log(window_record_log, window_size)
                        #print (ssthreshold,window_size)
                    else:
                        ssthreshold, window_size = TCP_Reno(ssthreshold, window_size, timeOut,duplicate)
                        window_size_log(window_record_log, window_size)
                        #print(ssthreshold, window_size)
                    timeOut = False

                finished = True
                for i in range(0,len(acknowledgements)):
                    if (acknowledgements[i] != 1):
                        finished = False
                        break

                if (finished):
                    print("All data has been transefered")
                    prased_message = p3_my_socket.prase_full_message(packet_list[send_count-1].encode())
                    prased_message["FIN"] = "1".encode()
                    prased_message["DATA"] = "".encode()
                    cur_time = time.time()
                    client_data_socket.sendto(p3_my_socket.build_header_message(prased_message).encode(), my_addr)

                    slow_start = check_state(window_size, ssthreshold)
                    update_log_file(log_file, p3_my_socket.build_header_message(prased_message).encode(),slow_start, False)

                    time_start = time.time()
                    client_data_socket.settimeout(time_out)
                    prased_log_info = p3_my_socket.prase_full_message(
                        p3_my_socket.build_header_message(prased_message).encode())
                    i = 1
                    while True:
                        try:
                            message, addr = client_data_socket.recvfrom(1024)

                            slow_start = check_state(window_size, ssthreshold)
                            update_log_file(log_file, message,slow_start, False)

                            time_end = time.time()
                            prased_message = p3_my_socket.prase_full_message(message)
                            print(check_ACK(prased_message))
                            if (check_ACK(prased_message)):
                                print("close the client socket")
                                print("the final message:", message)
                                # update and timeout variables
                                if (i == 1):
                                    timer_.update_timer(time_start, time_end)
                                    time_out = timer_.time_out_interval
                                print("the final time_out becomes to :", time_out)
                                print()
                                client_data_socket.close()
                                break
                        except socket.timeout:
                            print("did not receive, resend")
                            cur_time = time.time()
                            client_data_socket.sendto(p3_my_socket.build_header_message(prased_message).encode(),
                                                      my_addr)
                            slow_start = check_state(window_size, ssthreshold)
                            update_log_file(log_file, p3_my_socket.build_header_message(prased_message).encode(),slow_start, False)
                            client_data_socket.settimeout(time_out)
                    break


                    ###########
        except KeyboardInterrupt:
            print("client is interrupted")


            prased_message = p3_my_socket.prase_full_message(packet_list[send_count].encode())
            prased_message["FIN"] = "1".encode()
            prased_message["DATA"] = "".encode()
            cur_time = time.time()
            client_data_socket.sendto(p3_my_socket.build_header_message(prased_message).encode(), my_addr)
            interrupt_send_count =1
            slow_start = check_state(window_size, ssthreshold)
            update_log_file(log_file, p3_my_socket.build_header_message(prased_message).encode(), slow_start, False)

            time_start = time.time()
            client_data_socket.settimeout(time_out)
            prased_log_info = p3_my_socket.prase_full_message(
                p3_my_socket.build_header_message(prased_message).encode())
            i = 1
            while True:
                try:
                    message, addr = client_data_socket.recvfrom(1024)

                    slow_start = check_state(window_size, ssthreshold)
                    update_log_file(log_file, message, slow_start, False)
                    time_end = time.time()
                    prased_message = p3_my_socket.prase_full_message(message)
                    print(check_ACK(prased_message))
                    if (check_ACK(prased_message)):
                        print("close the client socket")
                        print("the final message:", message)
                        # update and timeout variables
                        if (i == 1):
                            timer_.update_timer(time_start, time_end)
                            time_out = timer_.time_out_interval
                        print("the final time_out becomes to :", time_out)
                        print()
                        client_data_socket.close()
                        break
                except socket.timeout:
                    if (interrupt_send_count >=3): # have alreay sent three times but still failed
                        # closed the packet anyway
                        client_data_socket.close()
                        break
                    print("did not receive, resend")
                    cur_time = time.time()
                    client_data_socket.sendto(p3_my_socket.build_header_message(prased_message).encode(),
                                              my_addr)
                    interrupt_send_count += 1
                    slow_start = check_state(window_size, ssthreshold)
                    update_log_file(log_file, p3_my_socket.build_header_message(prased_message).encode(), slow_start, False)
                    client_data_socket.settimeout(time_out)
                ###########
    data_port = str(data_port)
    data_port = int(data_port,16)
    create_log_file(log_file, data_port)
    create_window_file(window_record_log, data_port)

