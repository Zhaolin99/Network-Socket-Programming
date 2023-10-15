import socket
from argparse import ArgumentParser
import random
import p2_my_socket
from p2_my_socket import timer
#from time import sleep
import time

def parse_args():
    # parse the command line arguments
    args = ArgumentParser()
    args.add_argument('--dest_ip', default="127.0.0.1")
    args.add_argument('--dest_port', default=8000, type=int)
    args.add_argument('--input', default="alice29.txt")
    return args.parse_args()


# source port: 16 : client port
# dest port 16 : server port
# sequence : 32
# ack num : 32
# SYN : 4
# ACK : 4
# FIN: 4
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
    message = source_port + dest_port + sequence + acknowledge + SYN + ACK +FIN
    return message


def check_FIN(msg):
    return msg["FIN"] == "1".encode()

def check_ACK(msg):
    return msg["ACK"] == "1".encode()

def build_header_message(prased_message):
    message = prased_message["src_port"].decode()+prased_message["dest_port"].decode()+ \
              prased_message["sequence"].decode()+ prased_message["ack_num"].decode()

    message_2=prased_message["SYN"].decode()\
              + prased_message["ACK"].decode() + prased_message["FIN"].decode()

    message = message+message_2
    return message

def read_in_chunks(f, chunk_size):
    while True:
        data = f.read(chunk_size)
        if not data:
            break
        yield data

if __name__ == '__main__':
    args = parse_args()
    interrupt = False
    # First send message to welcome socket (SYN=1)
    message = build_welcome_message(0, args.dest_port)
    log_file = []
    timer_ = timer(0.125,0.25)
    time_out = timer_.time_out_interval
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
    # Three way handshake
        # First Send with SYN=1
        # LOG 1
        cur_time = time.time()
        client_socket.sendto(message.encode(), (args.dest_ip, args.dest_port))
        time_start = time.time()
        client_socket.settimeout(time_out)
        prased_log_info = p2_my_socket.prase_full_message(message.encode())
        log_content = p2_my_socket.log_file_class(prased_log_info, cur_time)
        dict = {cur_time: log_content.output}
        log_file.append(dict)
        # First Receive
        i=1
        while True:
            try:
                message, addr = client_socket.recvfrom(1024)
                time_end = time.time()
                # LOG 2
                cur_time = time.time()
                prased_log_info = p2_my_socket.prase_full_message(message)
                log_content = p2_my_socket.log_file_class(prased_log_info, cur_time)
                dict = {cur_time: log_content.output}
                log_file.append(dict)

                prased_message = p2_my_socket.prase_welcome_message(message)
                #print("Client/ first receive in Three-way handshake: ", prased_message)
                break
            except socket.timeout:
                #print("did not receive, resend")
                # LOG 3
                cur_time = time.time()
                client_socket.sendto(message.encode(), (args.dest_ip, args.dest_port))
                client_socket.settimeout(time_out)
                prased_log_info = p2_my_socket.prase_full_message(message.encode())
                log_content = p2_my_socket.log_file_class(prased_log_info, cur_time)
                dict = {cur_time: log_content.output}
                log_file.append(dict)
                i+=1
        if (i==1): # only send msg once and get the response
            # Also, TCP never computes a SampleRTT for a segment that has been retransmitted;
            timer_.update_timer(time_start,time_end)
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
        prased_message["ack_num"] = tmp
        new_ack_length = '{:08x}'.format(int(prased_message["ack_num"].decode(),16) + 1)
        prased_message["ack_num"] = (str(new_ack_length)).encode()
        send_message = p2_my_socket.build_header_message(prased_message)
        #print ("cient's second sendto message: ",send_message)


        #Second Send
        #do not need to recieve ack for the second send message
        cur_time = time.time()
        client_socket.sendto(send_message.encode(), (args.dest_ip, args.dest_port))
        # LOG3
        prased_log_info = p2_my_socket.prase_full_message(send_message.encode())
        log_content = p2_my_socket.log_file_class(prased_log_info, cur_time)
        dict = {cur_time: log_content.output}
        log_file.append(dict)
        #Three way handshake finished
        print("Three way handshake finished")


    prased_message["ACK"] = "0".encode()
    send_message = p2_my_socket.build_header_message(prased_message)

    # Created Data Socket

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_data_socket:
        my_addr=(args.dest_ip,int(prased_message["dest_port"].decode()))
        #message = send_message + "Ping"
        #print("Client/ data send is", message.encode())

        # while read some data
        i = 0
        with open(args.input) as file:
            read_size = 1000 - len(send_message)
            #read_size = 100
            for piece in read_in_chunks(file, read_size):
                message = send_message + piece
                try:
                    #print("client's sendto message: ", message)
                    # Log 5
                    cur_time = time.time()

                    prased_log_info = p2_my_socket.prase_full_message(message.encode())
                    log_content = p2_my_socket.log_file_class(prased_log_info, cur_time)
                    dict = {cur_time: log_content.output}
                    log_file.append(dict)
                    print("Log: ", log_content.output)
                    client_data_socket.sendto(message.encode(), my_addr)
                    time_start = time.time()
                    # time_start = time.time()
                    client_data_socket.settimeout(time_out)
                    j = 1
                    while True:
                        i += 1
                        # Send to Server Data Socket
                        # print("cient's second sendto message: ", message)
                        # client_data_socket.sendto(message.encode(),my_addr)
                        try:
                            # Received with message
                            message, addr = client_data_socket.recvfrom(1024)
                            # LOG6
                            cur_time = time.time()
                            prased_log_info = p2_my_socket.prase_full_message(message)
                            log_content = p2_my_socket.log_file_class(prased_log_info, cur_time)
                            dict = {cur_time: log_content.output}
                            log_file.append(dict)
                            print("Log: ", log_content.output)

                            time_end = time.time()
                            prased_message = p2_my_socket.prase_full_message(message)
                            # update the parse message
                            tmp = prased_message["dest_port"]
                            prased_message["dest_port"] = prased_message["src_port"]
                            prased_message["src_port"] = tmp
                            prased_message["SYN"] = "0".encode()
                            prased_message["ACK"] = "0".encode()
                            temp = prased_message["sequence"]
                            prased_message["sequence"] = prased_message["ack_num"]
                            prased_message["ack_num"] = temp
                            new_ack_length = '{:08x}'.format(int(prased_message["ack_num"].decode(), 16) + len(
                                prased_message["DATA"].decode().encode('utf-8')))
                            prased_message["ack_num"] = (str(new_ack_length)).encode()
                            #print("Client/ Received ACK '", prased_message["ACK"].decode(),"' count=", i)
                            send_message = p2_my_socket.build_header_message(prased_message)
                            # when the first transfer succeed
                            if (j == 1):
                                timer_.update_timer(time_start, time_end)
                                time_out = timer_.time_out_interval

                            break
                        except socket.timeout:
                            #print("did not receive, resend")
                            # LOG 7
                            cur_time = time.time()
                            client_data_socket.sendto(message.encode(), my_addr)
                            client_data_socket.settimeout(time_out)
                            prased_log_info = p2_my_socket.prase_full_message(message.encode())
                            log_content = p2_my_socket.log_file_class(prased_log_info, cur_time)
                            dict = {cur_time: log_content.output}
                            log_file.append(dict)
                            print("Log: ", log_content.output)
                            j += 1

                except KeyboardInterrupt:
                    interrupt = True
                    print("client is interrupted")
                    prased_message["FIN"] = "1".encode()
                    # LOG 6
                    cur_time = time.time()
                    client_data_socket.sendto(build_header_message(prased_message).encode(), my_addr)
                    time_start = time.time()
                    client_data_socket.settimeout(time_out)
                    prased_log_info = p2_my_socket.prase_full_message(build_header_message(prased_message).encode())
                    log_content = p2_my_socket.log_file_class(prased_log_info, cur_time)
                    dict = {cur_time: log_content.output}
                    log_file.append(dict)
                    print("Log: ", log_content.output)

                    i = 1
                    while True:
                        try:
                            message, addr = client_data_socket.recvfrom(1024)
                            time_end = time.time()
                            cur_time = time.time()
                            prased_log_info = p2_my_socket.prase_full_message(message)
                            log_content = p2_my_socket.log_file_class(prased_log_info, cur_time)
                            dict = {cur_time: log_content.output}
                            log_file.append(dict)
                            print("Log: ", log_content.output)

                            prased_message = p2_my_socket.prase_full_message(message)
                            print(check_ACK(prased_message))
                            if (check_ACK(prased_message)):
                                print("close the client socket")
                                print("the final message:", message)
                                # update and timeout variables
                                if (i == 1):
                                    timer_.update_timer(time_start, time_end)
                                    time_out = timer_.time_out_interval
                                #print("the final time_out becomes to :", time_out)
                                client_data_socket.close()
                                break
                        except socket.timeout:
                            #print("did not receive, resend")
                            cur_time = time.time()
                            client_data_socket.sendto(build_header_message(prased_message).encode(), my_addr)
                            client_data_socket.settimeout(time_out)
                            prased_log_info = p2_my_socket.prase_full_message(
                                build_header_message(prased_message).encode())
                            log_content = p2_my_socket.log_file_class(prased_log_info, cur_time)
                            dict = {cur_time: log_content.output}
                            log_file.append(dict)
                            print("Log: ", log_content.output)

                            i += 1

                    break
            # the file is transferred entirely without interruption
            if (not interrupt):
                print("client is not interrupted, finish sending the file")
                prased_message["FIN"] = "1".encode()
                # LOG 6
                cur_time = time.time()
                client_data_socket.sendto(build_header_message(prased_message).encode(), my_addr)
                time_start = time.time()
                client_data_socket.settimeout(time_out)
                prased_log_info = p2_my_socket.prase_full_message(build_header_message(prased_message).encode())
                log_content = p2_my_socket.log_file_class(prased_log_info, cur_time)
                dict = {cur_time: log_content.output}
                log_file.append(dict)
                print("Log: ", log_content.output)

                i = 1
                while True:
                    try:
                        message, addr = client_data_socket.recvfrom(1024)
                        time_end = time.time()
                        cur_time = time.time()
                        prased_log_info = p2_my_socket.prase_full_message(message)
                        log_content = p2_my_socket.log_file_class(prased_log_info, cur_time)
                        dict = {cur_time: log_content.output}
                        log_file.append(dict)
                        print("Log: ", log_content.output)

                        prased_message = p2_my_socket.prase_full_message(message)
                        print(check_ACK(prased_message))
                        if (check_ACK(prased_message)):
                            print("close the client socket")
                            #print("the final message:", message)
                            # update and timeout variables
                            if (i == 1):
                                timer_.update_timer(time_start, time_end)
                                time_out = timer_.time_out_interval
                            #print("the final time_out becomes to :", time_out)
                            client_data_socket.close()
                            break
                    except socket.timeout:
                        #print("did not receive, resend")
                        cur_time = time.time()
                        client_data_socket.sendto(build_header_message(prased_message).encode(), my_addr)
                        client_data_socket.settimeout(time_out)
                        prased_log_info = p2_my_socket.prase_full_message(
                            build_header_message(prased_message).encode())
                        log_content = p2_my_socket.log_file_class(prased_log_info, cur_time)
                        dict = {cur_time: log_content.output}
                        i += 1


        file_index = str(data_port)
        file_index = str(int(file_index, 16))
        file_name = "logfile_client_" + file_index + ".txt"
        f = open(file_name, "w")
        for log in log_file:
            for key, value in log.items():
                f.write(str(value))
                f.write("\n")
        f.close()




