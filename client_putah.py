import socket
import time
from argparse import ArgumentParser
import random
import my_socket
#from time import sleep

def parse_args():
    # parse the command line arguments
    args = ArgumentParser()
    args.add_argument('--server_ip', default="127.0.0.1")
    args.add_argument('--server_port', default=8000, type=int)
    return args.parse_args()


# source port: 16 : client port
# dest port 16 : server port
# sequence : 32
# ack num : 32
# SYN : 4
# ACK : 4
# FIN: 4

#Client build the initial message in three way handshake, mainly set up the header format
def build_welcome_message(client_port, server_port):
    source_port = client_port # need to be updated
    source_port = '{:04x}'.format(source_port)
    dest_port = server_port  # need to be updated
    dest_port = '{:04x}'.format(dest_port)
    sequence = '{:08x}'.format(0)
    acknowledge = '{:08x}'.format(0)
    SYN = '{:01x}'.format(1)
    ACK = '{:01x}'.format(0)
    FIN = '{:01x}'.format(0)
    message = source_port + dest_port + sequence + acknowledge + SYN + ACK +FIN
    return message

#Check if there is FIN (finish message)
def check_FIN(msg):
    return msg["FIN"] == "1".encode()

#Check if there is ACK (Acknowlegment message)
def check_ACK(msg):
    return msg["ACK"] == "1".encode()

#Combine prased parts into a full header message to send
def build_header_message(prased_message):
    message = prased_message["src_port"].decode()+prased_message["dest_port"].decode()+ \
              prased_message["sequence"].decode()+ prased_message["ack_num"].decode()

    message_2=prased_message["SYN"].decode()\
              + prased_message["ACK"].decode() + prased_message["FIN"].decode()

    message = message+message_2
    return message


if __name__ == '__main__':
    args = parse_args()
    # First send message to welcome socket (SYN=1)
    message = build_welcome_message(0, args.server_port)
    log_file=[]

    #Client first send out socket ("welcome socket")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
    # Three way handshake
        # First Send with SYN=1
        # LOG 1
        cur_time = time.time()
        client_socket.sendto(message.encode(), (args.server_ip, args.server_port))

        prased_log_info = my_socket.prase_full_message(message.encode())
        log_content = my_socket.log_file_class(prased_log_info, cur_time)
        dict = {cur_time : log_content.output}
        log_file.append(dict)

        # First Receive
        message, addr = client_socket.recvfrom(1024)

        # LOG 2
        cur_time = time.time()
        prased_log_info = my_socket.prase_full_message(message)
        log_content = my_socket.log_file_class(prased_log_info, cur_time)
        dict = {cur_time: log_content.output}
        log_file.append(dict)

        prased_message = my_socket.prase_welcome_message(message)
        #print("Client/ first receive in Three-way handshake: ", prased_message)

        #Build the header to send (based on what is received)
        #Create the random number as data port number
        data_port = 1024 + random.randint(0, 500)
        prased_message["dest_port"] = prased_message["src_port"]
        prased_message["src_port"] = str(data_port).encode()
        prased_message["SYN"] = "0".encode()
        prased_message["ACK"] = "1".encode()
        tmp = prased_message["sequence"]
        prased_message["sequence"] = prased_message["ack_num"]
        prased_message["ack_num"] = tmp
        new_ack_length = '{:08x}'.format(int(prased_message["ack_num"].decode(),16) + 1)
        prased_message["ack_num"] = (str(new_ack_length)).encode()

        # Second Send
        send_message = my_socket.build_header_message(prased_message)
        #print ("cient's second sendto message: ",send_message)
        cur_time = time.time()
        client_socket.sendto(send_message.encode(), (args.server_ip, args.server_port))

        # LOG3
        prased_log_info = my_socket.prase_full_message(send_message.encode())
        log_content = my_socket.log_file_class(prased_log_info, cur_time)
        dict = {cur_time: log_content.output}
        log_file.append(dict)
        #Three way handshake finished
        print("Three way handshake finished")


    prased_message["ACK"] = "0".encode()
    send_message = my_socket.build_header_message(prased_message)

    # Created data sokcet and start sending data
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_data_socket:
        i=0
        my_addr=(args.server_ip,int(prased_message["dest_port"].decode()))
        message = send_message + "Ping"
        #print("Clinet/ data send is", message.encode())
        try:
            while True:
                i += 1
                #Send to Server Data Socket
                #print("cient's second sendto message: ", message)

                # Log 4
                cur_time = time.time()
                client_data_socket.sendto(message.encode(),my_addr)
                prased_log_info = my_socket.prase_full_message(message.encode())
                log_content = my_socket.log_file_class(prased_log_info, cur_time)
                dict = {cur_time: log_content.output}
                print("Log: ",log_content.output)
                log_file.append(dict)

                #Received with message
                message, addr = client_data_socket.recvfrom(1024)
                prased_message = my_socket.prase_full_message(message)

                # LOG5
                cur_time = time.time()
                prased_log_info = my_socket.prase_full_message(message)
                log_content = my_socket.log_file_class(prased_log_info, cur_time)
                dict = {cur_time: log_content.output}
                print("Log: ", log_content.output)
                log_file.append(dict)
                # update the parse message
                tmp = prased_message["dest_port"]
                prased_message["dest_port"] = prased_message["src_port"]
                prased_message["src_port"] = tmp
                prased_message["SYN"] = "0".encode()
                prased_message["ACK"] = "0".encode()
                temp = prased_message["sequence"]
                prased_message["sequence"] = prased_message["ack_num"]
                prased_message["ack_num"] = temp
                new_ack_length = '{:08x}'.format(int(prased_message["ack_num"].decode(),16) + len(prased_message["DATA"].decode().encode('utf-8')) )
                prased_message["ack_num"] = (str(new_ack_length)).encode()
                print("Client received message has Data'", prased_message["DATA"].decode(), "' count=",i)
                message = my_socket.build_full_message(prased_message,1)

        except KeyboardInterrupt:
            print ("client is interrupted")
            prased_message["FIN"] = "1".encode()
            # LOG 6
            cur_time = time.time()
            client_data_socket.sendto(build_header_message(prased_message).encode(), my_addr)

            prased_log_info = my_socket.prase_full_message(build_header_message(prased_message).encode())
            log_content = my_socket.log_file_class(prased_log_info, cur_time)
            dict = {cur_time: log_content.output}
            print("Log FIN: ", log_content.output)
            log_file.append(dict)

            # LOG 7
            for i in range(3):
                message, addr = client_data_socket.recvfrom(1024)
                cur_time = time.time()
                prased_log_info = my_socket.prase_full_message(message)
                log_content = my_socket.log_file_class(prased_log_info, cur_time)
                dict = {cur_time: log_content.output}
                print("Log: ", log_content.output)
                log_file.append(dict)
                prased_message = my_socket.prase_full_message(message)
            #print (check_ACK(prased_message))

                if (check_ACK(prased_message)): #Successfully received the last ACK
                    print ("close the client socket")

                    file_index = str(int(str(data_port),16))
                    file_name = "logfile_client_"+file_index+".txt"
                    client_data_socket.close()
                    break
                else:
                    continue

        f = open(file_name, "w")
        for log in log_file:
            for key, value in log.items():
                f.write(str(value))
                f.write("\n")
        f.close()