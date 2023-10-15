import time

import my_socket
from my_socket import welcome_socket
import socket
from argparse import ArgumentParser
from _thread import *
import threading

def parse_args():
    # parse the command line arguments
    args = ArgumentParser()
    args.add_argument('--ip', default="127.0.0.1")
    args.add_argument('--port', default=8000, type=int)
    return args.parse_args()

#Combine prased parts into a full header message to send
def build_header_message(prased_message):
    message = prased_message["src_port"].decode()+prased_message["dest_port"].decode()+ \
              prased_message["sequence"].decode() + prased_message["ack_num"].decode()

    message_2=prased_message["SYN"].decode()\
              + prased_message["ACK"].decode() + prased_message["FIN"].decode()

    message = message+message_2
    return message

def check_FIN(msg):
    return msg["FIN"] == "1".encode()
def check_ACK(msg):
    return msg["ACK"] == "1".encode()


if __name__ == '__main__':
    args = parse_args()
    my_welcome_socket = welcome_socket(args.port)

    while True:
        print("Welcome Server is waiting")
        #1. Make the three-way handshake
        #2. Creat the data_socket through my_welcome_socket
        my_welcome_socket.accept(args.ip)
        # new thread with data socket function is called in the welcome socket accpet funtion





