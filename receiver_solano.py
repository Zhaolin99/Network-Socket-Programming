
#Command --ip 192.168.1.188 --port 8101 --packet_loss_percentage 10 --round_trip_jitter 0.5 --output output.txt
import random
import time

import p2_my_socket
from p2_my_socket import welcome_socket, my_data_socket
import socket
from argparse import ArgumentParser
from _thread import *
from time import sleep
import threading


def parse_args():
    # parse the command line arguments
    args = ArgumentParser()
    args.add_argument('--ip', default="127.0.0.1")
    args.add_argument('--port', default=8000, type=int)
    args.add_argument('--packet_loss_percentage', default=10, type=int)
    args.add_argument('--round_trip_jitter', default=0.5, type=float)
    args.add_argument('--output', default="output.txt")
    return args.parse_args()


if __name__ == '__main__':
    args = parse_args()
    my_welcome_socket = welcome_socket(args.port)

    while True:
        print("Server is waiting")
            # Finish three way hand shake in class my_welcome_socket
        server_socket_port = my_welcome_socket.accept(args)

            #Start the new thread for data socket (port_number generated from welcome socket accept)
            # start_new_thread(new_socket_thread, (args, server_socket_port,))

