
import time
import p3_my_socket
from p3_my_socket import welcome_socket
import socket
from argparse import ArgumentParser

def parse_args():
    # parse the command line arguments
    args = ArgumentParser()
    args.add_argument('--ip', default="127.0.0.1")
    args.add_argument('--port', default=8000, type=int)
    args.add_argument('--packet_loss_percentage', default=10, type=int)
    args.add_argument('--round_trip_jitter', default=0.5, type=float)
    args.add_argument('--bdp', default=20000, type=int)
    args.add_argument('--output', default="output.txt")
    return args.parse_args()



if __name__ == '__main__':
    args = parse_args()
    my_welcome_socket = welcome_socket(args.port)
    while True:
            print("Server is waiting")
            # Finish three way hand shake in class my_welcome_socket
            server_socket_port = my_welcome_socket.accept(args)

