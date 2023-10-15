
import binascii
import socket
import sys
import random
import time
from collections import OrderedDict
from bs4 import BeautifulSoup

# Same functions from Project Part 2, used to build a local server
#Function for decoding header section from response
def decode_header_resp(message):
    # Returns: decoded header information, and count number on each section
    # Paramerter: message (response get from server)
    header_info = {
        "ID":[],
        "QPARAMS":{},
        "QDCOUNT": [],
        "ANCOUNT": [],
        "NSCOUNT": [],
        "ARCOUNT": [],
    }

    #Parse each portion by bits from given message
    ID = message[0:4]
    query_params = message[4:8]
    QDCOUNT = message[8:12]
    ANCOUNT = message[12:16]
    NSCOUNT = message[16:20]
    ARCOUNT = message[20:24]

    #Convert and parse flags from query parameters
    params = "{:b}".format(int(query_params, 16)).zfill(16)
    QPARAMS = OrderedDict([
        ("QR", params[0:1]),
        ("OPCODE", params[1:5]),
        ("AA", params[5:6]),
        ("TC", params[6:7]),
        ("RD", params[7:8]),
        ("RA", params[8:9]),
        ("Z", params[9:12]),
        ("RCODE", params[12:16])
    ])

    #Save into header information
    header_info["ID"]=(ID)
    header_info["QPARAMS"]=(QPARAMS)
    header_info["QDCOUNT"]=(QDCOUNT)
    header_info["ANCOUNT"]=(ANCOUNT)
    header_info["NSCOUNT"]=(NSCOUNT)
    header_info["ARCOUNT"]=(ARCOUNT)

    #Decode Counts (into oct for reading)
    num_answers = int(ANCOUNT, 16)
    num_authorative = int(NSCOUNT, 16)
    num_additional = int(ARCOUNT, 16)
    return header_info, num_answers, num_authorative, num_additional

#Function for decoding question section from response
def decode_question_resp(message):
    # Returns: decoded question information, the end point for question section
    # Paramerter: message (response get from server)
    question_info = {
        "QNAME":[],
        "QTYPE":[],
        "QCLASS": []
    }
    # A fix length of header, so question start at 24
    question_start_pt = 24

    # Get first part of the QName
    qname_part_start=26
    part_len = message[question_start_pt:question_start_pt+2]
    qname_part_end = qname_part_start + (int(part_len,16)*2)
    qname_part=[]

    # while loop: keeping getting the QNames untill '00'
    # Each part of QNAME is save into qname_part, parse by "00"
    while (part_len != "00" and qname_part_end <= len(message)):
        qname_part.append(message[qname_part_start:qname_part_end])
        question_start_pt = qname_part_end
        qname_part_start = question_start_pt + 2
        part_len = message[question_start_pt:question_start_pt + 2]
        qname_part_end = qname_part_start + (int(part_len, 16) * 2)

    #Decode all of the qname_part into readable version
    QNAME = ""
    for part in qname_part:
       x = binascii.unhexlify(part).decode()
       QNAME = QNAME+x+"."
    QNAME = QNAME[:-1]

    #Parse further part of question section
    qtype_start = qname_part_end
    qtype_end = qtype_start+4
    qclass_start = qtype_end
    qclass_end = qclass_start+4
    QTYPE = message[qtype_start:qtype_end]
    QCLASS = message[qclass_start:qclass_end]

    #Save into questin_info
    question_info["QNAME"] = (QNAME)
    question_info["QTYPE"] = (QTYPE)
    question_info["QCLASS"] = (QCLASS)

    return question_info, qclass_end

#Function for decoding answer, additional, authoritive section from response (one function for same format)
def decode_resp(message, msg_start, num_answers):
    # Returns: decoded section information, ip_addr(decode ip address from RData for next server),the end point for current section
    # Paramerter: message (response get from server), msg_start (the start point for current section), num_answers(count from header)
    answers = []
    ip_addr = []

    #iterate through all answers
    if num_answers > 0:
        for answer_i in range (num_answers):
            #print (answer_i)
            NAME = message[msg_start:msg_start + 4]  # Refers to Question
            #print ("Name:", NAME)
            TYPE = message[msg_start + 4:msg_start + 8]
            #print("TYPE:", TYPE)
            CLASS = message[msg_start + 8:msg_start + 12]
            #print("CLASS:", CLASS)
            x= message[msg_start + 12:msg_start + 20]
            #print("before convert, x: ", x)
            state_10 = int(x, 16)
            #print ("after convert, x: ", state_10)
            TTL = state_10
            x = message[msg_start + 20:msg_start + 24]
            state_10 = int(x, 16)
            RDLENGTH = state_10
            #print ("RDLENGTH:", RDLENGTH)

            RDDATA = message[msg_start + 24:msg_start + 24 + (RDLENGTH * 2)]
            RDDATA_decoded = ""
            #print ("RDDATA", RDDATA)
            if (TYPE == "0001"):
                tmp = [RDDATA[i:i + 2] for i in range(0, len(RDDATA), 2)]  # parse into 2,2,2,2 for ip
                for i in tmp:
                    x = int(i, 16)
                    x = str(x)
                    RDDATA_decoded = RDDATA_decoded + x + "."
                RDDATA_decoded = RDDATA_decoded[:-1]
            msg_start = msg_start + 24 + (RDLENGTH * 2)

            #One of the answer save to answers
            answer = {"NAME": NAME, "TYPE": TYPE, "CLASS": CLASS, "TTL": TTL, "RDLENGTH": RDLENGTH, "RDATA": RDDATA,
                      "RDATA_DECODED": RDDATA_decoded}
            answers.append(answer)
            ip_addr.append(RDDATA_decoded)

    return answers, ip_addr, msg_start

#Function for build up message header section
def header():
    header = ""
    ID = "aa0a" #Random assigned
    state_10 = int(ID, 16)
    state_2_1 = '{:04x}'.format(state_10)
    QR_OPCODE = "0000"
    state_10 = int(QR_OPCODE, 16)
    state_2_2 = '{:04x}'.format(state_10)
    QDCOUNT = "0001" #One question as request
    state_10 = int(QDCOUNT, 16)
    state_2_3 = '{:04x}'.format(state_10)
    ANCOUNT = "0000"
    state_10 = int(ANCOUNT, 16)
    state_2_4 = '{:04x}'.format(state_10)
    NSCOUNT = "0000"
    state_10 = int(NSCOUNT, 16)
    state_2_5 = '{:04x}'.format(state_10)
    ARCOUNT = "0000"
    state_10 = int(ARCOUNT, 16)
    state_2_6 = '{:04x}'.format(state_10)
    message =  state_2_1 + state_2_2 + state_2_3 + state_2_4 + state_2_5 + state_2_6

    #print (message)
    return message

#Function for build up message question section
def question (QNAME = "tmz.com"):
    #QNAME default set as tmz.com or other from command line
    message = ""
    addr_parts = QNAME.split(".")
    #Enocde the QNAME
    for part in addr_parts:
        addr_len = "{:02x}".format(len(part))
        addr_part = binascii.hexlify(part.encode())
        message += addr_len
        message += addr_part.decode()

    message += "00"  # Terminating bit for QNAME
    QTYPE = "0001"
    state_10 = int(QTYPE, 16)
    state_2_1 = '{:04x}'.format(state_10)
    QCLASS = "0001"
    state_10 = int(QCLASS, 16)
    state_2_2 = '{:04x}'.format(state_10)
    message = message + state_2_1 + state_2_2
    #print (message)
    return message

def tcpConnection (ip_addr,target):
    #print (ip_addr[0])
    target_host = ip_addr
    target_port = 80
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_host, target_port))
    request = "GET / HTTP/1.1\r\nHost:%s\r\n\r\n" %target
    client.send(request.encode())

    # receive some data
    response = client.recv(4096)
    http_response = repr(response)
    http_response_len = len(http_response)

    soup = BeautifulSoup(http_response, "html.parser") # TODO format ok?

    # open the file in w mode
    # set encoding to UTF-8
    with open("output3.html", "w", encoding='utf-8') as file:
        # prettify the soup object and convert it into a string
        file.write(str(soup.prettify()))

    return

if __name__ == "__main__":
    RTT_WITH_Cache = {}
    RTT_WITH_No_Cache = {}
    my_cache = {
        "host_name":"ip_address_answer"
    }
    TTL_list_inCache = {

    }
    current_time = time.time()
    min_TTL = current_time+1
    min_TTL_name = ""
    while True:
        while (current_time < min_TTL): #do not delete from cache yet
            current_time = time.time()
            print ("INPUT: ")
            #Receive Hostname
            received_host = input()
            RTT_receive = time.time()
            if received_host in my_cache: #found in cache
                #send back!
                print("Send back to client here,", my_cache[received_host])
                RTT_send_back = time.time()
                RTT_WITH_Cache[received_host] = (RTT_send_back-RTT_receive)
                print("This Hostname is found in Cache, RTT is %.4f"%(RTT_send_back-RTT_receive))
                current_time = time.time()
            else:  #Do the regular Request through three levels of DNS server
                RTT_LIST = []  # RTT time for each server
                Server_ip = []  # Save for each server ip
                HOST_Name = received_host  # Host request from command line

                # Build message to send
                message = header() + question(HOST_Name)
                message = message.replace(" ", "").replace("\n", "")

                # 1. Send to ROOT DNS
                HOST = "198.41.0.4"  # a.root-servers.net
                PORT = 53
                # send request to the root-server
                ts_root_start = time.time()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect((HOST, PORT))
                    s.sendall(binascii.unhexlify(message))
                    data, _ = s.recvfrom(4096)
                    s.close()
                # Save the RTT and picked TLD server IP address
                ts_root_end = time.time()
                RRT_root = ts_root_end - ts_root_start
                RTT_LIST.append(RRT_root)
                Server_ip.append(HOST)

                # Decode received data
                response = binascii.hexlify(data).decode("utf-8")  # turn into the hex
                # Prase response from ROOT-DNS
                header_info, num_answers, num_authorative, num_additional = decode_header_resp(response)
                question_info, Q_ends = decode_question_resp(response)
                answer_info, ip_addr, A_ends = decode_resp(response, Q_ends, num_answers)
                authorative_info, name, Au_ends = decode_resp(response, A_ends, num_authorative)
                additional_info, ip_addr, ad_ends = decode_resp(response, Au_ends, num_additional)

                # 2. Send to TLD DNS
                # clear the decoded ip address; ivp6 is cleared out
                non_empty_ipaddr = []
                for i in ip_addr:
                    if i != "":
                        non_empty_ipaddr.append(i)
                HOST = random.choice(non_empty_ipaddr)

                ts_TLD_start = time.time()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect((HOST, PORT))
                    s.sendall(binascii.unhexlify(message))
                    data, _ = s.recvfrom(4096)

                    s.close()
                ts_TLD_end = time.time()
                RRT_TLD = ts_TLD_end - ts_TLD_start
                RTT_LIST.append(RRT_TLD)
                Server_ip.append(HOST)

                response = binascii.hexlify(data).decode("utf-8")
                # Prase response from ROOT-DNS
                header_info, num_answers, num_authorative, num_additional = decode_header_resp(response)
                question_info, Q_ends = decode_question_resp(response)
                answer_info, ip_addr, A_ends = decode_resp(response, Q_ends, num_answers)
                authorative_info, name, Au_ends = decode_resp(response, A_ends, num_authorative)
                additional_info, ip_addr, ad_ends = decode_resp(response, Au_ends, num_additional)

                # 3. Send to Auth DNS
                non_empty_ipaddr = []
                for i in ip_addr:
                    if i != "":
                        non_empty_ipaddr.append(i)
                HOST = random.choice(non_empty_ipaddr)

                ts_Auth_start = time.time()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect((HOST, PORT))
                    s.sendall(binascii.unhexlify(message))
                    data, _ = s.recvfrom(4096)

                    s.close()
                ts_Auth_end = time.time()
                RRT_Auth = ts_Auth_end - ts_Auth_start
                RTT_LIST.append(RRT_Auth)
                Server_ip.append(HOST)

                response = binascii.hexlify(data).decode("utf-8")
                # Prase response from ROOT-DNS
                header_info, num_answers, num_authorative, num_additional = decode_header_resp(response)
                question_info, Q_ends = decode_question_resp(response)
                answer_info, ip_addr, A_ends = decode_resp(response, Q_ends, num_answers)
                authorative_info, name, Au_ends = decode_resp(response, A_ends, num_authorative)
                additional_info, ip_addr_auth, ad_ends = decode_resp(response, Au_ends, num_additional)

                # Randomly select the address from answer section, to build TCP Connection
                non_empty_ipaddr = []
                for i in ip_addr:
                    if i != "":
                        non_empty_ipaddr.append(i)
                address = random.choice(non_empty_ipaddr)
                used_ip_index = non_empty_ipaddr.index(address)

                # -----------------------------------------------------------------------------------
                RTT_send_back = time.time()
                RTT_WITH_No_Cache[received_host] = (RTT_send_back - RTT_receive)
                print("Host is not found in cache, the RTT is %.4f"%(RTT_send_back - RTT_receive))

                #Add the address to cache
                my_cache[received_host] = address

                current_time = time.time()
                TTL = answer_info[used_ip_index]["TTL"] + current_time
                print("TTL for %s"%received_host, " is %.4fs"%answer_info[used_ip_index]["TTL"])
                TTL_list_inCache[received_host] = TTL

                min_TTL_name = min(TTL_list_inCache, key=TTL_list_inCache.get)
                min_TTL = TTL_list_inCache[min_TTL_name]
                # -----------------------------------------------------------------------------------

        #When Current_time = min_TTL, the min_TTL needs to be deleted
        my_cache.pop(min_TTL_name)
