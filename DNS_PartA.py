

import binascii
import socket
import struct
import sys
from collections import OrderedDict
from bs4 import BeautifulSoup
import time
import random
# See https://web.archive.org/web/20180919041301/https://routley.io/tech/2017/12/28/hand-writing-dns-messages.html
# See https://tools.ietf.org/html/rfc1035

def header():
    header = ""
    ID = "aa0a"
    state_10 = int(ID, 16)
    state_2_1 = '{:04x}'.format(state_10)
    QR_OPCODE = "0000"
    state_10 = int(QR_OPCODE, 16)
    state_2_2 = '{:04x}'.format(state_10)
    QDCOUNT = "0001"
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

def question (hostname):
    message = ""
    QNAME = hostname
    addr_parts = QNAME.split(".")
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

def decode_header_resp(message):
    header_info = {
        "ID":[],
        "QPARAMS":{},
        "QDCOUNT": [],
        "ANCOUNT": [],
        "NSCOUNT": [],
        "ARCOUNT": [],
    }

    ID = message[0:4]
    query_params = message[4:8]
    QDCOUNT = message[8:12]
    ANCOUNT = message[12:16]
    NSCOUNT = message[16:20]
    ARCOUNT = message[20:24]

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

    header_info["ID"]=(ID)
    header_info["QPARAMS"]=(QPARAMS)
    header_info["QDCOUNT"]=(QDCOUNT)
    header_info["ANCOUNT"]=(ANCOUNT)
    header_info["NSCOUNT"]=(NSCOUNT)
    header_info["ARCOUNT"]=(ARCOUNT)

    num_answers = int(ANCOUNT, 16)
    num_authorative = int(NSCOUNT, 16)
    num_additional = int(ARCOUNT, 16)
    # num_answers = max([int(ANCOUNT, 16), int(NSCOUNT, 16), int(ARCOUNT, 16)])
    return header_info, num_answers, num_authorative, num_additional

def decode_question_resp(message):
    # Question section
    question_info = {
        "QNAME":[],
        "QTYPE":[],
        "QCLASS": []
    }
    #print("question message:",  message)
    question_start_pt = 24

    # Get first part of the QName
    qname_part_start=26
    part_len = message[question_start_pt:question_start_pt+2]
    qname_part_end = qname_part_start + (int(part_len,16)*2)
    qname_part=[]

    # while loop: keeping getting the QNames untill '00'
    while (part_len != "00" and qname_part_end <= len(message)):
        qname_part.append(message[qname_part_start:qname_part_end])
        question_start_pt = qname_part_end
        qname_part_start = question_start_pt + 2
        part_len = message[question_start_pt:question_start_pt + 2]
        qname_part_end = qname_part_start + (int(part_len, 16) * 2)

    QNAME = ""
    for part in qname_part:
       x = binascii.unhexlify(part).decode()
       QNAME = QNAME+x+"."
    QNAME = QNAME[:-1]

    qtype_start = qname_part_end
    qtype_end = qtype_start+4
    qclass_start = qtype_end
    qclass_end = qclass_start+4
    QTYPE = message[qtype_start:qtype_end]

    QCLASS = message[qclass_start:qclass_end]
    question_info["QNAME"] = (QNAME)
    question_info["QTYPE"] = (QTYPE)
    question_info["QCLASS"] = (QCLASS)

    return question_info, qclass_end

def decode_resp(message, msg_start, num_answers):
    # Question section
    answers = []
    ip_addr = []
    #print("answer message:",  message)
    if num_answers > 0:
        for answer_i in range (num_answers):
            NAME = message[msg_start:msg_start + 4]  # Refers to Question

            TYPE = message[msg_start + 4:msg_start + 8]

            CLASS = message[msg_start + 8:msg_start + 12]

            x= message[msg_start + 12:msg_start + 20]

            state_10 = int(x, 16)

            TTL = state_10
            x = message[msg_start + 20:msg_start + 24]
            state_10 = int(x, 16)
            RDLENGTH = state_10
            RDDATA = message[msg_start + 24:msg_start + 24 + (RDLENGTH * 2)]
            RDDATA_decoded = ""

            if (TYPE == "0001"):
                tmp = [RDDATA[i:i + 2] for i in range(0, len(RDDATA), 2)]  # parse into 2,2,2,2 for ip
                for i in tmp:
                    x = int(i, 16)
                    x = str(x)
                    RDDATA_decoded = RDDATA_decoded + x + "."
                RDDATA_decoded = RDDATA_decoded[:-1]
            msg_start = msg_start + 24 + (RDLENGTH * 2)
            answer = {"NAME": NAME, "TYPE": TYPE, "CLASS": CLASS, "TTL": TTL, "RDLENGTH": RDLENGTH, "RDATA": RDDATA,
                      "RDATA_DECODED": RDDATA_decoded}
            answers.append(answer)
            ip_addr.append(RDDATA_decoded)

    return answers, ip_addr, msg_start

def tcpConnection (host_ip,target, count):
    target_host = host_ip
    target_port = 80
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_host, target_port))
    request = "GET / HTTP/1.1\r\nHost:%s\r\n\r\n" %target
    ts_start = time.time()
    client.send(request.encode())

    # receive some data
    response = client.recv(4096)
    ts_end = time.time()
    # print("RTT for HTTP: ", ts_end-ts_start, " second")
    http_response = repr(response)
    http_response_len = len(http_response)

    soup = BeautifulSoup(http_response, "html.parser")

    # open the file in w mode
    # set encoding to UTF-8
    if (count ==0):
        with open("PartA_http_Iran_ShangWu_918332750_ZhaolinZhong_916944852.html", "w", encoding='utf-8') as file:
            # prettify the soup object and convert it into a string
            file.write(str(soup.prettify()))
    elif (count ==1):
        with open("PartA_http_USA_ShangWu_918332750_ZhaolinZhong_916944852.html", "w", encoding='utf-8') as file:
            # prettify the soup object and convert it into a string
            file.write(str(soup.prettify()))
    else:
        with open("PartA_http_Canada_ShangWu_918332750_ZhaolinZhong_916944852.html", "w", encoding='utf-8') as file:
            # prettify the soup object and convert it into a string
            file.write(str(soup.prettify()))

    return

def build (HOST_list, message, count):
    for HOST in HOST_list:
    # test for part 3
    # HOST = "10.103.161.186"

    # server_addr = ("169.237.229.88",53)

        ts_start = time.time()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(10.0)
                try:
                    s.connect((HOST, PORT))
                    s.sendall(binascii.unhexlify(message))
                    data, _ = s.recvfrom(4096)
                except s.timeout :
                    s.close()
                    continue

        ts_end = time.time()
        if (ts_end - ts_start < 10.0):
            #print("RTT for DNS: ", ts_end - ts_start, " second")
            break

    response = binascii.hexlify(data).decode("utf-8") #turn into the hex


    # Decode response Question & Header

    header_info, num_answers, num_authorative, num_additional = decode_header_resp(response)
    #print("\nHeader Decode:", header_info)
    #print("ANCOUNT=", header_info["ANCOUNT"])

    question_info, Q_ends = decode_question_resp(response)
    #print("\nQuestion Decode:", question_info)
    #print("QNAME=", question_info["QNAME"])

    answer_info, ip_addr, A_ends = decode_resp(response, Q_ends, num_answers)
    #print("\nAnswer Decode:", answer_info)
    #print ("\nAnswer Ip Address Decode:", ip_addr)

    authorative_info, name, Au_ends = decode_resp(response, A_ends, num_authorative)
    additional_info, ip_addr1, ad_ends = decode_resp(response, Au_ends, num_additional)

    non_empty_ipaddr = []
    for i in ip_addr:
        if i != "":
            non_empty_ipaddr.append(i)

    website_ipaddr = random.choice(non_empty_ipaddr)
    tcpConnection(website_ipaddr, HOST_Name,count)

    # print output
    print ("Domain:", HOST_Name)
    print ("HTTP Server IP address:", website_ipaddr )
    return




if __name__ == "__main__":


    HOST_Name = sys.argv[1]

    # Build message to send
    message = header() + question(HOST_Name)
    message = message.replace(" ", "").replace("\n", "")
    HOST_list_USA = ["168.62.214.68","169.237.229.88", "104.42.159.98"]
    HOST_list_Iran = ["91.245.229.1", "46.224.1.42", "185.161.112.34"]
    HOST_list_Canada = ["136.159.85.15", "184.94.80.170", "142.103.1.1"]
    HOST_list =[HOST_list_Iran,HOST_list_USA,HOST_list_Canada]
    #Iran server sometimes gets error without responding
    #HOST_list = [HOST_list_USA, HOST_list_Canada]
    PORT = 53
    count =0
    for i in HOST_list:
        #We have this part just for test
        """
        if (count == 0):
            print ("Iran Local DNS Server")
        elif (count ==1):
            print ("USA Local DNS Server")
        else:
            print("Canada Local DNS Server")
         """
        build (i,message, count)
        count +=1
        print("\n")




