# -*- coding: utf-8 -*-
"""
Created on Wed Sep 12 23:03:40 2018

@author: Carvin
"""
from socket import socket
import sys
import threading
import time
import os
import random


class VauleError(Exception):
    def __init__(self, message):
        self.message = message

class ParameterError(Exception):
    def __init__(self, message):
        self.message = message

class Segment:
    # define a STP segment
    # seq, ack is a 6 difits number start from '0000000000'
    # flag is three digits number with '0' = 'SYN','1' = 'ACK', '2' = 'FIN', 3 = 'SYN/ACK'
    # the length of a STP Header is 50 bytes
    # digits[0:5] is SEQ number
    # difits[5:10] is ACK number
    # digits[10:13] is flag
    # difit[13:117] is window size
    # for making a STP segment
    # para[0] is sequence number
    # para[1] is acknowledge number
    # para[2] is flag
    # para[3] is MWS
    # para[4] is data
    def __init__(self, *para):
        if (len(para) == 5):
            self.seq = para[0]                          # integer
            self.ack = para[1]                          # integer
            self.flag = para[2]                         # str in ['SYN', 'ACK', 'FIN']
            self.window_size = para[3]                  # integer
            self.data = para[4]                         # bytes
            self.checksum = self.make_checksum()        # str with hex
            self.header = self.make_header()            # bytes
            self.header_length = len(self.header)       # integer
            self.segment = self.header + self.data      # bytes
        elif (len(para) == 1):
            self.analyse_segment(para[0])
        else:
            raise ParameterError(f'wrong number of parameters   {para}')

    def _encode(data):             # data should be an integer
        return hex(data)[2:]

    def _decode(data):             # data should be a bytes
        data = str(data, encoding = 'utf-8')
        return int(data, 16)

    def make_seq(self, num):
        num = self._encode(num)
        if len(num) == 1:
            return '0000000' + str(num)
        elif len(num) == 2:
            return '000000' + str(num)
        elif len(num) == 3:
            return '00000' + str(num)
        elif len(num) == 4:
            return '0000' + str(num)
        elif len(num) == 5:
            return '000' + str(num)
        elif len(num) == 6:
            return '00' + str(num)
        elif len(num) == 7:
            return '0' + str(num)
        elif len(num) == 8:
            return str(num)
        else:
            raise ValueError(f'Invailed Sequence Number!   {num}')

    def make_ack(self, num):
        num = self._encode(num)
        if len(num) == 1:
            return '0000000' + str(num)
        elif len(num) == 2:
            return '000000' + str(num)
        elif len(num) == 3:
            return '00000' + str(num)
        elif len(num) == 4:
            return '0000' + str(num)
        elif len(num) == 5:
            return '000' + str(num)
        elif len(num) == 6:
            return '00' + str(num)
        elif len(num) == 7:
            return '0' + str(num)
        elif len(num) == 8:
            return str(num)
        else:
            raise ValueError(f'Invailed Acknowledged Number!   {num}')

    def make_window(self, num):         # num is integer
        num = self._encode(num)
        if len(num) == 1:
            return '0' + str(num)
        elif len(num) == 2:
            return str(num)


    def make_flag(self, flag):          # flag is str
        if flag == 'SYN':
            return self._encode(int('0b0001', 2))
        elif flag == 'ACK':
            return self._encode(int('0b0010', 2))
        elif flag == 'FIN':
            return self._encode(int('0b0100', 2))
        elif flag == 'SYN/ACK':
            return self._encode(int('0b1000', 2))
        else:
            raise ValueError(f'Invailed Flag!   {fg}')

    def make_checksum(self):
        check_sum = 0
        dtt = self.data.hex()
        # take every 4 digits hex to a adder
        for i in range(0, len(dt), 4):
            check_sum += int(dt[i:i + 4], 16)   # convert 4 digits hex to int
            # rollback
            if check_sum > 65535:
                a = int(hex(check_sum)[0:-4], 16)
                b = int(hex(check_sum)[-4:], 16)
                check_sum = a + b
        # change signed int into unsigned int
        check_sum = ~check_sum
        check_sum &= int('0xffff', 16)
        return hex(check_sum)

    def make_header(self):
        header = self.make_seq(self.seq)
                    + self.make_ack(self.ack)
                    + self.make_flag(self.flag)
                    + self.make_window(self.window_size)
                    + self.checksum
        return bytes(header, encoding = 'utf-8')

    def analyse_segment(self, segment):
        self.header= segment[0:21]
        self.data = segment[21:]
        self.get_seq(self.header[0:8])
        self.get_ack(self.header[8:16])
        self.get_flag(self.header[16:17])
        self.get_window(self.header[17:19])
        self.get_checksum(self.header[19:21])

    def get_seq(self, data):             # data is bytes
        data = self.decode(data)
        self.seq = int(data, 16)

    def get_ack(self, data):             # data is bytes
        data = self.decode(data)
        self.ack = int(data, 16)

    def get_window(self, data):          # data is bytes
        data = self.decode(data)
        self.window_size = int(data, 16)

    def get_checksum(self, data):        # data is bytes
        data = self.decode(data)
        self.checksum = int(data, 16)

    def get_flag(self, data):            # data is bytes
        fg = str(data, encoding = 'utf-8')
        fg = int(fg, 16)
        if fg == int('0001',2):
            self.flag = 'SYN'
        elif fg == int('0010',2):
            self.flag = 'ACK'
        elif fg == int('0100', 2):
            self.flag = 'FIN'
        elif fg == int('1000', 2):
            self.flag = 'SYN/ACK'
        else:
            raise ValueError(f'Invailed Flag!   {fg}')

    def is_corrupt(self):
        if self.checksum + self.make_checksum(self.data) == int('0xffffffffffffffff', 16):
            return False
        else:
            return True





class Server:
    def __init__(self, ip, port, argv):
        # arguments for server
        self.host_ip = argv[1]
        self.host_port = int(argv[2])
        self.MWS = sys.argv[4]
        self.LastByteSent = 0
        self.LastByteAcked = 0
        self.MSS = int(sys.argv[5])
        self.gamma = int(sys.argv[6])
        self.next_seq_num = 0
        self.next_ack_num = 0
        self.fileName = sys.argv[3]
        self.filePath = os.path.abspath('.') + '\\' + self.fileName
        self.pck_recv = []
        self.pck_send = []
        self.BUFFER = self.MSS + 60

        # arguments for PLDs
        self.pDrop = float(sys.argv[7])
        self.pDuplicate = float(sys.argv[8])
        self.pCorrupt = float(sys.argv[9])
        self.pOrder = float(sys.argv[10])
        self.maxOrder = float(sys.argv[11])
        self.pDelay = float(sys.argv[12])
        self.maxDelay = int(sys.argv[13])
        self.seed_num = int(sys.argv[14])

    def rdt_send(self, data):
        sock.send(data)

    def recv():
        pass

    def readfile(self, filePath):
        with open(filePath, 'rb') as file:
            data = file.read()
        return data

    def make_pkt(self, data):
        seg = Segment(self.seq_num, self.ack_num, 'ACK', self.MWS, data)
        return seg.segment

    def rdt_send(self, data):
        seg = make_pkt(data)


    def shake_hand(self, pck):
        pass

    def listen(self):
        print(f'Start listen:')

    def log(self,*para):
        # parameters order is event, time, top, seq, nobd, ack
        fileNmae = 'Sender_log.txt'
        if len(para) == 0:
            with open(os.path.abspath('.') + '\\' + 'Sender_log.txt', 'w') as file:
                file.write('event/' + 'time/' + 'type_of_packet/'
                                   + 'seq_number/' + 'number_of_bytes_data/'
                                   + 'ack_number')
        elif len(para) == 6:
            with open(os.path.abspath('.') + '\\' + 'Sender_log.txt', 'a') as file:
                file.write(para[0] + '/'
                           + para[1] + '/'
                           + para[2] + '/'
                           + para[3] + '/'
                           + para[4] + '/'
                           + para[5] + '/')

    def isACK(self, data):
        seg = Segment(data)
        if seg.flag in 'ACK':
            return True
        else:
            return False
    def isSYN(self, data):
        seg = Segment(data)
        if seg.flag in 'SYN':
            return True
        else:
            return False
    def isFIN(self, data):
        seg = Segment(data)
        if seg.flag in 'FIN':
            return True
        else:
            return False
    def connection():
        pass
    def func_timer():
        pass
    def checksum():
    def plds():
        pass

host_addr = sys.argv[1]
port = int(sys.argv[2])


# random.seed(seed_num);
# random.random(0,1)
server = Server(host_addr, port, sys.argv)
sock = socket(socket.AF_INET, socket.DGRAM)
host = (host_addr, port)
sock.bind(host)
BUFFER = server.MSS + 60 + sys.getsizeof(b'')
fg = 0
sent_flag = 0


while True:



print('Finsh!')
sock.close()

































