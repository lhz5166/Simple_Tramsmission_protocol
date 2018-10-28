# -*- coding: utf-8 -*-
"""
Created on Wed Sep 12 23:03:40 2018

@author: Carvin
"""
import socket
import sys
from threading import Timer, Thread, Lock
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
            self.window_size = int(para[3])             # integer
            self.data = para[4]                         # bytes
            self.len_data = len(self.data)
            self.checksum = self.make_checksum()        # str with hex
            self.header = self.make_header()            # bytes
            self.len_header = len(self.header)
            self.segment = self.header + self.data      # bytes
        elif (len(para) == 1):
            # print(para[0])
            self.analyse_segment(para[0])
        else:
            raise ParameterError(f'wrong number of parameters   {para}')

    def _encode(self, data):             # data should be an integer
        return hex(data)[2:]

    def _decode(self, data):             # data should be a bytes
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
            return '0000000' + num
        elif len(num) == 2:
            return '000000' + num
        elif len(num) == 3:
            return '00000' + num
        elif len(num) == 4:
            return '0000' + num
        elif len(num) == 5:
            return '000' + num
        elif len(num) == 6:
            return '00' + num
        elif len(num) == 7:
            return '0' + num
        elif len(num) == 8:
            return num
        else:
            raise ValueError(f'Invailed Acknowledged Number!   {num}')

    def make_window(self, num):         # num is integer
        num = self._encode(num)
        if len(num) == 1:
            return '00' + num
        elif len(num) == 2:
            return '0' + num
        elif len(num) == 3:
            return num
        else:
            raise ValueError(f'Invailed Acknowledged Number!   {num}')


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
        dt = self.data.hex()
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
        # print(hex(check_sum))
        if len(hex(check_sum)[2:]) == 1:
            return '000' + hex(check_sum)[2:]
        elif len(hex(check_sum)[2:]) == 2:
            return '00' + hex(check_sum)[2:]
        elif len(hex(check_sum)[2:]) == 3:
            return '0' + hex(check_sum)[2:]
        elif len(hex(check_sum)[2:]) == 4:
            return hex(check_sum)[2:]

    def make_header(self):
        header = self.make_seq(self.seq)\
                    + self.make_ack(self.ack)\
                    + self.make_flag(self.flag)\
                    + self.make_window(self.window_size)\
                    + self.checksum
        return bytes(header, encoding = 'utf-8')

    def analyse_segment(self, segment):
        self.header= segment[0:24]
        self.data = segment[24:]
        self.get_seq(self.header[0:8])
        self.get_ack(self.header[8:16])
        self.get_flag(self.header[16:17])
        self.get_window(self.header[17:20])
        self.checksum = str(self.header[20:24], encoding = 'utf-8')
        self.len_data = len(self.data)

    def get_seq(self, data):             # data is bytes
        data = self._decode(data)
        self.seq = data

    def get_ack(self, data):             # data is bytes
        data = self._decode(data)
        self.ack = data

    def get_window(self, data):          # data is bytes
        data = self._decode(data)
        self.window_size = data

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
        # print(self.checksum)
        # print(self.make_checksum()) 
        if int(self.checksum, 16) == int(self.make_checksum(), 16):
            return False
        else:
            return True

def log(*para):
    # parameters order is event, time, top, seq, nobd, ack
    event = ''
    if len(para) == 0:
        if os.path.exists(os.path.abspath('.') + '\\' + 'Reciver_log.txt'):
            os.remove(os.path.abspath('.') + '\\' + 'Reciver_log.txt')
        with open(os.path.abspath('.') + '\\' + 'Reciver_log.txt', 'w') as file:
            file.write('<event>' + '<time>' + '<type_of_packet>'
                               + '<seq_number>' + '<number_of_bytes_data>'
                               + '<ack_number>' + '\n')
    elif len(para) == 6:
        events = {0: 'snd', 1: 'rcv', 2: 'drop', 3: 'corr', 4: 'dup',
                  5: 'rord', 6: 'dely', 7: 'DA', 8: 'RXT'}
        for i in para[0]:
            event += events[int(i)]
            event += '/'
        event = '<' + event[:-1] + '>'
        time = '<' + str(para[1]) + '>'
        types = {'SYN': 'S', 'ACK': 'A', 'FIN': 'F', 'Data': 'D', 'SYN/ACK': 'SA'}
        type_of_packet = '<' + types[para[2]] + '>'
        seq = '<' + str(para[3]) +'>'
        data_len = '<' + str(para[4]) + '>'
        ack = '<' + str(para[5]) +'>'
        with open(os.path.abspath('.') + '\\' + 'Reciver_log.txt', 'a') as file:
            file.write(event + time + type_of_packet  + seq + data_len + ack + '\n')
    elif len(para) == 7:
        with open(os.path.abspath('.') + '\\' + 'Reciver_log.txt', 'a') as file:
            file.write(f'===========================================================\n')
            file.write(f'Amount of data received (byte)                        {para[0]}\n')
            file.write(f'Total Segments received                               {para[1]}\n')
            file.write(f'Data segments received                                {para[2]}\n')
            file.write(f'Data segments with Bit Errors                         {para[3]}\n')
            file.write(f'Duplicate data segments received                      {para[4]}\n')
            file.write(f'Duplicate ACKs sent                                   {para[5]}\n')
            file.write(f'===========================================================\n')

def writefile(*data):
    global file_name
    if len(data) == 0:
        if os.path.exists(os.path.abspath('.') + '\\' + file_name):
            os.remove(os.path.abspath('.') + '\\' + file_name)
        if not os.path.exists(os.path.abspath('.') + '\\' + file_name):
            with open(os.path.abspath('.') + '\\' + file_name, 'wb') as file:
                pass
    if len(data) == 1:
        with open(os.path.abspath('.') + '\\' + file_name, 'ab') as file:
            file.write(data[0])

def shakehand():
    print('waiting for shakehand......')
    global recv_base
    global next_seq
    global next_ack
    global start_time
    global num_seg
    while True:
        data, addr = sock.recvfrom(BUFFER)
        packet_recv = Segment(data)
        num_seg += 1
        log([1], round(time.time() - start_time, 2), packet_recv.flag,
            packet_recv.seq, len(packet_recv.data), packet_recv.ack)
        print('Recived packet seq, ack is: ', packet_recv.seq, packet_recv.ack)
        if packet_recv.flag == 'SYN':
            print('receive a SYN')
            packet_send = Segment(next_seq, next_ack, 'SYN/ACK', MWS, b'')
            sock.sendto(packet_send.segment, addr)
            log([0], round(time.time() - start_time, 2), packet_send.flag,
                packet_send.seq, len(packet_send.data), packet_send.ack)
            print('Send a SYN/ACK seq, ack is: ', next_seq, next_ack)
        if packet_recv.flag == 'ACK':
            recv_base += 1
            break
    print(' Shakehand success!')


receiver_port = int(sys.argv[1])
file_name = sys.argv[2]
data_recv = []
recv_base = 0
next_seq = 0
next_ack = 1
num_data = 0
num_seg = 0
num_seg_data = 0
num_seg_cor = 0
num_seg_dup = 0
num_ack_sent = 0
MWS = 0
BUFFER = 1024
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host = ('localhost', receiver_port)
sock.bind(host)

print('waiting for request.....')

writefile()
log()
start_time = time.time()
shakehand()
print('Start data transmission ......')
while True:
    data, addr = sock.recvfrom(BUFFER)
    packet_recv = Segment(data)
    num_seg += 1
    print('receive an ack pack seq, ack, corrupt is: ', packet_recv.seq, packet_recv.ack, packet_recv.is_corrupt())
    if packet_recv.is_corrupt():
        num_seg_cor += 1
        print('received packet checksum: ', packet_recv.make_checksum())
        #print(data)
    if (not packet_recv.is_corrupt()) and (packet_recv.flag == 'ACK'):
        num_seg_data += 1
        log([1], round(time.time() - start_time, 2), 'Data',
            packet_recv.seq, len(packet_recv.data), packet_recv.ack)
        MWS = packet_recv.window_size
        if packet_recv.seq > recv_base:
            # append data in to reciver buffer
            packet_send = Segment(packet_recv.ack, recv_base, 'ACK', MWS, b'')
            sock.sendto(packet_send.segment, addr)
            log([0], round(time.time() - start_time, 2), packet_send.flag,
                packet_send.seq, len(packet_send.data), packet_send.ack)
            print('Send an ack pack seq, ack is: ', packet_send.seq, packet_send.ack)
            flag = 0
            if packet_recv not in data_recv:
                data_recv.append(packet_recv)
                data_recv.sort(key = lambda x: x.seq)
            else:
                num_seg_dup += 1
                
        if packet_recv.seq == recv_base:
            if packet_recv not in data_recv:
                data_recv.append(packet_recv)
                data_recv.sort(key = lambda x: x.seq)
            pre_base = recv_base
            for pack in data_recv:
                if pack.seq == recv_base:
                    recv_base = pack.seq + len(pack.data)
            print('recv_base: ', recv_base)
            for pack in data_recv:
                if pack.seq == pre_base and pre_base < recv_base:
                    writefile(pack.data)
                    num_data += len(pack.data)
                    pre_base = pack.seq + len(pack.data)
            packet_send = Segment(packet_recv.ack, recv_base, 'ACK', MWS, b'')
            sock.sendto(packet_send.segment, addr)
            log([0], round(time.time() - start_time, 2), packet_send.flag,
                packet_send.seq, len(packet_send.data), packet_send.ack)
            print('Send an ack pack seq, ack is: ', packet_send.seq, packet_send.ack)

        elif packet_recv.seq < recv_base:
            num_seg_dup += 1
            packet_send = Segment(packet_recv.ack, recv_base, 'ACK', MWS, b'')
            sock.sendto(packet_send.segment, addr)
            num_ack_sent += 1
            log([0,7], round(time.time() - start_time, 2), packet_send.flag,
                packet_send.seq, len(packet_send.data), packet_send.ack)
            print('Send a ack pack seq, ack is: ', packet_send.seq, packet_send.ack) 

    if packet_recv.flag == 'FIN':
        num_seg += 1
        log([1], round(time.time() - start_time, 2), packet_recv.flag,
            packet_recv.seq, len(packet_recv.data), packet_recv.ack)
        packet_send = Segment(packet_recv.ack, packet_recv.seq + 1, 'ACK', MWS, b'')
        sock.sendto(packet_send.segment, addr)
        log([0], round(time.time() - start_time, 2), packet_send.flag,
                packet_send.seq, len(packet_send.data), packet_send.ack)
        packet_send = Segment(packet_recv.ack, packet_recv.seq + 1, 'FIN', MWS, b'')
        sock.sendto(packet_send.segment, addr)
        log([0], round(time.time() - start_time, 2), packet_send.flag,
                packet_send.seq, len(packet_send.data), packet_send.ack)
        data, addr = sock.recvfrom(BUFFER)
        num_seg += 1
        packet_recv = Segment(data)
        log([1], round(time.time() - start_time, 2), packet_recv.flag,
                packet_recv.seq, len(packet_recv.data), packet_recv.ack)
        break
        
log(num_data, num_seg, num_seg_data, num_seg_cor, num_seg_dup, num_ack_sent, 0)
for pack in data_recv:
    print(pack.seq)
print('Transmission Complete!')
sock.close()


