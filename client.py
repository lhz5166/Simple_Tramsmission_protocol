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
    # seq, ack is a 6 difits number start from '00000'
    # flag is three digits number with '0' = 'SYN','1' = 'ACK', '2' = 'FIN', 3 = 'SYN/ACK'
    # the length of a STP Header is 46 bytes
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
            self.seq = self.make_seq(para[0])
            self.ack = self.make_ack(para[1])
            self.flag = self.make_flag(para[2])
            self.window_size = bytes(para[3], encoding = 'utf-8')

            self.data = para[4]
            self.header = self.make_header()
            self.header_length = len(self.header)
            self.segment = self.header + self.data
        elif (len(para) == 1):
            self.analyse_segment(para[0])
        else:
            raise ParameterError(f'wrong number of parameters   {para}')

    def make_seq(num):
        if len(num) == 1:
            return '0000' + str(num)
        elif len(num) == 2:
            return '000' + str(num)
        elif len(num) == 3:
            return '00' + str(num)
        elif len(num) == 4:
            return '0' + str(num)
        elif len(num) == 5:
            return str(num)
        else:
            raise ValueError(f'Invailed Sequence Number!   {num}')
            return
    def make_ack(num):
        if len(num) == 1:
            return '0000' + str(num)
        elif len(num) == 2:
            return '000' + str(num)
        elif len(num) == 3:
            return '00' + str(num)
        elif len(num) == 4:
            return '0' + str(num)
        elif len(num) == 5:
            return str(num)
        else:
            raise ValueError(f'Invailed Acknowledge Number!   {num}')
            return

    def make_flag(fg):
        if flag == 'SYN':
            return '001'
        elif flag == 'ACK':
            return '010'
        elif flag == 'FIN':
            return '100'
        elif flag == 'SYN/ACK':
            return '011'
        else:
            raise ValueError(f'Invailed Flag!   {fg}')
            return

    def make_header(self):
        header = self.seq + self.ack + self.flag + self.window_size
        return bytes(header, encoding = 'utf-8')

    def analyse_segment(self, segment):
        self.header= segment[0:50]
        self.data = str(segment[50:], encoding = 'utf-8')
        self.seq = int(self.header[0:5])
        self.ack = int(self.header[5:9])
        self.flag = self.get_flag(str(self.header[10:13], encoding = 'utf-8'))
        self.window_size = int(self.header[13:])
        self.header_length = len(self.header)

    def get_flag(self, fg):
        if fg == '001':
            self.flag = 'SYN'
        elif fg == '010':
            self.flag = 'ACK'
        elif fg == '100':
            self.flag = 'FIN'
        elif fg == '011':
            self.flag = 'SYN/ACK'
        else:
            raise ValueError(f'Invailed Flag!   {fg}')