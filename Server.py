# -*- coding: utf-8 -*-
"""
Created on Wed Sep 12 23:03:40 2018

@author: Carvin
"""
import socket
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
            self.window_size = int(para[3])             # integer
            self.data = para[4]                         # bytes
            self.acked_pk = []
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
        # print(self.data)
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

    def get_checksum(self, data):        # data is bytes
        data = self._decode(data)
        self.checksum = data

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
        # arguments for server initialization
        self.host_ip = ip
        self.host_port = port
        self.host = (self.host_ip, self.host_port)
        self.MWS = int(sys.argv[4])
        self.MSS = int(sys.argv[5])
        self.gamma = int(sys.argv[6])
        self.fileName = sys.argv[3]
        self.fin_flag = False            # flag used to finish connection
        # arguments for server
        self.filePath = os.path.abspath('.') + '\\' + self.fileName
        self.data = self.readfile(self.filePath)
        self.timer = threading.Timer(0, self.func_timer)
        self.next_seq_num = 0
        self.next_ack_num = 0
        self.stop_flag = False
        self.s_time = 0
        self.send_buffer = []
        self.retran_flag = False
        self.reorder = []
        self.send_base = 0
        self.SampleRTT = 0
        self.Estimated_RTT = 0.5
        self.DevRTT = 0.25
        self.TimeoutInterval = 0
        self.BUFFER = 1024
        # arguments for record
        self.len_data = len(self.data)
        self.num_seg = 0
        self.num_pld = 0
        self.num_drop = 0
        self.num_cor = 0
        self.num_reo = 0
        self.num_dup = 0
        self.num_dely = 0
        self.num_ret_time = 0
        self.num_ret_fast = 0
        self.num_ack_dup = 0

        # arguments for PLDs
        self.pDrop = float(sys.argv[7])
        self.pDuplicated = float(sys.argv[8])
        self.pCorrupt = float(sys.argv[9])
        self.pOrder = float(sys.argv[10])
        self.maxOrder = float(sys.argv[11])
        self.pDelay = float(sys.argv[12])
        self.maxDelay = int(sys.argv[13])
        self.seed = int(sys.argv[14])
    def shakehand(self):
        print('Start 3-way shakehand......')
        self.s_time = time.time()
        packet = Segment(self.next_seq_num, self.next_ack_num, 'SYN', self.MWS, b'')
        sock.sendto(packet.segment, self.host)
        start_time = time.time()
        self.log([0], round(time.time() - self.s_time, 2), packet.flag,
                    packet.seq, len(packet.data), packet.ack)
        while True:
            data, addr = sock.recvfrom(self.BUFFER)
            packet_recv = Segment(data)
            end_time = time.time()
            self.log([1], round(end_time - self.s_time, 2), packet_recv.flag,
                    packet_recv.seq, len(packet_recv.data), packet_recv.ack)
            self.SampleRTT = end_time - start_time      # unit is ms           
            self.get_eRTT()
            self.get_devRTT()
            self.get_TimeoutInterval()
            self.next_seq_num = packet_recv.ack
            self.next_ack_num += 1
            if packet_recv.flag == 'SYN/ACK':
                packet = Segment(self.next_seq_num, self.next_ack_num, 'ACK', self.MWS, b'')
                sock.sendto(packet.segment, self.host)
                self.num_seg += 1
                self.log([0], round(time.time() - self.s_time, 2), packet.flag,
                    packet.seq, len(packet.data), packet.ack)

                break
        print('shakehand successiful!')

    def stop(self):
        global stop_flag
        self.timer.cancel()
        self.next_seq_num = self.send_base
        packet = Segment(self.next_seq_num, 
            self.next_ack_num, 'FIN', self.MWS, b'')
        sock.sendto(packet.segment, host)
        self.num_seg += 1
        self.log([0], round(time.time() - self.s_time, 2), packet.flag,
                packet.seq, len(packet.data), packet.ack)
        data, addr = sock.recvfrom(self.BUFFER)
        packet_recv = Segment(data)
        self.log([1], round(time.time() - self.s_time, 2), packet_recv.flag,
                packet_recv.seq, len(packet_recv.data), packet_recv.ack)
        data, addr = sock.recvfrom(self.BUFFER)
        packet_recv = Segment(data)
        self.log([1], round(time.time() - self.s_time, 2), packet_recv.flag,
                packet_recv.seq, len(packet_recv.data), packet_recv.ack)
        packet = Segment(packet_recv.seq, packet_recv.ack, 'ACK', self.MWS, b'')
        sock.sendto(packet.segment, self.host)
        self.num_seg += 1
        self.log([0], round(time.time() - self.s_time, 2), packet.flag,
            packet.seq, len(packet.data), packet.ack)
        print('stop connection')
        stop_flag = True

    def run(self):
        start_time = 0
        count_ack = 0           # counter for duplicate ACKs
        dup_ack = 0             # used for find duplicate packet
        sample_seq = 0
        self.send_base += 1
        print('start data transmission.......')
        while True:
            # load data into send buffer
            if (self.next_seq_num - self.send_base) < self.MWS and self.next_seq_num < len(self.data):
                if self.next_seq_num <= len(self.data) - self.MSS:
                    packet = Segment(self.next_seq_num, self.next_ack_num, 'ACK', self.MWS, 
                        self.data[self.next_seq_num - 1: self.next_seq_num + self.MSS - 1])
                elif self.next_seq_num > len(self.data) - self.MSS:
                    packet = Segment(self.next_seq_num, self.next_ack_num, 'ACK', self.MWS, 
                        self.data[self.next_seq_num - 1:])
                if not self.timer.isAlive():
                    self.timer = threading.Timer(self.TimeoutInterval, self.func_timer)
                    self.timer.start()
                if self.PLDs(packet):
                    self.send_buffer.append(packet)
            if self.next_seq_num > len(self.data) and self.send_base >len(self.data):       
                break
            # event_1: receive some data from upper layer
            if self.send_buffer != []:
                packet = self.send_buffer.pop(0)
                sock.sendto(packet.segment, self.host)
                self.num_seg += 1
                self.log([0], round(time.time() - self.s_time, 2), 'Data',
                        packet.seq, len(packet.data), packet.ack)
                print(f'Send data seq, ack, flag: {packet.seq}, {packet.ack}, {packet.flag}')
                
                    # self.timer.join()
                # test sampleRTT for some packets which is not retransmmit
                if self.random(50) < 0.3:
                    start_time = time.time()
                    sample_seq = packet.seq
                # get next sequence number
                self.next_seq_num += packet.len_data
                continue

            # event_2: receive ACK packet          
            data_recv, addr = sock.recvfrom(self.BUFFER)
            print('send_base', self.send_base)
            packet_recv = Segment(data_recv)
            # reiciving a ACK packet which acknowledge the packet used to test sampleRTT
            if packet_recv.ack == sample_seq:
                end_time = time.time()
                self.SampleRTT = abs(end_time - start_time)
                start_time = 0
                end_time = 0
                sample_seq = 0
                # calculate the new TimeoutInterval
                self.get_eRTT()
                self.get_devRTT()
                self.get_TimeoutInterval()
            # if receive an ACK with ack feild > sendBase
            if packet_recv.ack > self.send_base:
                self.log([1], round(time.time() - self.s_time, 2), packet_recv.flag,
                    str(packet_recv.seq), str(len(packet_recv.data)), str(packet_recv.ack))
                print('Recived a ACK packet seq, ack: ', packet_recv.seq, packet_recv.ack)
                self.send_base = packet_recv.ack
                # if there are some packets are any not-yet-acknowledged packet
                if(self.send_base <= self.next_seq_num - self.MSS):
                    if not self.timer.isAlive():
                        self.timer = threading.Timer(self.TimeoutInterval, self.func_timer)
                        self.timer.start()
                        #self.timer.join()
            # if receive a duplicate ack
            else:
                self.num_ack_dup += 1
                self.log([1,7], round(time.time() - self.s_time, 2), packet_recv.flag,
                    str(packet_recv.seq), str(len(packet_recv.data)), str(packet_recv.ack))
                print('Recived a dpulicated ACK packet seq, ack: ', packet_recv.seq, packet_recv.ack)
                if dup_ack != 0 and packet_recv.ack == dup_ack:
                    count_ack += 1
                else:
                    dup_ack = packet_recv.ack
                    count_ack = 1
                if count_ack == 3:
                    if len(self.data[packet_recv.ack - 1:]) > self.MSS:
                        packet = Segment(packet_recv.ack, self.next_ack_num, 'ACK'
                                         , self.MWS, self.data[packet_recv.ack - 1: packet_recv.ack + self.MSS - 1])
                    else:
                        packet = Segment(packet_recv.ack, self.next_ack_num, 'ACK'
                                         , self.MWS, self.data[packet_recv.ack - 1:])
                    sock.sendto(packet.segment, self.host)
                    self.num_seg += 1
                    self.num_ret_fast += 1
                    self.log([0,8], round(time.time() - self.s_time, 2), 'Data',
                            packet.seq, len(packet.data), packet.ack)
                    print('Send a fast retrans data seq, ack: ', packet.seq, packet.ack)
                    dup_ack = 0
                    count_ack = 0     

    def random(self, seed):
        random.seed = seed
        return random.random()

    def get_eRTT(self):
        alpha = 0.125
        self.Estimated_RTT = (1 - alpha) * self.Estimated_RTT + alpha * self.SampleRTT

    def get_devRTT(self):
        beta = 0.25
        self.DevRTT = (1 - beta) * self.DevRTT + beta * abs(self.SampleRTT - self.Estimated_RTT)

    def get_TimeoutInterval(self):
        self.TimeoutInterval = self.gamma * self.DevRTT + self.Estimated_RTT

    def readfile(self, filePath):
        with open(filePath, 'rb') as file:
            data = file.read()
        return data

    def log(self, *para):
        # parameters order is event, time, top, seq, nobd, ack
        event = ''
        if len(para) == 0:
            if os.path.exists(os.path.abspath('.') + '\\' + 'Sender_log.txt'):
                os.remove(os.path.abspath('.') + '\\' + 'Sender_log.txt')
            with open(os.path.abspath('.') + '\\' + 'Sender_log.txt', 'w') as file:
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
            with open(os.path.abspath('.') + '\\' + 'Sender_log.txt', 'a') as file:
                file.write(event + time + type_of_packet + seq + data_len + ack + '\n')
        elif len(para) == 11:
            with open(os.path.abspath('.') + '\\' + 'Sender_log.txt', 'a') as file:
                file.write(f'===========================================================\n')
                file.write(f'Size of the file (in Bytes):                          {para[0]}\n')
                file.write(f'Segments transmitted (including drop & RXT)           {para[1]}\n')
                file.write(f'Number of Segments handled by PLD                     {para[2]}\n')
                file.write(f'Number of Segments dropped                            {para[3]}\n')
                file.write(f'Number of Segments Corrupted                          {para[4]}\n')
                file.write(f'Number of Segments Re-ordered                         {para[5]}\n')
                file.write(f'Number of Segments Duplicated                         {para[6]}\n')
                file.write(f'Number of Segments Delayed                            {para[7]}\n')
                file.write(f'Number of Retransmissions due to TIMEOUT              {para[8]}\n')
                file.write(f'Number of FAST RETRANSMISSION                         {para[9]}\n')
                file.write(f'Number of DUP ACKS received                           {para[10]}\n')
                file.write(f'===========================================================\n')

    def func_timer(self):
        global stop_flag
        if not stop_flag:
            print('timeout!')
            if len(self.data[self.send_base - 1:]) > self.MSS:
                packet = Segment(self.send_base, self.next_ack_num, 'ACK'
                        , self.MWS, self.data[self.send_base - 1: self.send_base + self.MSS - 1])
            else:
                packet = Segment(self.send_base, self.next_ack_num, 'ACK'
                         , self.MWS, self.data[self.send_base - 1: ])
            sock.sendto(packet.segment, self.host)
            self.num_seg += 1
            self.num_ret_time += 1
            self.log([0,8], round(time.time() - self.s_time, 2), 'Data',
                    packet.seq, len(packet.data), packet.ack)
            #print('retransmited packet checksum: ', packet.checksum)
            #print(packet.segment)
            print(f'Send retransmited packet seq, ack, flag: {packet.seq}, {packet.ack}, {packet.flag}')
            # start a new timer
            if self.timer.isAlive():
                self.timer.cancel()
            self.timer = threading.Timer(self.TimeoutInterval, self.func_timer)
            self.timer.start()
            # restart timer

    def func_delay(self, data):
        sock.sendto(data, self.host)
        self.num_dely += 1
        self.num_seg += 1
        self.log([0,6], round(time.time() - self.s_time, 2), 'Data',
                packet.seq, len(packet.data), packet.ack)

    def PLDs(self, packet):
        # if there are some reordered packets
        self.num_pld += 1
        if self.reorder != []:
            for pack in self.reorder:
                pack[1] -= 1
                if pack[1] == 0:
                    sock.sendto(pack[0], self.host)
                    self.num_seg += 1
                    self.log([0,5], round(time.time() - self.s_time, 2), 'Data',
                        pack[0].seq, len(pack[0].data), pack[0].ack)
                    # do something
        event = ''
        if self.random(self.seed) < self.pDrop:
            event = 'drop'
        else:
            if self.random(self.seed) < self.pDuplicated:
                eventt = 'dup'
            else:
                if self.random(self.seed) < self.pCorrupt:
                    event = 'cor'
                else: 
                    if self.random(self.seed) < self.pOrder:
                        event = 'reorder'
                    else:
                        if self.random(self.seed) < self.pDelay:
                            event = 'delay'
                        else:
                            event = 'all good'
        if event == 'drop':
            self.num_drop += 1
            self.num_seg += 1
            self.log([2], round(time.time() - self.s_time, 2), 'Data',
                packet.seq, len(packet.data), packet.ack)
            self.next_seq_num += len(packet.data)
            return False
        if event == 'dup':
            self.num_dup += 1
            self.num_seg += 2
            sock.sendto(packet.segment, self.host)
            self.log([0,4], round(time.time() - self.s_time, 2), 'Data',
                packet.seq, len(packet.data), packet.ack)
            sock.sendto(packet.segment, self.host)
            self.log([0,4], round(time.time() - self.s_time, 2), 'Data',
                packet.seq, len(packet.data), packet.ack)
            return False
        if event == 'cor':
            self.num_cor += 1
            self.num_seg += 1
            packet.segment.replace('%', '#')
            sock.sendto(packet.segment, self.host)
            self.log([0,3], round(time.time() - self.s_time, 2), 'Data',
                packet.seq, len(packet.data), packet.ack)
            return False
        if event == 'reorder':
            self.num_reo += 1
            counter = self.maxOrder
            self.reorder.append([packet.segment, counter])
            return False
        if event == 'delay':
            self.num_dely += 1
            delay = threading.Timer(self.maxDelay / 1000, self.func_delay, [packet.segment])
            return
        if event == 'all good':
            return True
    
host_addr = sys.argv[1]
port = int(sys.argv[2])
sv = Server('localhost', port, sys.argv)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host = ('localhost', port)
stop_flag = False

sv.log()           # create a log file
sv.shakehand()
sv.run()
sv.stop()


sv.log(len(sv.data), sv.num_seg, sv.num_pld, sv.num_drop, sv.num_cor,
        sv.num_reo, sv.num_dup, sv.num_dely, sv.num_ret_time, sv.num_ret_fast, sv.num_ack_dup)
print('transmission complete!')
sock.close()
print('close socket!')


































