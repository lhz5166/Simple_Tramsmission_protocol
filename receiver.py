#!/usr/bin/python2
# -*- coding: utf-8 -*-

import sys
import socket
import time
import pickle


class STPPacket:
    def __init__(self, data, seq_num, ack_num, ack=False, syn=False,
                 fin=False):
        self.data = data
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.ack = ack
        self.syn = syn
        self.fin = fin


class Receiver:
    def __init__(self, port, file):
        self.port = int(port)
        self.file = file

    socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def stp_rcv(self):
        data, client_addr = self.socket.recvfrom(2048)
        stp_packet = pickle.loads(data)
        return stp_packet, client_addr

    def append_payload(self, data):
        f = open(self.file, "a+")
        f.write(data)
        f.close()

    def create_SYNACK(self, seq_num, ack_num):
        SYNACK = STPPacket('', seq_num, ack_num, ack=True, syn=True, fin=False)
        return SYNACK

    def create_ACK(self, seq_num, ack_num):
        ACK = STPPacket('', seq_num, ack_num, ack=True, syn=False, fin=False)
        return ACK

    def create_FIN(self, seq_num, ack_num):
        FIN = STPPacket('', seq_num, ack_num, ack=False, syn=False, fin=True)
        return FIN

    def udp_send(self, packet, addr):
        self.socket.sendto(pickle.dumps(packet), addr)

    def stp_close(self):
        self.socket.close()

    def update_log(self, action, pkt_type, packet):
        seq = packet.seq_num
        ack = packet.ack_num
        size = len(packet.data)
        curr_time = time.clock()
        curr_time = curr_time * 1000
        curr_time = str(curr_time)
        seq = str(seq)
        size = str(size)
        ack = str(ack)
        col_lens = [5, 8, 4, 5, 5, 7]
        args = [action, curr_time, pkt_type, seq, size, ack]
        final_str = ""
        counter = 0
        for c in col_lens:
            arg_len = len(args[counter])
            space_len = c - arg_len
            space_str = ""
            while arg_len < c:
                space_str += " "
                arg_len += 1
            final_str += str(args[counter]) + space_str
            counter += 1
        final_str += "\n"
        print(final_str)
        f = open("receiver_log.txt", "a+")
        f.write(final_str)
        f.close()


if len(sys.argv) != 3:
    print("Usage: ./Receiver.py port log.txt")
else:
    seq_num = 0
    ack_num = 0
    next_seq_num = 0
    next_ack_num = 0
    client_addr = None
    state_listen = True
    state_syn_rcv = False
    state_synack_sent = False
    state_established = False
    state_end = False
    port, file = sys.argv[1:]
    receiver = Receiver(port, file)
    receiver.socket.bind(('', receiver.port))
    data_progress = 0
    pkt_buffer = {}
    f = open("receiver_log.txt", "w")
    f.close()
    f = open(file, "w")
    f.close()
    print("Receiver is ready . . .")

    while True:
        print("start of loop")

        ### LISTENING STATE ###
        # wait for SYN seg
        if state_listen == True:
            print("\n==STATE: LISTEN==")
            syn_pkt, client_addr = receiver.stp_rcv()
            receiver.update_log("rcv", 'S', syn_pkt)
            # acknowledge client SYN
            ack_num += 1
            # creating SYNACK
            if syn_pkt.syn == True:
                synack_pkt = receiver.create_SYNACK(seq_num, ack_num)
                receiver.udp_send(synack_pkt, client_addr)
                receiver.update_log("snd", 'SA', synack_pkt)
                # increment seq for SYNACK
                seq_num += 1
                state_synack_sent = True
                state_listen = False

        ### SYNACK SENT ###
        # wait for ACK seg
        if state_synack_sent == True:
            print("\n==STATE: SYNACK SENT==")
            ack_pkt, client_addr = receiver.stp_rcv()
            receiver.update_log("rcv", 'A', ack_pkt)

            # ACK received, 3-way-established
            if ack_pkt.ack == True:
                state_established = True
                state_synack_sent = False

        ### HANDSHAKE ESTABLISHED ###
        if state_established == True:
            print("\n==STATE: CONNECTION ESTABLISHED==")
            # grab packets until FIN close request by client
            while True:
                packet, client_addr = receiver.stp_rcv()
                ack_num += len(packet.data)
                data = packet.data
                print("SEQUENCE NUMBER   = {}".format(seq_num))
                print("ACKNOWLDGE NUMBER = {}".format(ack_num))
                print("RECEIVER SEQ NUM = {}".format(seq_num))
                # Receive FIN, init close
                if packet.fin == True:
                    print("FIN initiated by sender . . .")
                    receiver.update_log("rcv", 'F', packet)
                    state_end = True
                    state_established = False
                    break
                # Receive normal seg, check pkt_sn = rcv_sn
                # Send ACK for packet, increment seq_num by sizeof payload
                elif packet.seq_num == seq_num:
                    print("==PACKET OKAY, SEND ACK==")
                    # acknowledge seg, increment seq_num (indicate sizeof payload ack-ing)
                    ack_pkt = receiver.create_ACK(seq_num, ack_num)
                    receiver.udp_send(ack_pkt, client_addr)
                    receiver.update_log("snd", 'A', ack_pkt)
                    seq_num += len(packet.data)
                    # add payload to final file
                    data_progress += len(data)
                    receiver.append_payload(data)
                    receiver.update_log("rcv", 'D', packet)
                # Out of order packet, put in buffer
                else:
                    print("==OUT OF ORDER: ADD PACKET TO BUFFER==")
                    # add packet to buffer
                    #pkt_buffer[packet.seq_number] = packet

        ### END OF CONNECTION ###
        if state_end == True:
            print("\n==STATE: END OF CONNECTION== ")
            # acknowledge FIN
            ack_num += 1
            # send ACK + FIN consecutive
            ack_pkt = receiver.create_ACK(seq_num, ack_num)
            print("ACK IS: {}".format(ack_pkt.ack_num))
            print("SEQ IS: {}".format(ack_pkt.seq_num))
            receiver.udp_send(ack_pkt, client_addr)

            fin_pkt = receiver.create_FIN(seq_num, ack_num)
            print("ACK IS: {}".format(fin_pkt.ack_num))
            print("SEQ IS: {}".format(fin_pkt.seq_num))
            receiver.udp_send(fin_pkt, client_addr)
            receiver.update_log("snd", 'FA', fin_pkt)

            # wait for sender ACK
            ack_pkt, client_addr = receiver.stp_rcv()
            receiver.update_log("rcv", 'A', ack_pkt)
            # receive sender ack, close connection
            if ack_pkt.ack == True:
                receiver.stp_close()
                break

    # Print final file
    f = open(file, "r")
    print(f.read())

    # Print final receiver log
    f = open("receiver_log.txt", "r")
    print(f.read())