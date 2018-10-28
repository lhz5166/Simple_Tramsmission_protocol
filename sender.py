#!/usr/bin/python2
# -*- coding: utf-8 -*-

import pickle
import sys
import time
import random
import socket


class STPPacket:
    def __init__(self, data, seq_num, ack_num, ack=False, syn=False,
                 fin=False):
        self.data = data
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.ack = ack
        self.syn = syn
        self.fin = fin


class PLDModule:
    def __init__(self, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay,
                 maxDelay, seed):
        self.pDrop = int(pDrop)
        self.pDuplicate = int(pDuplicate)
        self.pCorrupt = int(pCorrupt)
        self.pOrder = int(pOrder)
        self.maxOrder = int(maxOrder)
        self.pDelay = int(pDelay)
        self.maxDelay = int(maxDelay)
        self.seed = int(seed)
        random.seed(seed)

    def simulate(self):
        if random.random() < self.pDrop:
            return "drop"
        elif random.random() < self.pDuplicate:
            return "dup"
        elif random.random() < self.pCorrupt:
            return "corr"
        elif random.random() < self.pOrder:
            return "rord"
        elif random.random() < self.pDelay:
            return "dely"
        return ""


class Sender:
    def __init__(self, receiver_host_ip, receiver_port, file, mws, mss, gamma,
                 pDrop, seed):
        self.receiver_host_ip = receiver_host_ip
        self.receiver_port = int(receiver_port)
        self.file = file
        self.mws = int(mws)  # max window size
        self.mss = int(mss)  # max segment size
        self.gamma = gamma
        self.pDrop = pDrop
        self.seed = int(seed)

    #socket create
    socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def stp_open(self):
        f = open(self.file, "r")
        data = f.read()
        return data

    def stp_rcv(self):
        data, addr = self.socket.recvfrom(2048)
        stp_packet = pickle.loads(data)
        return stp_packet

    def create_SYN(self, seq_num, ack_num):
        SYN = STPPacket('', seq_num, ack_num, ack=False, syn=True, fin=False)
        return SYN

    def create_ACK(self, seq_num, ack_num):
        ACK = STPPacket('', seq_num, ack_num, ack=True, syn=False, fin=False)
        return ACK

    def create_FIN(self, seq_num, ack_num):
        FIN = STPPacket('', seq_num, ack_num, ack=False, syn=False, fin=True)
        return FIN

    def udp_send(self, stp_packet):
        self.socket.sendto(
            pickle.dumps(stp_packet),
            (self.receiver_host_ip, self.receiver_port))

    def stp_close(self):
        self.socket.close()

    def retransmit(self, packet):
        self.socket.sendto(
            pickle.dumps(packet), (self.receiver_host_ip, self.receiver_port))
        sender.update_log("snd", 'D', packet)

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
        col_lens = [5, 8, 4, 5, 5, 3]
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
        f = open("sender_log.txt", "a+")
        f.write(final_str)
        f.close()

    def split_data(self, app_data, start):
        length = len(app_data)
        end = data_progress + self.mss
        if end < length:
            payload = app_data[start:end]
        else:
            payload = app_data[start:length]
        return payload


if len(sys.argv) != 15:
    print(
        "Usage: sender.py receiver_host_ip receiver_port file.txt mws mss gamma pDrop pDuplicate pCorrupt pOrder maxOrder pDelay maxDelay seed"
    )
else:
    seq_num = 0
    ack_num = 0
    sendbase = 0
    num_unacked = 0

    state_closed = True
    state_syn_sent = False
    state_timeout = False
    state_established = False
    state_end = False

    prev_state = None
    curr_packet = None
    prev_pkt = None

    num_handled = 0
    num_dropped = 0
    num_corrupted = 0
    num_reordered = 0
    num_duplicated = 0
    num_delayed = 0
    num_retransmitted = 0

    receiver_host_ip, receiver_port, file, mws, mss, gamma, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed = sys.argv[
        1:]

    curr_time = 0
    prev_time = 0
    gamma = gamma
    f = open("sender_log.txt", "w")
    f.close()

    print("Sender initiated . . .")
    sender = Sender(receiver_host_ip, receiver_port, file, mws, mss, gamma,
                    pDrop, seed)
    app_data = sender.stp_open()

    data_progress = 0
    data_len = len(app_data)
    print("LEN OF DATA = {}".format(data_len))

    pld = PLDModule(pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay,
                    maxDelay, seed)

    while True:
        ### CLOSED STATE ###
        # send SYN seg
        if state_closed == True:
            print("\n==STATE: CLOSED==")
            syn_pkt = sender.create_SYN(seq_num, ack_num)
            sender.udp_send(syn_pkt)
            sender.update_log("snd", 'S', syn_pkt)
            state_closed = False
            state_syn_sent = True

        ### SYN SENT STATE - WAIT FOR SYNACK ###
        # wait for SYNACK seg
        if state_syn_sent == True:
            print("\n==STATE: SYN SENT==")
            synack_pkt = sender.stp_rcv()
            # check if SYNACK
            if synack_pkt.ack == True and synack_pkt.syn == True:
                # acknowledge SYNACK, update log
                ack_num = synack_pkt.seq_num + 1
                sender.update_log("rcv", 'SA', synack_pkt)
                # send ACK
                seq_num += 1
                ack_pkt = sender.create_ACK(seq_num, ack_num)
                sender.udp_send(ack_pkt)
                sender.update_log("snd", 'A', ack_pkt)
                print("SYNACK received . . .")
                # 3-way-handshake complete
                state_established = True
                state_syn_sent = False

        ### ESTABLISHED STATE ###
        # send payload segments to receiver until whole file transferred
        if state_established == True:
            print("\n==STATE: CONNECTION ESTABLISHED==")
            # grab mss data, then create packet
            payload = sender.split_data(app_data, data_progress)
            packet = STPPacket(
                payload, seq_num, ack_num, ack=False, syn=False, fin=False)
            # time between last packet and this packet
            curr_time = time.clock() * 1000
            time_diff = curr_time - prev_time
            print("CURR TIME = {}".format(curr_time))
            print("PREV TIME = {}".format(prev_time))
            print("TIME DIFF = {}".format(time_diff))
            print("TIMEOUT = {}".format(gamma))
            # prev packet exists, timeout reached -> retransmit
            if prev_pkt != None and time_diff > gamma:
                print("==PACKET RETRANSMITTING==")
                prev_pkt = packet
                sender.retransmit(packet)
                num_unacked += 1
                seq_num += len(payload)
                num_retransmitted += 1
                prev_pkt = None
                continue

            bufferedPacket = []
            # import pdb
            # pdb.set_trace()
            # pass packet through PLDModule
            result = pld.simulate()

            if result == "drop":
                prev_time = time.clock() * 1000
                print("==PACKET DROPPED==")
                num_dropped += 1
                sender.update_log("drop", 'D', packet)
                sender.retransmit(packet)
                num_unacked += 1
                num_retransmitted += 1

            elif result == "dup":
                prev_time = time.clock() * 1000
                print("==PACKET DUPLICATED==")
                num_duplicated += 1
                sender.update_log("dup", 'D', packet)
                sender.retransmit(packet)
                num_unacked += 1
                num_retransmitted += 1
            elif result == "corr":
                prev_time = time.clock() * 1000
                print("==PACKET CORRUPTED==")
                sender.update_log("corr", 'D', packet)
                sender.udp_send(packet)
                num_unacked += 1
                num_corrupted += 1
            elif result == "rord":
                prev_time = time.clock() * 1000
                print("==PACKET ORDERED==")

                if bufferedPacket:
                    print("==ALREADY A SEGMENT WAITING==",
                          bufferedPacket[0].seq_num)
                    sender.update_log("rord", 'D', packet)
                    sender.udp_send(packet)
                    num_unacked += 1
                else:
                    print("==SAVING FOR REORDERING==", packet.seq_num)
                    bufferedPacket.append(packet)
                    num_reordered += 1

            elif result == "dely":
                prev_time = time.clock() * 1000
                print("==PACKET DROPPED==")
                time.sleep(random.uniform(0, maxDelay))
                sender.update_log("dely", 'D', packet)
                sender.udp_send(packet)
                num_unacked += 1
            else:
                print("==PACKET SENT SUCCESSFULLY==")
                sender.udp_send(packet)
                num_unacked += 1
                sender.update_log("snd", 'D', packet)

            num_handled += 1
            seq_num += len(payload)

            # TIMER = tracking the oldest unacknowledged segment
            if curr_time == 0:
                curr_time = time.clock() * 1000
                print("<<< TIMER STARTED = {} >>>".format(curr_time))
            # update data progress and seq_num
            data_progress += len(payload)
            # wait for RCV ack
            print("\n==== STATE: WAITING FOR ACK ===")
            ack_pkt = sender.stp_rcv()
            sender.update_log("rcv", 'A', ack_pkt)
            ack_num += len(ack_pkt.data)
            if state_end != True and ack_pkt.ack == True and ack_pkt.ack_num > sendbase:
                print("<<< ACK RECEIVED >>>")
                num_unacked -= 1
                sendbase = ack_pkt.ack_num
                if num_unacked == 0:
                    curr_time = time.clock() * 1000
            # whole file has been sent, begin close connection
            if data_progress == data_len:
                # send FIN
                fin_pkt = sender.create_FIN(seq_num, ack_num)
                sender.udp_send(fin_pkt)
                sender.update_log("snd", 'F', fin_pkt)
                state_end = True
                state_established = False

        ### END OF CONNECTION ###
        # wait for ACK
        if state_end == True:
            print("\n==STATE: END OF CONNECTION==")
            ack_pkt = sender.stp_rcv()  # ACK log combined with FIN below
            print("ACK IS: {}".format(ack_pkt.ack_num))
            print("SEQ IS: {}".format(ack_pkt.seq_num))
            # received ACK -> wait for FIN
            if ack_pkt.ack == True:
                fin_pkt = sender.stp_rcv()
                print("ACK IS: {}".format(fin_pkt.ack_num))
                print("SEQ IS: {}".format(fin_pkt.seq_num))
                sender.update_log("rcv", 'FA', fin_pkt)
                # received FIN -> send ACK + wait 30 seconds
                if fin_pkt.fin == True:
                    # acknowledge FINACK
                    ack_num += 1
                    # send ACK
                    ack_pkt = sender.create_ACK(seq_num, ack_num)
                    sender.udp_send(ack_pkt)
                    sender.update_log("snd", 'A', ack_pkt)
                    break

    sender.stp_close()
    print("\n==FINAL SENDER LOG==")
    f = open("sender_log.txt", "a+")
    data = "Data Transferred = {} bytes\n".format(data_len)
    seg_sent = "Segments Sent = {}\n".format(num_handled)
    pkt_dropped = "Packets Dropped = {}\n".format(num_dropped)
    pkt_corrupted = "Packets Corrupted = {}\n".format(num_corrupted)
    pkt_reordered = "Packets Re-Ordered = {}\n".format(num_reordered)
    pkt_duplicated = "Packets Duplicated = {}\n".format(num_duplicated)
    pkt_delayed = "Packets Delayed = {}\n".format(num_delayed)
    seg_retrans = "Segments Retrans = {}\n".format(num_retransmitted)
    ack_duplicate = "Duplicate Acks = N/A"
    final_str = "\n" + data + seg_sent + pkt_dropped + pkt_corrupted + pkt_reordered + pkt_duplicated + pkt_delayed + seg_retrans + ack_duplicate
    f.write(final_str)
    f.close()
    f = open("sender_log.txt", "r")
    print(f.read())
    f.close()