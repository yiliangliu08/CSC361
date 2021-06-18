"""
Name: Yiliang Liu
StudentID: V00869672
"""

import sys
import struct


class IP_Header:
    src_ip = None  # <type 'str'>
    dst_ip = None  # <type 'str'>
    ip_header_len = None  # <type 'int'>
    total_len = None  # <type 'int'>

    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0

    def ip_set(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def header_len_set(self, length):
        self.ip_header_len = length

    def total_len_set(self, length):
        self.total_len = length

    def get_IP(self, buffer1, buffer2):
        src_addr = struct.unpack('BBBB', buffer1)
        dst_addr = struct.unpack('BBBB', buffer2)
        s_ip = str(src_addr[0]) + '.' + str(src_addr[1]) + '.' + str(src_addr[2]) + '.' + str(src_addr[3])
        d_ip = str(dst_addr[0]) + '.' + str(dst_addr[1]) + '.' + str(dst_addr[2]) + '.' + str(dst_addr[3])
        self.ip_set(s_ip, d_ip)

    def get_header_len(self, value):
        result = struct.unpack('B', value)[0]
        length = (result & 15) * 4
        self.header_len_set(length)

    def get_total_len(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = (buffer[1] & 15)
        length = num1 + num2 + num3 + num4
        self.total_len_set(length)


class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size = 0
    checksum = 0
    ugp = 0

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size = 0
        self.checksum = 0
        self.ugp = 0

    def src_port_set(self, src):
        self.src_port = src

    def dst_port_set(self, dst):
        self.dst_port = dst

    def seq_num_set(self, seq):
        self.seq_num = seq

    def ack_num_set(self, ack):
        self.ack_num = ack

    def data_offset_set(self, data_offset):
        self.data_offset = data_offset

    def flags_set(self, ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin

    def win_size_set(self, size):
        self.window_size = size

    def get_src_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = (buffer[1] & 15)
        port = num1 + num2 + num3 + num4
        self.src_port_set(port)
        # print(self.src_port)
        return None

    def get_dst_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = (buffer[1] & 15)
        port = num1 + num2 + num3 + num4
        self.dst_port_set(port)
        # print(self.dst_port)
        return None

    def get_seq_num(self, buffer):
        seq = struct.unpack(">I", buffer)[0]
        self.seq_num_set(seq)
        # print(seq)
        return None

    def get_ack_num(self, buffer):
        ack = struct.unpack('>I', buffer)[0]
        self.ack_num_set(ack)
        return None

    def get_flags(self, buffer):
        value = struct.unpack("B", buffer)[0]
        fin = value & 1
        syn = (value & 2) >> 1
        rst = (value & 4) >> 2
        ack = (value & 16) >> 4
        self.flags_set(ack, rst, syn, fin)
        return None

    def get_window_size(self, buffer1, buffer2):
        buffer = buffer2 + buffer1
        size = struct.unpack('H', buffer)[0]
        self.win_size_set(size)
        return None

    def get_data_offset(self, buffer):
        value = struct.unpack("B", buffer)[0]
        length = ((value & 240) >> 4) * 4
        self.data_offset_set(length)
        # print(self.data_offset)
        return None

    def relative_seq_num(self, orig_num):
        if (self.seq_num >= orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        # print(self.seq_num)

    def relative_ack_num(self, orig_num):
        if (self.ack_num >= orig_num):
            relative_ack = self.ack_num - orig_num + 1
            self.ack_num_set(relative_ack)


class packet():
    # pcap_hd_info = None
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None

    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        # self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No = 0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None

    def timestamp_set(self, buffer1, buffer2, orig_time):
        seconds = struct.unpack('I', buffer1)[0]
        microseconds = struct.unpack('<I', buffer2)[0]
        self.timestamp = round(seconds + microseconds * 0.000001 - orig_time, 6)

        # print(self.timestamp,self.packet_No)

    def packet_No_set(self, number):
        self.packet_No = number
        # print(self.packet_No)

    def get_RTT_value(self, p):
        rtt = p.timestamp - self.timestamp
        self.RTT_value = round(rtt, 8)


class Connection:
    complete = False
    reset = False
    syn = 0
    fin = 0
    packs = {}
    sends = 0
    recvs = 0
    sendbytes = 0
    recvbytes = 0
    sumRtt = 0
    nRtt = 0


def run(filename):
    localip = None
    conns = {}  # localport -> [connections]
    conn = None
    orgTime = 0

    with open(filename, "rb") as f:
        try:
            f.read(24)  # skip 24 bytes of cap header
            while True:
                pack = packet()
                buffer1 = f.read(4)
                buffer2 = f.read(4)
                if len(buffer1) != 4 or len(buffer2) != 4:
                    break
                pack.timestamp_set(buffer1, buffer2, orgTime)
                if orgTime == 0:
                    orgTime = pack.timestamp
                    pack.timestamp_set(buffer1, buffer2, orgTime)
                buf = f.read(4)  # caplen
                caplen = struct.unpack("I", buf)[0]
                #                 print(caplen)
                f.read(4)  # len, skip

                f.read(14)  # Ethernet header 14 bytes skipped

                buf = f.read(1)  # version and header len
                pack.IP_header.get_header_len(buf)
                f.read(1)  # skip
                buf = f.read(2)  # total len
                pack.IP_header.get_total_len(buf)
                f.read(5)  # skip 5 bytes
                buf = f.read(1)
                protocol = struct.unpack("B", buf)[0]
                if (protocol != 6):
                    continue  # not a tcp pack
                f.read(2)  # skip 2 bytes
                buffer1 = f.read(4)  # src ip
                buffer2 = f.read(4)  # dest ip
                pack.IP_header.get_IP(buffer1, buffer2)
                f.read(pack.IP_header.ip_header_len - 20)  # skip other bytes in ip header if any

                if localip == None:
                    localip = pack.IP_header.src_ip

                buf = f.read(2)
                pack.TCP_header.get_src_port(buf)
                buf = f.read(2)
                pack.TCP_header.get_dst_port(buf)
                buf = f.read(4)
                pack.TCP_header.get_seq_num(buf)
                buf = f.read(4)
                pack.TCP_header.get_ack_num(buf)
                buf = f.read(1)  # header len
                tcpheadlen = struct.unpack("B", buf)[0]
                tcpheadlen = (tcpheadlen >> 4) * 4
                buf = f.read(1)  # flags
                pack.TCP_header.get_flags(buf)
                buffer1 = f.read(1)  # window size
                buffer2 = f.read(1)  # window size
                pack.TCP_header.get_window_size(buffer1, buffer2)

                f.read(caplen - 14 - pack.IP_header.ip_header_len - 16)  # skip other bytes in pack
                datalen = pack.IP_header.total_len - pack.IP_header.ip_header_len - tcpheadlen
                key = ''
                if pack.IP_header.src_ip == localip:
                    port = pack.TCP_header.src_port
                    key = '%s:%d-%s%d' % (
                    pack.IP_header.src_ip, pack.TCP_header.src_port, pack.IP_header.dst_ip, pack.TCP_header.dst_port)
                else:
                    port = pack.TCP_header.dst_port
                    key = '%s:%d-%s%d' % (
                    pack.IP_header.dst_ip, pack.TCP_header.dst_port, pack.IP_header.src_ip, pack.TCP_header.src_port)

                if key in conns:
                    conn = conns[key]
                else:
                    conn = Connection()
                    pack.packet_No_set(pack.TCP_header.seq_num)
                    conn.packs[pack.TCP_header.seq_num] = pack
                    conns[key] = conn

                    conn.src_ip = pack.IP_header.src_ip
                    conn.dst_ip = pack.IP_header.dst_ip
                    conn.src_port = pack.TCP_header.src_port
                    conn.dst_port = pack.TCP_header.dst_port
                    conn.start_time = pack.timestamp

                if pack.TCP_header.flags['ACK'] == 1:
                    seq = pack.TCP_header.ack_num - 1
                    if seq in conn.packs:
                        conn.packs[seq].get_RTT_value(pack)
                        conn.sumRtt += conn.packs[seq].RTT_value
                        conn.nRtt += 1

                if pack.TCP_header.flags['SYN'] == 1:
                    conn.syn += 1
                if pack.TCP_header.flags['FIN'] == 1:
                    conn.complete = True
                    conn.fin += 1
                if pack.TCP_header.flags['RST'] == 1:
                    conn.reset = True

                if pack.IP_header.src_ip == localip:
                    conn.sends += 1
                    conn.sendbytes += datalen
                else:
                    conn.recvs += 1
                    conn.recvbytes += datalen

                conn.end_time = pack.timestamp
        except EOFError:
            pass

    print("A) Total number of connections:", len(conns))
    print()
    print("B) Connections' details:")
    nConn = 1
    for conn in conns.values():
        print("Connection %d:" % nConn)
        nConn += 1
        print("Source Address:", conn.src_ip)
        print("Destination address:", conn.dst_ip)
        print("Source Port:", conn.src_port)
        print("Destination Port:", conn.dst_port)
        status = "S%dF%d" % (conn.syn, conn.fin)
        if conn.reset:
            status += " R"
        #             status = "R"
        print("Status:", status)
        # (Only if the connection is complete provide the following information)
        if conn.complete:
            print("Start time:", conn.start_time)
            print("End Time:", conn.end_time)
            print("Duration:", conn.end_time - conn.start_time)
            print("Number of packets sent from Source to Destination:", conn.sends)
            print("Number of packets sent from Destination to Source:", conn.recvs)
            print("Total number of packets:", conn.sends + conn.recvs)
            print("Number of data bytes sent from Source to Destination:", conn.sendbytes)
            print("Number of data bytes sent from Destination to Source:", conn.recvbytes)
            print("Total number of data bytes:", conn.sendbytes + conn.recvbytes)
        print("END")
        print()

    print("C) General")
    print("Total number of complete TCP connections:", len([x for x in conns.values() if x.complete]))
    print("Number of reset TCP connections:", len([x for x in conns.values() if x.reset]))
    print("Number of TCP connections that were still open when the trace capture ended:",
          len([x for x in conns.values() if not x.complete and not x.reset]))
    print()

    print("D) Complete TCP connections:")
    maxDu = None
    minDu = None
    sumDu = 0
    maxP = None
    minP = None
    sumP = 0
    maxW = None
    minW = None
    sumW = 0
    maxRtt = None
    minRtt = None
    sumRtt = 0
    N = 0
    for conn in conns.values():
        if conn.complete:
            duration = conn.end_time - conn.start_time
            window = sum([x.TCP_header.window_size for x in conn.packs.values()]) / len(conn.packs)
            packs = conn.sends + conn.recvs
            if conn.nRtt > 0:
                rtt = conn.sumRtt / conn.nRtt
            else:
                rtt = 0
            if N == 0:
                maxDu = minDu = duration
                maxP = minP = packs
                maxW = minW = window
                maxRtt = minRtt = rtt
            if duration > maxDu:
                maxDu = duration
            if duration < minDu:
                minDu = duration
            if packs > maxP:
                maxP = packs
            if packs < minP:
                minP = packs
            if window > maxW:
                maxW = window
            if window < minW:
                minW = window
            if rtt > maxRtt:
                maxRtt = rtt
            if rtt < minRtt:
                minRtt = rtt
            sumDu += duration
            sumP += packs
            sumW += window
            sumRtt += rtt
            N += 1

    print("Minimum time duration:", minDu)
    print("Mean time duration:", sumDu / N)
    print("Maximum time duration:", maxDu)
    print("Minimum RTT value:", minRtt)
    print("Mean RTT value:", sumRtt / N)
    print("Maximum RTT value:", maxRtt)
    print("Minimum number of packets including both send/received:", minP)
    print("Mean number of packets including both send/received:", sumP / N)
    print("Maximum number of packets including both send/received:", maxP)
    print("Minimum receive window size including both send/received:", minW)
    print("Mean receive window size including both send/received:", sumW / N)
    print("Maximum receive window size including both send/received:", maxW)


if __name__ == "__main__":
    run(sys.argv[1])

