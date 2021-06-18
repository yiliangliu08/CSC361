"""
Name: Yiliang Liu
StudentID: V00869672
"""

import sys
import os
import TCPTrafficAnalysis as ta
import statistics

MF = 8192
FRAGOFF = 8191

protocols_table = {
    1 : "ICMP",
    6 : "TCP",
    17 : "UDP"
}

def isValid(protocol):
    if protocol == 1 or protocol == 17 or protocol == 6:
        return True
    else:
        return False

def analyse(filename):
    ta.run(filename)
    linux = False
    protocols = []
    sourceNode = ""
    destinationNode = ""
    destinationNodes = {}
    rtts = {}
    fragments = {}
    sends = {}
    packets={}
    for conn in ta.conns:
        #print(conn.ts)
        if isValid(conn.protocol):
            protocols.append(conn.protocol)
        if sourceNode == "" and conn.ttl == 1:
            if conn.protocol == 1:
                if conn.icmptype == 8:
                    sourceNode = conn.src_ip
                    destinationNode = conn.dst_ip
            else:
                linux = True
                sourceNode = conn.src_ip
                destinationNode = conn.dst_ip
        if sourceNode == "":
            continue
        if linux:
            if sourceNode == conn.src_ip:
                mf = bool(conn.off & MF)
                fragOff = conn.off & FRAGOFF
                if mf and fragOff == 0:
                    sends[(conn.ip.sport, conn.ip.dport)] = [(conn.ts, conn.ttl)]
                    packets[conn.ip.id] = (conn.ip.sport, conn.ip.dport)
                    fragments[conn.ip.id] = (1, 0)
                elif fragOff != 0:
                    sends[packets[conn.ip.id]].append((conn.ts,))
                    fragments[conn.ip.id] = (fragments[conn.ip.id][0] + 1, fragOff)
                else:
                    sends[(conn.ip.sport, conn.ip.dport)] = [(conn.ts, conn.ttl)]
            elif conn.protocol == 1:
                if conn.icmptype == 11:
                    destinationNodes[conn.src_ip] = sends[(conn.ip.icmpsport, conn.ip.icmpdport)][0][1]
                if not conn.src_ip in rtts:
                    rtts[conn.src_ip] = []
                #print("icmp src port",conn.ip.icmpsport)
                #print("icmp dst port",conn.ip.icmpdport)
                for fragment in sends[(conn.ip.icmpsport, conn.ip.icmpdport)]:
                    rtts[conn.src_ip].append(conn.ts - fragment[0])
        else:
            if conn.protocol == 1:
                if conn.icmptype == 8:
                    mf = bool(conn.off & MF)
                    fragOff = conn.off & FRAGOFF
                    if mf and fragOff == 0:
                        sends[conn.seq] = [(conn.ts, conn.ttl)]
                        packets[conn.ip.id] = conn.seq
                        fragments[conn.ip.id] = (1, 0)
                    elif fragOff != 0:
                        sends[packets[conn.ip.id]].append((conn.ts,))
                        fragments[conn.ip.id] = (fragments[conn.ip.id][0] + 1, fragOff)
                    else:
                        sends[conn.seq] = [(conn.ts, conn.ttl)]
                elif conn.dst_ip == sourceNode:
                    seq = 0
                    if conn.icmptype == 11:
                        seq = conn.ip.icmpseq
                        destinationNodes[conn.src_ip] = sends[seq][0][1]
                    if conn.icmptype == 0:
                        seq = conn.seq
                    if not conn.src_ip in rtts:
                        rtts[conn.src_ip] = []
                    for fragment in sends[seq]:
                        rtts[conn.src_ip].append(conn.ts - fragment[0])
                    

    print("The IP address of the source node: ", sourceNode)
    print("The IP address of ultimate destination node: ", destinationNode)
    print("The IP addresses of the intermediate destination nodes:")

    i = 1
    for node in sorted(((v,k) for k,v in destinationNodes.items())):
        if i != len(destinationNodes):
            print("    router " ,i,  ": " + node[1] + ",")
        else:
            print("    router " ,i , ": " + node[1] + ".")
        i = i + 1
    print()

    print("The values in the protocol field of IP headers: ")
    protocols.sort()
    for protocol in set(protocols): 
        print("     ", protocol,": ",protocols_table[protocol])
    
    print()
    if fragments:
        n = 1
        for ID, fragment in fragments.items():
            print("The number of fragments created from the original datagram id " + str(ID) + " is: " ,fragment[0])
            print("The offset of the last fragment is: " ,fragment[1] ,"\n")
            n = n + 1
    else:
        print("The number of fragments created from the original datagram is: 0")
        print("The offset of the last fragment is: 0\n")
    for item, rtt in rtts.items():
        if len(rtt) <= 1:
            print("The avg RTT between " + sourceNode + " and " + item + " is: %.2f ms, the s.d. is: 0 ms" % (sum(rtt) * 1000))
        else:
            print("The avg RTT between " + sourceNode + " and " + item + " is: %.2f ms, the s.d. is: %.2f ms" % (statistics.mean(rtt) * 1000, statistics.stdev(rtt) * 1000))
    for items, rtt in rtts.items():
        print(items, rtt)

if __name__ == "__main__":
    try:
        analyse(sys.argv[1])
    except FileNotFoundError:
        print("File \"%s\" not found." % sys.argv[1])
