from scapy.all import *
import sys

def stipPr(name):
    if name.endswith("."):
        return name[:-1]  
    return name

def websiteName(pcap_filename, server_ip):
    processed_file = rdpcap(pcap_filename)

    dnsQr = {}
    dnsAns = {}

    for packet in processed_file:
        if packet.haslayer(DNSRR):
            if packet.qr == 0: 
                dnsQr[packet.qd.qname.decode()] = packet[IP].src
            elif packet.qr == 1: 
                siteName = stipPr(packet.qd.qname.decode())
                ip_address = packet.an.rdata

                if ip_address == server_ip:
                    dnsAns[siteName] = ip_address

    for website, ip in dnsAns.items():
        print(f"Website: http://{website}")

def measure(pcap_filename, server_ip, server_port):
    load_layer("http") 
    rqTime = None
    latencies = []
    packet_count = 0
    processed_file = rdpcap(pcap_filename)
    sessions = processed_file.sessions()

    for session in sessions:
        

        for packet in sessions[session]:
            if packet.haslayer(TCP) and packet.haslayer(IP):
                if packet[IP].dst == server_ip and packet[TCP].dport == server_port and packet.haslayer(HTTPRequest):
                    rqTime = packet.time
                    packet_count += 1

                if packet[IP].src == server_ip and packet[TCP].sport == server_port and packet.haslayer(HTTPResponse):
                    if rqTime:
                        responseTime = packet.time
                        latency = responseTime - rqTime
                        latencies.append(latency)
                        rqTime = None

    if latencies:
            
            avgLatency = sum(latencies) / len(latencies)
            sorted_latencies = sorted(latencies)
            total = len(sorted_latencies)

            percentile_25 = sorted_latencies[int(total * 0.25)]
            percentile_50 = sorted_latencies[int(total * 0.50)]
            percentile_75 = sorted_latencies[int(total * 0.75)]
            percentile_95 = sorted_latencies[int(total * 0.95)]
            percentile_99 = sorted_latencies[int(total * 0.99)]

            websiteName(pcap_filename,server_ip)
            print(f"Destination address: {server_ip}")
            print(f"Port number: {server_port}")
            print(f"AVERAGE LATENCY: {avgLatency:.5f}")
            print(f"PERCENTILES: {percentile_25:.5f} {percentile_50:.5f} {percentile_75:.5f} {percentile_95:.5f} {percentile_99:.5f}")

if __name__ == "__main__":
    pcap_filename = sys.argv[1]
    server_ip = sys.argv[2]
    server_port = int(sys.argv[3])

    measure(pcap_filename, server_ip, server_port)
