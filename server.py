import argparse
from scapy.all import *
from base64 import b64decode

previous = None
outfile = None

def extract_data_from_query(packet):
    global previous
    if packet == previous:
        return
    previous = packet

    try:
        out = packet.qd.qname[:-1]
    except:
        out=b""
    out = base64.b64decode(out)
    print("Rcvd " + str(len(out)) + " bytes.")
    
    global outfile
    with open(outfile, "ab") as f:
        f.write(out)

def extract_data_from_payload(packet):
    global previous
    if packet == previous:
        return
    previous = packet

    try:
        out = packet.payload.load
    except:
        out=b""
    out = base64.b64decode(out)
    print("Rcvd " + str(len(out)) + " bytes.")
    
    global outfile
    with open(outfile, "ab") as f:
        f.write(out)


def listen_for_query(port):
    sniff(filter="udp port " + str(port), prn=extract_data_from_query)

def listen_for_payload(port):
    sniff(filter="udp port " + str(port), prn=extract_data_from_payload)


def main():
    parser = argparse.ArgumentParser("server")
    parser.add_argument("--outfile", "-o", help="Output file to write to.",
            type=str, default="output.txt")
    parser.add_argument("--port", "-p", help="Port to listen for traffic on.",
            type=int, default=53)
    parser.add_argument("--extract-from", "-e", help="What field to extract data from.",
            type=str, choices=["payload", "query"], default="query")
    args=parser.parse_args()
    
    global outfile
    outfile = args.outfile
    if args.extract_from == "query":
        listen_for_query(args.port)
    elif args.extract_from == "payload":
        listen_for_payload(args.port)

if __name__=="__main__":
    main()
