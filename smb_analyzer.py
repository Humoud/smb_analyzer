from scapy.all import *
import argparse
import iocextract

banner = """
SMB Analyzer V1.0\n
"""
print(banner)

parser = argparse.ArgumentParser(description='Extract SMB packets that contain a certain string from a pcap file')
parser.add_argument("-s", "--search", required=True, help = "string to search for (ex: http or mshta")
parser.add_argument("-i", "--input", required=True, help = "input pcap file name (ex: file.pcap)")
parser.add_argument("-o", "--output", default="analyzer_results", help = "output filename. if you provide 'results' as the value for this parameter, the script will output the results in 2 files: results.pcap and results.raw. Note that this script always appends to the output files, never over writes.")
parser.add_argument("-url-ioc", "--extract-url-iocs", default=False, help = "True or False, attempt to extract url based IOCs (uses IOCExtract). IOCs will be written to file output_file_name_provided.iocs")
args = parser.parse_args()

# read pcap
pkts = rdpcap(args.input)
counter = 0

#### output hits
# pcap and raw
pcap_output  = args.output+".pcap"
raw_output = args.output+".raw"
raw_file = open(raw_output, 'a')

def write(write_pkt, raw_data):
    wrpcap(pcap_output, write_pkt, append=True)
    raw_file.write(raw_data)

# Iterate through packets
for p in pkts:
    if TCP in p:
        # if source or dest port is 445
        if p[TCP].dport == 445 or p[TCP].sport == 445:
            # remove NULL bytes so that we can search for strings with ease
            arr_p = [x for x in str(p) if x != '\x00']
            string_p = ''.join(arr_p)
            if args.search in string_p.lower():
                write(p, string_p)
                counter += 1
                print("Hit: {}".format(counter))
raw_file.close()

# If ioc extraction is selected, attempt to do so
if args.extract_url_iocs:
    print("\nAttempting to extract URL based IOCs:")
    counter = 0
    iocs = []
    with open(raw_output) as f:
        content = f.readlines()
        for line in content:
            for url in iocextract.extract_urls(line):
                counter += 1
                iocs.append(url)
                print(url)
    print("Extracted {} IOCs (not unique)".format(counter))
    print("Writing IOCs to file analyzer.iocs...")
    with open( args.output+".ioc", 'w') as f:
        for item in iocs:
            f.write("{}\n".format(item))
print("Done!")
