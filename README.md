# smb_analyzer
Extract SMB packets that contain a certain string from a pcap file.

### Requirements:
  1. Python 2, i did try to make the code compatible with Python 3, however i am not sure if the two libraries below support python 3.
  2. https://github.com/secdev/scapy
      * `pip install scapy`
  3. https://github.com/InQuest/python-iocextract
      * `sudo apt-get install python-dev`
      * `pip install iocextract`
 
### Usage:
Help command output:
```bash
user6@onion-sweet01:~/Documents/scripts$ python smb_analyzer.py -h
SMB Analyzer V1.0


usage: smb_analyzer.py [-h] -s SEARCH -i INPUT [-o OUTPUT]
                       [-url-ioc EXTRACT_URL_IOCS]

Extract SMB packets that contain a certain string from a pcap file

optional arguments:
  -h, --help            show this help message and exit
  -s SEARCH, --search SEARCH
                        string to search for (ex: http or mshta
  -i INPUT, --input INPUT
                        input pcap file name (ex: file.pcap)
  -o OUTPUT, --output OUTPUT
                        output filename. if you provide 'results' as the value
                        for this parameter, the script will output the results
                        in 2 files: results.pcap and results.raw. Note that
                        this script always appends to the output files, never
                        over writes.
  -url-ioc EXTRACT_URL_IOCS, --extract-url-iocs EXTRACT_URL_IOCS
                        True or False, attempt to extract url based IOCs (uses
                        IOCExtract). IOCs will be written to file
                        output_file_name_provided.iocs
```

Let's assume we have a pcap file "file.pcap" and we want to get all SMB packets that contain the string "mshta".
This can be accomplished by using the following parameters:
```
user6@onion-sweet01:~/Documents/scripts$ python smb_analyzer.py -i file.pcap -o testrun -s mshta
SMB Analyzer V1.0


Hit: 1
Done!
```
Note that the results will be written to files: testrun.raw and testrun.pcap.

Now, in case you need extract URL based IOCs after the search for the string you have provided is completed, that can by done by passing `True` to the `url-ioc` switch. By default the `url-ioc` is set to `False`. Example:
```
user6@onion-sweet01:~/Documents/scripts$ python smb_analyzer.py -i file.pcap -o testrun -s mshta -url-ioc True
SMB Analyzer V1.0


Hit: 1

Attempting to extract URL based IOCs:
Hxxp[:]//Es[.]ldbdhm[.]Xyz/SMB1P[.]jpg /Q)",0)(window.close
Extracted 1 IOCs (not unique)
Writing IOCs to file testrun.iocs...
Done!
```

Keep in mind that the script does not sanitize the URLs, I have done that manually for this example. (The URL is a malicious link, for real)
