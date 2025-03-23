# dnsResponseSniffer
a C program (running on Linux) that sniffs DNS response packets and prints the domain and IPs resolved for that domain to the terminal.


# installations
# pcap library installation (required)
sudo apt-get install libpcap-dev
# tcpdump (for testing purpose only)
sudo apt-get install tcpdump


# build
gcc dnsSniffer.c -o dnsSniffer -lpcap


# run
sudo ./dnsSniffer <interface>


# example:
#-----------------------------------------------------------------
sudo ./dnsSniffer lo

Start listening for DNS responses
Domain: google.com
        IPv6 Address: 2a00:1450:4028:80a:::200e

Domain: google.com
        IPv4 Address: 142.250.75.142
#-----------------------------------------------------------------

# in the above example we captured 2 responses, each including one answer only (one with IPv4 and one with IPv6)
# if both answers will arrive in one message the expected output is:
Domain: google.com
        IPv6 Address: 2a00:1450:4028:80a:::200e
        IPv4 Address: 142.250.75.142
#-----------------------------------------------------------------
