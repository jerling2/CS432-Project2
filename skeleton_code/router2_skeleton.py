import socket
import sys
import traceback
from threading import Thread


# Helper Functions

# TODO
# The purpose of this function is to set up a socket connection.
def create_socket(host, port):
    # 1. Create a socket.
    ## soc = ...
    # 2. Try connecting the socket to the host and port.
    try:
        ## ...
    except:
        print("Connection Error to", port)
        sys.exit()
    # 3. Return the connected socket.
    return soc

# TODO
# The purpose of this function is to read in a CSV file.
def read_csv(path):
    # 1. Open the file for reading.
    table_file = open(path, "r")
    # 2. Store each line.
    table = table_file.readlines()
    # 3. Create an empty list to store each processed row.
    table_list = []
    # 4. For each line in the file:
    ## for ...:
        # 5. split it by the delimiter,
        ## ...
        # 6. remove any leading or trailing spaces in each element, and
        ## ...
        # 7. append the resulting list to table_list.
        ## table_list.append(...)
    # 8. Close the file and return table_list.
    table_file.close()
    return table_list

# TODO
# The purpose of this function is to find the default port
# when no match is found in the forwarding table for a packet's destination IP.
def find_default_gateway(table):
    # 1. Traverse the table, row by row,
    ## for ...:
        # 2. and if the network destination of that row matches 0.0.0.0,
        ## if ...:
            # 3. then return the interface of that row.
            ## return ...

# TODO
# The purpose of this function is to generate a forwarding table that includes the IP range for a given interface.
# In other words, this table will help the router answer the question:
# Given this packet's destination IP, which interface (i.e., port) should I send it out on?
def generate_forwarding_table_with_range(table):
    # 1. Create an empty list to store the new forwarding table.
    new_table = []
    # 2. Traverse the old forwarding table, row by row,
    ## for ...:
        # 3. and process each network destination other than 0.0.0.0
        # (0.0.0.0 is only useful for finding the default port).
        ## if ...:
            # 4. Store the network destination and netmask.
            ## network_dst_string = ...
            ## netmask_string = ...
            # 5. Convert both strings into their binary representations.
            ## network_dst_bin = ...
            ## netmask_bin = ...
            # 6. Find the IP range.
            ## ip_range = ...
            # 7. Build the new row.
            ## new_row = ...
            # 8. Append the new row to new_table.
            ## new_table.append(new_row)
    # 9. Return new_table.
    return new_table

# TODO
# The purpose of this function is to convert a string IP to its binary representation.
def ip_to_bin(ip):
    # 1. Split the IP into octets.
    ## ip_octets = ...
    # 2. Create an empty string to store each binary octet.
    ip_bin_string = ""
    # 3. Traverse the IP, octet by octet,
    ## for ...:
        # 4. and convert the octet to an int,
        ## int_octet = ...
        # 5. convert the decimal int to binary,
        ## bin_octet = ...
        # 6. convert the binary to string and remove the "0b" at the beginning of the string,
        ## bin_octet_string = ...
        # 7. while the sting representation of the binary is not 8 chars long,
        # then add 0s to the beginning of the string until it is 8 chars long
        # (needs to be an octet because we're working with IP addresses).
        ## while ...:
            ## bin_octet_string = ...
        # 8. Finally, append the octet to ip_bin_string.
        ## ip_bin_string = ...
    # 9. Once the entire string version of the binary IP is created, convert it into an actual binary int.
    ## ip_int = ...
    # 10. Return the binary representation of this int.
    return bin(ip_int)


# TODO
# The purpose of this function is to find the range of IPs inside a given a destination IP address/subnet mask pair.
def find_ip_range(network_dst, netmask):
    # 1. Perform a bitwise AND on the network destination and netmask
    # to get the minimum IP address in the range.
    ## bitwise_and = ...
    # 2. Perform a bitwise NOT on the netmask
    # to get the number of total IPs in this range.
    # Because the built-in bitwise NOT or compliment operator (~) works with signed ints,
    # we need to create our own bitwise NOT operator for our unsigned int (a netmask).
    ## compliment = ...
    ## min_ip = ...
    # 3. Add the total number of IPs to the minimum IP
    # to get the maximum IP address in the range.
    ## max_ip = ...
    # 4. Return a list containing the minimum and maximum IP in the range.
    return [min_ip, max_ip]


# The purpose of this function is to perform a bitwise NOT on an unsigned integer.
def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n

# NOTE: this is unique to router 2 +
# The purpose of this function is to receive and process an incoming packet.
def receive_packet(connection, max_buffer_size):
    # 1. Receive the packet from the socket.
    ## received_packet = ...
    # 2. If the packet size is larger than the max_buffer_size, print a debugging message
    packet_size = sys.getsizeof(received_packet)
    if packet_size > max_buffer_size:
        print("The packet size is greater than expected", packet_size)
    # 3. Decode the packet and strip any trailing whitespace.
    ## decoded_packet = ...
    # 3. Append the packet to received_by_router_2.txt.
    print("received packet", decoded_packet)
    ## ...
    # 4. Split the packet by the delimiter.
    ## packet = ...
    # 5. Return the list representation of the packet.
    return packet


# TODO
# The purpose of this function is to write packets/payload to file.
def write_to_file(path, packet_to_write, send_to_router=None):
    # 1. Open the output file for appending.
    out_file = open(path, "a")
    # 2. If this router is not sending, then just append the packet to the output file.
    ## if ...:
        out_file.write(packet_to_write + "\n")
    # 3. Else if this router is sending, then append the intended recipient, along with the packet, to the output file.
    else:
        out_file.write(packet_to_write + " " + "to Router " + send_to_router + "\n")
    # 4. Close the output file.
    out_file.close()


# The purpose of this function is to
# (a) create a server socket,
# (b) listen on a specific port,
# (c) receive and process incoming packets,
# (d) forward them on, if needed.

# NOTE: This is unique to router 2+
def start_server():
    # 1. Create a socket.
    ## host = ...
    ## port = ...
    ## soc = ...
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket created")
    # 2. Try binding the socket to the appropriate host and receiving port (based on the network topology diagram).
    try:
        ## ...
    except:
        print("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()
    # 3. Set the socket to listen.
    ## ...
    print("Socket now listening")

    # 4. Read in and store the forwarding table.
    ## forwarding_table = ...
    # 5. Store the default gateway port.
    ## default_gateway_port = ...
    # 6. Generate a new forwarding table that includes the IP ranges for matching against destination IPS.
    ## forwarding_table_with_range = ...

    # 7. Continuously process incoming packets.
    while True:
        # 8. Accept the connection.
        ## connection, address = ...
        ## ip, port = ...
        print("Connected with " + ip + ":" + port)
        # 9. Start a new thread for receiving and processing the incoming packets.
        try:
            ## ...
        except:
            print("Thread did not start.")
            traceback.print_exc()

# NOTE: This is unique to router 2+
# The purpose of this function is to receive and process incoming packets.
def processing_thread(connection, ip, port, forwarding_table_with_range, default_gateway_port, max_buffer_size=5120):
    # 1. Connect to the appropriate sending ports (based on the network topology diagram).
    ## ...

    # 2. Continuously process incoming packets
    while True:
        # 3. Receive the incoming packet, process it, and store its list representation
        ## packet = ...

        # 4. If the packet is empty (Router 1 has finished sending all packets), break out of the processing loop
        ## if ...:
            break

        # 5. Store the source IP, destination IP, payload, and TTL.
        ## sourceIP = ...
        ## destinationIP = ...
        ## payload = ...
        ## ttl = ...

        # 6. Decrement the TTL by 1 and construct a new packet with the new TTL.
        ## new_ttl = ...
        ## new_packet = ...

        # 7. Convert the destination IP into an integer for comparison purposes.
        ## destinationIP_bin = ...
        ## destinationIP_int = ...

        # 8. Find the appropriate sending port to forward this new packet to.
        ## ...

        # 9. If no port is found, then set the sending port to the default port.
        ## ...

        # 11. Either
        # (a) send the new packet to the appropriate port (and append it to sent_by_router_2.txt),
        # (b) append the payload to out_router_2.txt without forwarding because this router is the last hop, or
        # (c) append the new packet to discarded_by_router_2.txt and do not forward the new packet
        ## if ...:
            print("sending packet", new_packet, "to Router 3")
            ## ...
        ## elif ...:
            print("sending packet", new_packet, "to Router 4")
            ## ...
        ## elif ...:
            print("OUT:", payload)
            ## ...
        else:
            print("DISCARD:", new_packet)
            ## ...


# Main Program

# 1. Start the server.
start_server()
