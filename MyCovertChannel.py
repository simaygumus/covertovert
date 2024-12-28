from scapy.all import IP, UDP, DNS, DNSQR
from CovertChannelBase import CovertChannelBase
from scapy.all import sniff
import time


class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()

    def decode_binary_message(self, binary_message):
        """
        Decodes a binary string into a human-readable message.
        """
        decoded_message = ""
        # Process the binary string in chunks of 8 bits
        for i in range(0, len(binary_message), 8):
            eight_bits = binary_message[i:i+8]
            # Convert each 8-bit chunk to a character
            decoded_message += self.convert_eight_bits_to_character(eight_bits)
        return decoded_message

    def send(self, log_file_name, parameter1=None, parameter2=None):
        """
        - Creates a DNS packet with the AD flag set to 0.
        - Sends the packet using the `send` method from CovertChannelBase.
        """
        # Craft the DNS packet
        receiver_ip = "receiver"  # Ensure a valid IP address
        parameter = 3

        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        message = self.decode_binary_message(binary_message)
        print(message)

        needed_field_count = self.max_length(255, parameter)
        bit_per_field = self.max_length(parameter,2)

        for x in range(0, len(binary_message), 8):
            encoded_list = self.encode_message(needed_field_count, self.convert_to_base(int(binary_message[x:x+8],2), parameter), bit_per_field)
            print(encoded_list)
            for bit in encoded_list:
                time.sleep(0.03)  # Adjust the delay as needed
                print(bit, end="", flush=True)
                packet = None
                if int(bit) == 1:
                    packet = IP(dst=receiver_ip) / UDP(dport=53) / DNS(rd=1, ad=1, qd=DNSQR(qname="example.com"))
                elif int(bit) == 0:
                    packet = IP(dst=receiver_ip) / UDP(dport=53) / DNS(rd=1, ad=0, qd=DNSQR(qname="example.com"))
                super().send(packet)


    def receive(self, parameter1=None, parameter2=None, parameter3=None, log_file_name=None):
        parameter = 3
        final_message = []
        last_character = ''

        needed_field_count = self.max_length(255, parameter)
        bit_per_field = self.max_length(parameter,2)
        char_length = needed_field_count*bit_per_field
        collected_bits = []
        def process_packet(packet):
            nonlocal collected_bits
            nonlocal last_character
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                ad_flag = dns_layer.ad
                collected_bits.append(int(ad_flag))
                if len(collected_bits) == char_length:
                    last_character = chr(self.decode_message(needed_field_count, bit_per_field, collected_bits, parameter))
                    print(last_character, end="", flush=True)
                    collected_bits = []
                    final_message.append(last_character)

                if log_file_name:
                    self.log_message(f"Received packet with AD flag = {ad_flag}", log_file_name)

        print("Listening for DNS packets...")

        while True:
            packets = sniff(filter="udp port 53", prn=process_packet, timeout=1, count=1)
            if last_character == '.':
                break




    def max_length(self, max_num_to_be_presented, parameter):
        max_num_to_be_presented
        count = 0
        while max_num_to_be_presented > 0:
            max_num_to_be_presented = max_num_to_be_presented // parameter
            count += 1
        return count

    def convert_to_base(self, num, parameter):
        counts = []
        while num > 0:
            counts.append(num % parameter)
            num = num // parameter
        return counts[::-1]

    def write_num_in_binary(self, number, each_index_long):
        encoded_list = []
        for i in range(each_index_long-1, -1, -1):
            powered_value = pow(2, i)
            if number >= powered_value:
                number -= powered_value
                encoded_list += [1]
            else:
                encoded_list += [0]
        return encoded_list


    def encode_message(self, length, counts_of_indexes, each_index_long):
        encoded_list = [0] * (length-len(counts_of_indexes))*each_index_long
        for x in counts_of_indexes:
            encoded_list += self.write_num_in_binary(x, each_index_long)
        return encoded_list

    def get_value_of_base(self, encoded,base):
        count = 0
        result = 0
        for x in encoded[::-1]:
            result += x * pow(base, count)
            count += 1
        return result

    def decode_message(self, needed_field_count, bit_per_field, encoded, parameter):
        message_length = needed_field_count*bit_per_field
        result_list = []
        for x in range(0, message_length, bit_per_field):
           result_list.append(self.get_value_of_base(encoded[x:x+bit_per_field], 2))

        return self.get_value_of_base(result_list,parameter)


