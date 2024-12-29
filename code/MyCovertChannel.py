from scapy.all import IP, UDP, DNS, DNSQR
from CovertChannelBase import CovertChannelBase
from scapy.all import sniff
import time


class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()

    def send(self, log_file_name, parameter1=None, parameter2=None):
        """
        This function is used for encoding the message. It gets the random binary message, and sends it to the encode_message function. After that, it iterates 
        over the result, sets the AD flag accordingly and sends the packet.
        """
        receiver_ip = parameter2

        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        needed_field_count = self.max_length(255, parameter1) # Holds how many fields will be used for the given parameter1
        bit_per_field = self.max_length(parameter1, 2) # Holds how many bits will be used for each field


        for x in range(0, len(binary_message), 8): # Goes char by char, hence step is 8 (8 bits)
            encoded_list = self.encode_message(needed_field_count, self.convert_to_base(int(binary_message[x:x+8],2), parameter1), bit_per_field) # Create the encoded message
            for bit in encoded_list: # Send encoded message bit by bit inside for loop
                time.sleep(0.05)  # Adjusting the delay
                packet = None
                if int(bit) == 1:
                    packet = IP(dst=receiver_ip) / UDP(dport=53) / DNS(rd=1, ad=1, qd=DNSQR(qname="example.com"))
                elif int(bit) == 0:
                    packet = IP(dst=receiver_ip) / UDP(dport=53) / DNS(rd=1, ad=0, qd=DNSQR(qname="example.com"))
                super().send(packet)


    def receive(self, parameter1=None, parameter2=None, parameter3=None, log_file_name=None):
        """
        This function receives the bits as the packets arrive. As the bits comes it stores them in the collected_bits variable. If length of collected_bits
        reaches the char_length, the algorithm decodes the content of the collected_bits, and equals to result to a variable last_character. Then it adds
        last_character to final_message. The reason there is a last_character variable is to control whether the "." is reached or not. After "." is reached,
        it logs the final message to log_file, and exits.
        """
        final_message = ''
        last_character = ''

        needed_field_count = self.max_length(255, parameter1) # Holds how many fields will be used for the given parameter1
        bit_per_field = self.max_length(parameter1, 2) # Holds how many bits will be used for each field
        char_length = needed_field_count*bit_per_field # Holds how many bits correspond to a char
        collected_bits = [] # Holds the received bits
        def process_packet(packet):
            nonlocal collected_bits
            nonlocal last_character
            nonlocal final_message
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                ad_flag = dns_layer.ad
                collected_bits.append(int(ad_flag))
                if len(collected_bits) == char_length: # When enough bits are received
                    last_character = chr(self.decode_message(needed_field_count, bit_per_field, collected_bits, parameter1)) # Decode the char and store it in last_character
                    collected_bits = []
                    final_message = final_message+last_character 
        while True:
            packets = sniff(filter="udp port 53", prn=process_packet, timeout=1, count=1)
            if last_character == '.':
                if log_file_name:
                    self.log_message(final_message, log_file_name)
                break




    def max_length(self, max_num_to_be_presented, parameter):
        """
        This function returns how many fields are required to represent max_num_to_be_presented in base parameter
        For example:
        max_num_to_be_presented = 255, parameter = 2
        return 8
        """
        count = 0
        while max_num_to_be_presented > 0:
            max_num_to_be_presented = max_num_to_be_presented // parameter
            count += 1
        return count

    def convert_to_base(self, num, parameter):
        """
        This function returns num representation in base parameter as a list
        For example:
        num =127 parameter=5
        return [1,0,0,2]
        """
        counts = []
        while num > 0:
            counts.append(num % parameter)
            num = num // parameter
        return counts[::-1]

    def write_num_in_binary(self, number, field_amount):
        """
        Returns the binary writing of number using field_amount length
        For example:
        number = 5, field_amount = 6
        return [0,0,0,1,0,1]
        """
        binary_list = []
        for i in range(field_amount-1, -1, -1):
            powered_value = pow(2, i)
            if number >= powered_value:
                number -= powered_value
                binary_list += [1]
            else:
                binary_list += [0]
        return binary_list


    def encode_message(self, amount_of_field, number_in_field, bit_per_field):
        """
        Returns the encoded message. Gets how many field (amount_of_field) there should be, each fields number (number_in_field) and how many bits will be used to represent each field (bit_per_field)
        """
        encoded_list = [0] * (amount_of_field-len(number_in_field))*bit_per_field
        for x in number_in_field:
            encoded_list += self.write_num_in_binary(x, bit_per_field)
        return encoded_list

    def get_value_of_base(self, encoded, base_k):
        """
        encoded represents a number that is written in base-base_k, this function returns the same number in base-10
        """
        count = 0
        result = 0
        for x in encoded[::-1]:
            result += x * pow(base_k, count)
            count += 1
        return result

    def decode_message(self, amount_of_field, bit_per_field, encoded, parameter):
        """
        Returns the decoded char value. Gets how many field (amount_of_field) there should be, how many bits will be used to represent each field (bit_per_field)
        encoded is the encoded message and we get the parameter
        """
        message_length = amount_of_field*bit_per_field
        result_list = []
        for x in range(0, message_length, bit_per_field):
           result_list.append(self.get_value_of_base(encoded[x:x+bit_per_field], 2))

        return self.get_value_of_base(result_list, parameter)