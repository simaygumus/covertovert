# Covert Storage Channel that exploits Protocol Field Manipulation using AD Flag field in DNS [Code: CSC-PSV-DNS-ADF]

## Introducing
This Covert Storage Channel Implementation uses AD (Authenticated Data) flag field in DNS [Code: CSC-PSV-DNS-ADF]. This flag is used for whether the data in the DNS response has been authenticated. It is a 1 bit field.
Our Covert Channel implementation manipulates this field for transferring information. It uses an encoding algorithm in the sender container, and decodes the incoming message in the receiver container. Due to AD flag is one bit field, it can send  at most one bit with one packet.

## Encoding Algorithm
This algorithm changes the base of the characters' ASCII values to parameter determined base. It gets one character, takes its ASCII value and  converts its base. It decides which base it is going to convert the message according to the parameter. Then, it writes each digit in binary. Due to the base changing operations, there are some restrictions on the parameter values:
- Parameter can't be less than or equal to 1 as writing a number in base 1, 0 or any negative value does not make sense.
- Parameter shouldn't be 2. It can be, it creates no errors, but encoded value is going to be the same as original message. This is because mod operation is based on the parameter, such as if parameter is 3, it encodes the number in base 3. A binary number, which is already encoded in base 2, will create same result when the parameter is 2.

Other than that, parameter can take any integer value. There are also some other information and restrictions:
- The second parameter in the sender function is used to store IP address of the receiver container.
- The parameter that is used to convert the base should be same for both of encoder and decoder. This parameter is the first parameter in both of the functions.


## Decoding Algorithm
This algorithm stores the incoming bits as the packets arrive. It uses parameter to calculate how many bits are required to store a converted base character. When the total number of stored bits are equal to the calculated value, it calculates each digit back to base k and then converts the number to base 10, and converts it to a char.
As the algorithm decodes the message, it stores chars to a string variable final_message. Also, it checks whether last character is "." or not. When the "." character is reached, it logs final_message to the log_file, and quits.

## Channel Capacity
Our algorithm sent 128 bits in 13.29 seconds. This means the channel capacity is equal to 9.25.



