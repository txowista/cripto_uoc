#########################################################################################
#
# CONSTANTS
#
# You can use these definitions in your implementation
#
#########################################################################################
from sage.all import *
import copy
from collections import namedtuple
GFBitType = GF(2)
o = GFBitType(0)
l = GFBitType(1)

BitType = Integers(2)
BIT0 = BitType(0)
BIT1 = BitType(1)

#########################################################################################
#
# STUDENT HELPERS
#
# You can create your own functions in this area
#
#########################################################################################
def create_input_myfare(input, index):
    output = []
    for i in range(index, index + 7, 2):
        output.append(input[i])
    return output
def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result
def frombits(bits):
    chars = []
    for b in range(len(bits) / 8):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)
# EXERCISE 1.1: Get LFSR's output sequence (use symbols o and l to define polinomial and initial_state vectors)

# Function UOC_LFSR_Sequence.
# * Parameter polynomial: vector of GFBitType
# * Parameter initial_state: vector of GFBitType
# * Parameter output_bits: positive number
# * Returns: vector of BitType
def UOC_LFSR_Sequence(polynomial, initial_state, output_bits):
    result = None
    #### IMPLEMENTATION GOES HERE ####
    result=[]
    for i in range(0,output_bits):
        result.append(int(initial_state[0]))
        xtemp = 0
        for x in range(len(polynomial)):
            if polynomial[x] == GFBitType(1):
                xtemp ^= int(initial_state[x])
        for j in range(1, len(initial_state)):
            initial_state[j-1] = initial_state[j]
        initial_state[len(initial_state)-1] = xtemp
    ##################################
    return result


# EXERCISE 1.2: Implement non-linear functions fA, fB and fC.

# Function UOC_Myfare_fA.
# * Parameter input: vector of BitType (size = 4)
# * Returns: BitType
def UOC_Myfare_fA(input):
    result = None
    #### IMPLEMENTATION GOES HERE ####
    sub_1 = input[0] | input[1]
    sub_2 = input[0] & input[3]
    sub_1 ^= sub_2
    sub_2 = input[0] ^ input[1]
    sub_2 |= input[3]
    sub_2 &= input[2]
    result = sub_1 ^ sub_2
    ##################################
    return result


# Function UOC_Myfare_fB.
# * Parameter input: vector of BitType (size = 4)
# * Returns: BitType
def UOC_Myfare_fB(input):
    result = None

    #### IMPLEMENTATION GOES HERE ####
    sub_1 = input[0] & input[1]
    sub_1 |= input[2]
    sub_2 = input[0] ^ input[1]
    sub_3 = input[2] | input[3]
    sub_2 &= sub_3
    result = sub_1 ^ sub_2
    ##################################
    return result


# Function UOC_Myfare_fC.
# * Parameter input: vector of BitType (size = 5)
# * Returns: BitType
def UOC_Myfare_fC(input):
    result = None

    #### IMPLEMENTATION GOES HERE ####
    sub_1 = input[1] | input[4]
    sub_2 = input[3] ^ input[4]
    sub_1 &= sub_2
    sub_1 |= input[0]
    sub_2 = input[1] & input[3]
    sub_2 ^= input[0]
    sub_3 = input[1] & input[4]
    sub_4 = input[2] ^ input[3]
    sub_3 |= sub_4
    sub_2 &= sub_3
    result = sub_1 ^ sub_2
    ##################################

    return result


# EXERCISE 1.3: Implement final non-linear filter function

# Function UOC_Myfare_NonLinearFilter.
# * Parameter input: vector of BitType (size = 48)
# * Returns: BitType
def UOC_Myfare_NonLinearFilter(input):
    result = None

    #### IMPLEMENTATION GOES HERE ####
    input_f = []
    input_f.append(UOC_Myfare_fA(create_input_myfare(input, 9)))
    input_f.append(UOC_Myfare_fB(create_input_myfare(input, 17)))
    input_f.append(UOC_Myfare_fB(create_input_myfare(input, 25)))
    input_f.append(UOC_Myfare_fA(create_input_myfare(input, 33)))
    input_f.append(UOC_Myfare_fB(create_input_myfare(input, 41)))
    result = UOC_Myfare_fC(input_f)
    ##################################

    return result


# EXERCISE 1.4: Implement Myfare random generator

# Function UOC_Myfare_PseudoRandomGenerator.
# * Parameter key: vector of BitType (size = 48)
# * Parameter output_bits: number
# * Returns: vector of BitType
def UOC_Myfare_PseudoRandomGenerator(key, output_bits):
    output = []

    #### IMPLEMENTATION GOES HERE ####
    # x 48 + x 43 + x 39 + x 38 + x 36 + x 34 + x 33 +
    # x 31 + x 29 + x 24 + x 23 + x 21 + x 19 + x 13 + x 9 + x 7 + x 6 + x 5 + 1
    polinomial = [l, o, o, o, o, l, o, o, o, l, l, o, l, o, l, l, o, l, o, l, o, o, o, o, l, l, o, l, o, l, o, o, o, o,
                  o, l, o, o, o, l, o, l, l, l, o, o, o, o]
    my_key = copy.copy(key)
    for i in range(0, output_bits):
        output.append(UOC_Myfare_NonLinearFilter(my_key))
        UOC_LFSR_Sequence(polinomial, my_key, 1)
    ##################################
    return output


# EXERCISE 1.5: Implement Myfare cipher/decipher

# Function UOC_Myfare_Cipher.
# * Parameter key: vector of BitType (size = 48)
# * Parameter mode: "e" (encipher), "d" (decipher)
# * Parameter message: String (encipher mode), Binary String (decipher mode)
# * Returns: Binary String (encipher mode), String (decipher mode)
def UOC_Myfare_Cipher(key, mode, message):
    result = ""
    ### IMPLEMENTATION GOES HERE ####
    if mode == 'e':
        my_message = tobits(message)
        one_time_pad = UOC_Myfare_PseudoRandomGenerator(key, len(my_message))
        for i in range(0, len(my_message)):
            result += str(my_message[i] ^ one_time_pad[i])
    if mode == 'd':
        my_message = list(message)
        one_time_pad = UOC_Myfare_PseudoRandomGenerator(key, len(my_message))
        for i in range(0, len(my_message)):
            result += str(int(my_message[i]) ^ one_time_pad[i])
        result = frombits(result)
    ##################################
    return result


# EXERCISE 2.1

# Function UOC_find_spaces_ciphertexts.
# * Parameter ciphertexts: list of hexadecimal strings with the ciphertextx
# * Returns: list of lists of ints (space positions for each ciphertext)
def UOC_find_spaces_ciphertexts(ciphertexts):
    spaces = []
    #### IMPLEMENTATION GOES HERE ####
    my_sizes = []
    for size in ciphertexts:
        my_sizes.append(len(size))
    my_sizes.sort(reverse=true)
    for i in range(0, len(ciphertexts)):
        spaces_temp = []
        for j in range(0, len(ciphertexts)):
            my_spaces = []
            if i != j:
                for k in range(0, min(len(ciphertexts[i]), len(ciphertexts[j])), 2):
                    temp = int(ciphertexts[i][k:k + 2], 16) ^ int(ciphertexts[j][k:k + 2], 16)
                    if 0x61 <= temp <= 0x7A or temp == 0:
                        my_spaces.append(k)
                if len(ciphertexts[i]) != len(ciphertexts[j]):
                    for n in range(min(len(ciphertexts[i]), len(ciphertexts[j])),
                                   len(ciphertexts[i]), 2):
                        if n < my_sizes[1]:
                            my_spaces.append(n)
                spaces_temp.append(my_spaces)
        for l in range(1, len(spaces_temp)):
            spaces_temp[0] = (sorted(list(set(spaces_temp[0]).intersection(spaces_temp[l]))))
        spaces.append(spaces_temp[0])
    #################################
    return spaces


# EXERCISE 2.2
# Function UOC_recover_key.
# * Parameter ciphertexts: list of hexadecimal strings with the ciphertextx
# * Returns: hexadecimal string with the recovered key
def UOC_recover_key(ciphertexts):
    key = ""

    #### IMPLEMENTATION GOES HERE ####



    ##################################

    return key


# EXERCISE 2.3
# Function UOC_recover_message.
# * Parameter ciphertexts: list of hexadecimal strings with the ciphertextx
# * Returns: ASCII string with the plaintext corresponding to the last ciphertext in ciphertexts
def UOC_recover_message(ciphertexts):
    last_plaintext = ""

    #### IMPLEMENTATION GOES HERE ####


    ##################################

    return last_plaintext


# EXERCISE 2.3 - Ciphertexts

# Ciphertexts obtained by ciphering with the same key

ciphertexts = [
    '282139B03D3A4D12AE4FDCCB27A486CAA99D01D17DB82288A0F47AFB6A7710C3EA9FF932D974392E1B9D7992CDE66EDFEC39C7A535E57B4B402273CAFF616DB56F37',
    '355635DF2B374712AB45CDBB4FA0EAC9CC9C06C009D73D8BD2F371FF181E13B1E198F934',
    '294829AB27245012A841DBCB3BA09FDDC18B74D00ED73A88A4F96D9A6D1904D4F798EB24DC6058381BFE6C8FDB830FDB833BC8A235EF7C3D483E79DDE91169B56C358C131AFBDE53B149BC0155EC2F01477C524EFEA7B3D6136E0A93B5A7105445',
    '354933AC483F5A12A259A8AF2AB283DDC7FF16C015B62284BDEE1FF4770360D0858EFD33C07F503807FE6E92D2ED0BC48D2CCFBA5CF463',
    '35493FDF3E375A66C04DC9A120B383CED0FF1BC37DA4318EA7EE76EE617706D0EC91ED22D07E39231D9D6D95BEE21AB69826C3D659E56C58495178DE907870AC6D35E1171AEBBF42BE40BD734589280F4375',
    '28475AB22B32467CA14CDBCB20A78CDFDB9A10A51CD7329FB7F91FF8711060DCE49E9839DB0D5C34169F7680DB8308D99E4EC7D651EE7B3D56307AC8FC741DA86935FE1774E8B143BB4BD31144EC3007447C4E20FAD5ABCA11660A82A5B275584D7E0D46',
    '2C4028A6483E4876C041A8A83DB89ACEC6FF1FC004D72785B79C74FF680360D8EBFDFD23D67F563B7E9F7683BEE618D39E37D2BE5CEE7D3D563972B8E37074B80124E41774F9BB52A42FA41653895C1D5F6B5820EFC8C4D4116D7D',
    '274828AC3C565D7AA559A8A82EAC8FBACF9006A509BF31EDBAFD7CF17D0513B1E788EC50DC0D5729089B6AE7DAEA0AB68D20DFA25DE9745A25387BD4F5767CB00127E5061C9FB34FD74CBC1E5199280B58',
    '2A4423DF3B355B7DB720DCA44FB39FD6CCFF00CD18BA548CBEF01FF17D0E60C2E68FF727B579564C18977683BEF706D3814ECDB34C807F4E462378CF906572DC6322E51C139FAA5EB242D3124D805C0F447D3D49F5A7B0D71A026E97BFBC1B5F5262',
    '324232BA2533297BB320CAAA3CA48EBAC69174D115B2548FBDF472E9180105C3F694F73EB5625F4C0AFE7D8ED0F01AD38520A6A65AE4755156227CC1906372AF643E']

# Ciphertext to decrypt:

target_ciphertext = "36445ABB21254A7DB645DAAE2BC199DFDB961BD00ED72388B3F771FF6B0405C28594F650C27D583809911886BEF31CD99821C5B959806E55442517CBF57268AE64238C1318F3DE5BB84BB6014FEC2C1C456D5843EFC2A0BF086B6C9F"

#### IMPLEMENTATION GOES HERE ####

##################################################################################
# TEST CASES EXERCICE 1.1: LFSR
####################################################################################

def test_case_10(name, polynomial, initial_state, output_bits, exp_result):
    result = UOC_LFSR_Sequence(polynomial, initial_state, output_bits)
    print "Test", name + ":", result == exp_result and len(result) == output_bits

exp_result = [1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1]
test_case_10("1.1", [l, l, o, o], [l, o, o, o], 20, exp_result)

exp_result = [0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1]
test_case_10("1.2", [l, o, l, l, o, o], [o, o, o, l, o, o], 20, exp_result)

exp_result = [0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1]
test_case_10("1.3", [l, l, l, o, o, l, o, o, o, o, o, o, o, o, o, o, o, o, o], [o, o, l, l, l, l, o, o, o, l, o, l, o, o, l, o, o, l, o], 30, exp_result)

exp_result = [0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0]
test_case_10("1.4", [l, o, l, o, l, o, o, o, o, o, o, o, o], [o, o, l, l, l, o, o, o, o, l, o, l, o], 30, exp_result)

exp_result = [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0]
test_case_10("1.5", [l, l, o, o, l, o, l, o], [l, o, o, o, o, o, o, o], 70, exp_result)

exp_result = [1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1]
test_case_10("1.6", [l, o, o, l, l, o, o, o], [l, l, o, o, l, l, o, o], 70, exp_result)

####################################################################################
# TEST CASES EXERCICE 1.2: MYFARE NON-LINEAR FUNCTIONS FA, FB AND FC
####################################################################################

def test_case_20(name, input, exp_result):
    result = UOC_Myfare_fA(input)
    print "Test", name + ":", result == exp_result

def test_case_21(name, input, exp_result):
    result = UOC_Myfare_fB(input)
    print "Test", name + ":", result == exp_result

def test_case_22(name, input, exp_result):
    result = UOC_Myfare_fC(input)
    print "Test", name + ":", result == exp_result

test_case_20("2.1.1", [1, 0, 0, 1], 0)
test_case_20("2.1.2", [1, 1, 1, 1], 1)
test_case_20("2.1.3", [0, 0, 0, 0], 0)
test_case_20("2.1.4", [0, 0, 1, 1], 1)
test_case_20("2.1.5", [0, 1, 0, 0], 1)

test_case_21("2.2.1", [1, 0, 0, 1], 1)
test_case_21("2.2.2", [1, 1, 1, 1], 1)
test_case_21("2.2.3", [0, 0, 0, 0], 0)
test_case_21("2.2.4", [0, 0, 1, 1], 1)
test_case_21("2.2.5", [0, 1, 0, 0], 0)

test_case_22("2.3.1", [1, 0, 0, 0, 1], 1)
test_case_22("2.3.2", [1, 1, 1, 1, 1], 1)
test_case_22("2.3.3", [0, 0, 0, 0, 0], 0)
test_case_22("2.3.4", [0, 0, 0, 1, 1], 0)
test_case_22("2.3.5", [0, 1, 0, 0, 0], 0)
test_case_22("2.3.6", [0, 1, 1, 0, 0], 0)
test_case_22("2.3.7", [0, 0, 1, 1, 0], 0)
test_case_22("2.3.8", [1, 1, 0, 1, 0], 1)

####################################################################################
# TEST CASES EXERCICE 1.3: MYFARE NON-LINEAR FUNCTION
####################################################################################

def test_case_30(name, input, exp_result):
    result = UOC_Myfare_NonLinearFilter(input)
    print "Test", name + ":", result == exp_result

test_case_30("3.1", [1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0], 1)
test_case_30("3.2", [0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0], 0)
test_case_30("3.3", [0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1], 0)
test_case_30("3.4", [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 1)
test_case_30("3.5", [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 0)
test_case_30("3.6", [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0)


####################################################################################
# TEST CASES EXERCICE 1.4: MYFARE PSEUDO RANDOM GENERATOR
####################################################################################

def test_case_40(name, key, output_bits, exp_result):
    result = UOC_Myfare_PseudoRandomGenerator(key, output_bits)
    print "Test", name + ":", result == exp_result


k4 = [0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
r4 = [0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0]

test_case_40("4.1", k4, 30, r4)

k4 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 1, 0, 0, 0]
r4 = [0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1,
      0, 1, 0, 1, 0, 0, 1]

test_case_40("4.2", k4, 45, r4)

k4 = [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 1, 0, 1]
r4 = [0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0,
      1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0]

test_case_40("4.3", k4, 53, r4)

k4 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
r4 = [0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1,
      1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0,
      1, 0, 0, 0]

test_case_40("4.4", k4, 80, r4)

k4 = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
r4 = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0,
      1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0,
      0, 0, 1, 0]

test_case_40("4.5", k4, 80, r4)

k4 = [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
r4 = [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0,
      1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1,
      0, 1, 1, 1]

test_case_40("4.6", k4, 80, r4)

k4 = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
      0, 1, 1, 1, 0, 0, 0, 0, 1, 1]
r4 = [1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1,
      0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0,
      1, 1, 1, 0]

test_case_40("4.7", k4, 80, r4)

k4 = [0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0,
      0, 0, 1, 1, 1, 0, 0, 1, 1, 0]
r4 = [0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0,
      1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1,
      0, 0, 1, 0]

test_case_40("4.8", k4, 80, r4)

k4 = [1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0,
      0, 1, 1, 0, 1, 1, 0, 0, 1, 0]
r4 = [1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0,
      0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0,
      0, 0, 1, 1]

test_case_40("4.9", k4, 80, r4)


####################################################################################
# TEST CASES EXERCICE 1.5: MYFARE CIPHER
####################################################################################

def test_case_50(name, key, message, exp_ciphered):
    ciphered = UOC_Myfare_Cipher(key, "e", message)
    print "Test", name + ":", str(ciphered) == exp_ciphered and ceil(len(ciphered) / 8) == len(message)


def test_case_51(name, key, message, exp_deciphered):
    deciphered = UOC_Myfare_Cipher(key, "d", message)
    print "Test", name + ":", deciphered == exp_deciphered and ceil(len(message) / 8) == len(deciphered)


def test_case_52(name, key, message, exp_ciphered):
    ciphered = UOC_Myfare_Cipher(key, "e", message)
    deciphered = UOC_Myfare_Cipher(key, "d", ciphered)
    print "Test", name + ":", str(ciphered) == exp_ciphered and deciphered == message and ceil(
        len(ciphered) / 8) == len(message)


k5 = [0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
exp_result = "000110100110011000111100001000000111110000111101111011001111011100110001101110111000110100001101"
test_case_50("5.1.1", k5, "Cryptography", exp_result)

k5 = [0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1,
      1, 0, 0, 0, 1, 0, 0, 0, 1, 1]
exp_result = "0110110010001000101110110100101011110001000011110000000001000110111110010111100000000101101000110001000101011011110011011001010011100000101111101000111101101101"
test_case_50("5.1.2", k5, "Safe cipher algoritm", exp_result)

k5 = [0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1,
      1, 0, 0, 1, 1, 0, 0, 0, 0, 1]
exp_result = "11100110100110001110101111110010111001011111111011011111111010001010110010011111110101001101101001000111100100001001100001010010101101111111111010010000110110110000010110011101110110010011011000110001110100000011011011000101"
test_case_50("5.1.3", k5, "RSA is a public key algoritm", exp_result)

k5 = [0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0,
      0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
exp_result = "the Huntsman ordered to take Snow White"
message = "001100010010110001100010111000001010010111110011010001100110111111101110111000101101101011111111000101010110011111111001010110000101000101111111110110110101001001011101010100100111010101110001100111101110101110101011101100101011110010110011100101000110010010000110110100111110100110010010000100100110001100111000"
test_case_51("5.2.1", k5, message, exp_result)

k5 = [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 1, 1, 1, 0, 1]
exp_result = "Once upon a time"
message = "01101110111110100000010101001110110110001111001010010101100110001100001010001001111101001101011110101111111010111010010110011110"
test_case_51("5.2.2", k5, message, exp_result)

k5 = [1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0,
      0, 0, 0, 0, 0, 1, 0, 1, 1, 1]
exp_result = "Triple DES cipher"
message = "0001000111110001011010000100010100101101011111000100001010111000000111110011010001101110011010100001111011011010000101101001001010111111"
test_case_51("5.2.3", k5, message, exp_result)

k5 = [0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
exp_result = "0010100101111011001010010010100101101111001000001110101011110101001110001010001010000110010101001001101100100101110100101001100010011000001001000011100111110000010000011001010001011100000011101011010101011000001100110110001001110110100001000110010110110110"
test_case_52("5.3.1", k5, "polygraphic substitution ciphers", exp_result)

k5 = [1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0,
      0, 0, 1, 1, 1, 0, 0, 0, 0, 1]
exp_result = "111100000101010100000011010010011101001000010001000010010110111010011101010010101111000000101100001111000011001001010011000100111101101101010011000101110000001101010000101100110010000011011111101100010011101011111000101010011001101001110010010010111000011010111010"
test_case_52("5.3.2", k5, "susceptible to frequency analysis", exp_result)

k5 = [1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0,
      0, 0, 1, 0, 1, 0, 1, 0, 1, 1]
exp_result = "0000111111110001110001111010100100101110011101010011001101101101010100000010001111001100001110000100011111000101110011100100001011011100100101110011100011011000011111011101011101010111"
test_case_52("5.3.3", k5, "Certification authority", exp_result)

####################################################################################
# TEST CASES EXERCICE 2.1
####################################################################################

def test_case_6(name, ciphertexts, exp):
    spaces = UOC_find_spaces_ciphertexts(ciphertexts)
    print "Test", name + ":", exp == spaces

ciphertexts =  ['0517119A', '01131596', '0D7519FE']
exp_spaces = [[], [], [2, 6]]
test_case_6("6.1", ciphertexts, exp_spaces)

ciphertexts =  ['6417119A4113DAC1', '0D757292491BD2D9', '150701FE']
exp_spaces = [[0], [2, 4], [6]]
test_case_6("6.2", ciphertexts, exp_spaces)

ciphertexts = ['1310728D5014D3CD03F1484ABB417B7CC1036DCA54B18C07F85AEE8A2FFC3B531B3A6DE0CBE9F3CDE7EF79C509A8E772F234EBDA2358936A86989C', '101D17FE4010CBCC6FEA5743BF560F13C06519C159D48F059150ECED29EE5A5E1B2069E4C0F2E7CBEB807FA413C68163E528FFAE254BE16D849F88', '101D17FE4010CEC06DE22742B3551267CE7770CD5FC2EE1AF734E8EF23F25A5C722B69FAA4E6E9D4FEF563AC0EA1E770EE299BCC3E50946C9EF091122FD826D57BCCE9BBFF5132C43C08215110DDC2D646B9C17A02808E7A1A1C0120E3C2', '001004974710CEA967EA5040DA4C1413D86B7CD054B19A1DF44D85E921F43B507E487DE5C1E186D0E08064B003AEE772EF20F6CB3E5C886A9AF0840A3AB42CD969CC80BBF7225ACC286053530FD3D2B325BBC06B7290886E18181F3BEFD3DE', '051B16FE471AD0D976F1425CDA4C1E61C26A77C35DC2EE01F95185EE25EC5E5E743865F3CAF186D6E88074AA0DB69265E53F9BCD23519579999C801E4ABB2AD765CD87BDFA302EC4340E52360CD9D2C429A8D873009B8C741B1802']
exp_spaces =  [[4, 16, 28, 34, 42, 54, 60, 64, 86, 92], [6, 30, 36, 48, 64, 82, 90, 102, 108], [6, 20, 44, 50, 72, 92, 100, 114, 122, 132, 138, 148, 160], [14, 24, 30, 42, 52, 60, 66, 76, 82, 92, 114, 140, 146, 158, 168], [6, 24, 44, 52, 76, 82, 100, 120, 150]]

# [6, 20, 44, 50, 72, 92, 100, 114, 122, 132, 138, 148, 160]

# [14, 24, 30, 42, 52, 60, 66, 76, 82, 92, 114, 140, 146, 158, 168]

# [6, 24, 44, 52, 76, 82, 100, 120, 150]]


test_case_6("6.3", ciphertexts, exp_spaces)


# Additional information to debug: key used to cipher and plaintexts:
plaintexts = ["WE STAND TODAY ON THE BRINK OF A REVOLUTION IN CRYPTOGRAPHY", "THE DEVELOPMENT OF CHEAP DIGITAL HARDWARE HAS FREED IT FROM", "THE DESING LIMITATIONS OF MECHANICAL COMPUTING AND BROUGH THE COST OF HIGH GRADE CRYPTOGRAPHIC",
"DEVICES DOWN TO WHERE THEY CAN BE USED IN SUCH COMMERCIAL APPLICATIONS AS REMOT CASH DISPENSERS", "AND COMPUTER TERMINALS THE DEVELOPMENT OF COMPUTER CONTROLED COMMUNICATIONS NETWORKPROMISES"]
key = [0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0]


####################################################################################
# TEST CASES EXERCICE 2.2
####################################################################################

def test_case_7(name, ciphertexts, exp):
    key = UOC_recover_key(ciphertexts)
    mylen = len(exp)
    if len(key) >= mylen:
        print "Test", name + ":", exp == key[:mylen]
    else:
        print "Test", name + ":", False


ciphertexts = ['0517119A', '01131596', '0D7519FE']
exp_key = "??55??DE"
test_case_7("7.1", ciphertexts, exp_key)

ciphertexts = ['6417119A4113DAC1', '0D757292491BD2D9', '150701FE']
exp_key = "445552DE"
test_case_7("7.2", ciphertexts, exp_key)

ciphertexts = [
    '1310728D5014D3CD03F1484ABB417B7CC1036DCA54B18C07F85AEE8A2FFC3B531B3A6DE0CBE9F3CDE7EF79C509A8E772F234EBDA2358936A86989C',
    '101D17FE4010CBCC6FEA5743BF560F13C06519C159D48F059150ECED29EE5A5E1B2069E4C0F2E7CBEB807FA413C68163E528FFAE254BE16D849F88',
    '101D17FE4010CEC06DE22742B3551267CE7770CD5FC2EE1AF734E8EF23F25A5C722B69FAA4E6E9D4FEF563AC0EA1E770EE299BCC3E50946C9EF091122FD826D57BCCE9BBFF5132C43C08215110DDC2D646B9C17A02808E7A1A1C0120E3C2',
    '001004974710CEA967EA5040DA4C1413D86B7CD054B19A1DF44D85E921F43B507E487DE5C1E186D0E08064B003AEE772EF20F6CB3E5C886A9AF0840A3AB42CD969CC80BBF7225ACC286053530FD3D2B325BBC06B7290886E18181F3BEFD3DE',
    '051B16FE471AD0D976F1425CDA4C1E61C26A77C35DC2EE01F95185EE25EC5E5E743865F3CAF186D6E88074AA0DB69265E53F9BCD23519579999C801E4ABB2AD765CD87BDFA302EC4340E52360CD9D2C429A8D873009B8C741B1802']
exp_key = "????52DE??????8923??07??FA??5B33??2339????91CE??B114A5AA????1B??3B68????84??A6????A0??E5??E6C7??????BB8E????C1????D0????6AF8????????C9????717A????400116??????9366??????52"
test_case_7("7.3", ciphertexts, exp_key)