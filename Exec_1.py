from sage.all import *
####################################################################
# CONSTANT DEFINITIONS #############################################
####################################################################

MAX_NONCE = pow(10,  20)
MAX_TARGET = pow (2 , 128)
BTC_IMPORT = 25

INITIAL_BLOCK_HASH = "b482f2b7458c897489cb847936f4ef34"

LOG_LEVEL = 2  # 0 (do not print anything), 1 (print important stuff), 2 (debug - verbose mode)

####################################################################
# HELPER METHODS ###################################################
####################################################################

# IMPORTANT: DO NOT USE THESE GLOBAL VARIABLES IN YOUR IMPLEMENTATION
current_value = 0
random_values = []

def mod_exp(base, exponent, module):
    r = 1
    while (exponent > 0):
        if (exponent & 1) > 0:
            r = r * base % module
        exponent >>= 1
        base = (base * base) % module
    return r
# IMPORTANT: DO NOT USE THIS METHOD IN YOUR IMPLEMENTATION
def reset_Random_in_TestCase(values):
    global random_values, current_value
    current_value = 0
    random_values = []
    for v in values:
        random_values.append(v)


# Get a random integer between 0 and MAX_NONCE
def UOC_Random_int():
    global random_values, current_value
    if len(random_values) == 0:
        value = randint(0, MAX_NONCE)
        return value
    else:
        if current_value < len(random_values):
            value = random_values[current_value]
            current_value = current_value + 1
            return value
        else:
            print_level(2, "You've run out of random values in the test case.")
            return -1


def length_in_bits(number):
    binArray = number.digits(base=2)
    return len(binArray)


# Get a hex string with the MD5 sum of the message
def UOC_MD5(message):
    import hashlib
    m = hashlib.md5()
    m.update(message)
    return m.hexdigest()


# Convert a hex string to an integer value
def hexString_to_int(hexString):
    return int(hexString, base=16)


# Returns the string concatenation of the integers in list
def concatenate_ints_as_strings(list):
    return "".join(str(e) for e in list)


# Prints a message if LOG_LEVEL is higher than the specified level
def print_level(level, msg):
    if level < LOG_LEVEL:
        print msg


# Returns a pair of RSA public and private keys (keyLength is the key size in bits)
def UOC_RSA_KeyGenerate(keyLength):
    maxModulN = pow(2 , keyLength)
    r1 = randint(1, int(sqrt(maxModulN)))
    r2 = randint(maxModulN // (2 * r1), maxModulN // r1)

    p = next_prime(r1)
    bits = length_in_bits(p * r2)
    while bits != keyLength:
        if bits < keyLength:
            r2 = randint(r2, maxModulN // r1)
        else:
            r2 = randint(maxModulN // (2 * r1), r2)
        bits = length_in_bits(p * r2)

    q = next_prime(r2)
    n = p * q
    bits = length_in_bits(n)
    while bits != keyLength:
        if bits < keyLength:
            q = next_prime(q)
        else:
            q = previous_prime(q)
        n = p * q
        bits = length_in_bits(n)

    fi_n = (p - 1) * (q - 1)
    e = randint(fi_n // 2 - fi_n // 4, fi_n // 2 + fi_n // 4)
    while gcd(e, fi_n) != 1:
        e = e - 1
    d = inverse_mod(e, fi_n)

    return [[e, n], [d, n]]


####################################################################
# DATA STRUCTURES ##################################################
####################################################################

# RSA key structure
class rsa_public_key():
    def __init__(self):
        self.exponent = -1
        self.modulus = -1

    # Show public key content
    def print_me(self):
        print "RSA Public key"
        print "  exponent:", self.exponent
        print "  modulus:", self.modulus


# Transaction structure
class transaction_struct():
    def __init__(self):
        self.transaction_hash = -1
        self.address_source = -1
        self.source_public_key_info = rsa_public_key()
        self.address_destination = -1
        self.tximport = -1
        self.hash_previous_transaction = -1
        self.signature = -0x01

    # Show transaction content
    def print_me(self):
        print "Transaction"
        print "  transaction_hash:", self.transaction_hash
        print "  address_source:", self.address_source
        print "  source_public_key_info"
        print "    source_public_key_info.exponent:", self.source_public_key_info.exponent
        print "    source_public_key_info.modulus:", self.source_public_key_info.modulus
        print "  address_destination:", self.address_destination
        print "  import:", self.tximport
        print "  hash_previous_transaction:", self.hash_previous_transaction
        print "  signature:", self.signature

    # Returns a character string with the transaction information (used to obtain the transaction hash value)
    def get_hash_transaction(self):
        TransactionContent = [self.address_source, self.source_public_key_info.modulus,
                              self.source_public_key_info.exponent, self.address_destination, self.tximport,
                              self.hash_previous_transaction]
        return concatenate_ints_as_strings(TransactionContent)


# Block structure
class block_struct():
    def __init__(self):
        self.block_hash = -1
        self.previous_block_hash = -1
        self.target = -1
        self.bitcoin_gen_transaction = transaction_struct()
        self.transaction_list = []
        self.nonce = 0

    # Show block content
    def print_me(self):
        print "Block"
        print "  block_hash:", self.block_hash
        print "  previous_block_hash:", self.previous_block_hash
        print "  target:", self.target
        print "  bitcoin_gen_transaction:"
        self.bitcoin_gen_transaction.print_me()
        print "  transaction_list:"
        for tx in self.transaction_list:
            tx.print_me()
        print "  nonce:", self.nonce

    # Returns a character string with the block information (used to obtain the block hash value)
    def get_hash_block(self):
        BlockContent = [self.previous_block_hash, self.target, self.bitcoin_gen_transaction.transaction_hash,
                        self.nonce]
        for tx in self.transaction_list:
            BlockContent.append(tx.transaction_hash)
        return concatenate_ints_as_strings(BlockContent)


# Blockchain structure

BLOCK_CHAIN = []


def print_blockchain(blockchain):
    for block in BLOCK_CHAIN:
        block.print_me()


####################################################################
# BLOCK CHAIN INITIALIZATION #######################################
####################################################################

FIRST_TX = transaction_struct()
FIRST_TX.address_destination = "b7857e51c8c9894920ea8d4b1740e7df"
FIRST_TX.tximport = BTC_IMPORT
FIRST_TX.transaction_hash = "9ac7fc7d84387cbb748e32b733c66bb6"

FIRST_BLOCK = block_struct()
FIRST_BLOCK.target = MAX_TARGET
FIRST_BLOCK.bitcoin_gen_transaction = FIRST_TX
FIRST_BLOCK.block_hash = "b482f2b7458c897489cb847936f4ef34"

BLOCK_CHAIN.append(FIRST_BLOCK)


# EXERCISE 1.1: RSA Signature

# privKey: [d, n]
# message: positive integer.
# returns message ciphered using private key.
def UOC_RSA_Sign(privKey, message):
    result = 0

    #### IMPLEMENTATION GOES HERE ####
    privKey_d = privKey[0]
    privKey_n = privKey[1]
    result = mod_exp(message, privKey_d, privKey_n)

    ##################################

    return result


# EXERCISE 1.2: RSA Validation

# pubKey: [e, n]
# message: numeric value.
# signature: signature to be verified
# returns 1 for a successful validation or 0 otherwise.
def UOC_RSA_Verify(pubKey, message, signature):
    result = -1

    #### IMPLEMENTATION GOES HERE ####
    pubKey_e = pubKey[0]
    pubKey_n = pubKey[1]
    signature_check = mod_exp(signature, pubKey_e, pubKey_n)
    if message == signature_check:
        result = 1
    else:
        result = 0
    ##################################

    return result


# EXERCISE 2.1: Bitcoin payment

# priv_key: private key of the bitcoin account
# pub_key: public  key of the bitcoin account
# addr_dest: destination bitcoin address
# hash_output_payment: hash value of the previous transaction
# tx_import: transaction import
# returns a transaction structure.

def UOC_BitcoinPayment(privKey, pubKey, addr_dest, hash_previous_transaction, tximport):
    new_transaction = transaction_struct()

    #### IMPLEMENTATION GOES HERE ####




    ##################################

    return new_transaction


# EXERCISE 2.2: Bitcoin generation transaction validation (just for bitcoin_generation transactions)

# transaction: transaction structure to be validated
# returns 1 for a successful validation or 0 otherwise.

def UOC_GenTransactionValidation(transaction):
    result = -1

    #### IMPLEMENTATION GOES HERE ####




    ##################################

    return result


# EXERCISE 2.3: Bitcoin transaction validation (for non bitcoin_generation transactions)

# block_chain: total block chain
# transaction: transaction structure to be validated
# returns 1 for a successful validation or 0 otherwise.

def UOC_TransactionValidation(block_chain, transaction):
    result = -1

    #### IMPLEMENTATION GOES HERE ####




    ##################################

    return result


# EXERCISE 2.4: Bitcoin block validation

# block: block structure to be validated
# returns 1 for a successful validation or 0 otherwise.

def UOC_BlockValidation(block_chain, block):
    result = -1

    #### IMPLEMENTATION GOES HERE ####




    ##################################

    return result


# EXERCISE 2.5: Bitcoin block chain validation

# block_chain: block chain structure to be validated
# returns last block hash for a successful validation or 0 otherwise.

def UOC_BlockChainValidation(block_chain):
    result = -1

    #### IMPLEMENTATION GOES HERE ####




    ##################################

    return result


# EXERCISE 3.1: Create a new block

# previous_block_hash: hash of the previous block in the blockchain
# block_transactions: list of transactions in this block
# tximport: import of the generation transaction
# address: destination address of the generation transaction
# returns: filled block structure

def UOC_CreateNewBlock(previous_block_hash, block_transactions, tximport, address):
    new_block = block_struct()

    #### IMPLEMENTATION GOES HERE ####




    ##################################

    return new_block


# EXERCISE 3.2: Add a new block to the block chain

# block_chain: block chain structure where the block will be added
# block: new block to add to the blockchain
# target: current target value
# returns: modified block_chain with new block added

# WARNING: block_chain list object (param) is modified
# TIP: you must use UOC_Random_int to get the random values in the mining process (in order to pass the test case).

def UOC_AddBlock2Blockchain(block_chain, block, target):
    #### IMPLEMENTATION GOES HERE ####




    ##################################

    return block_chain


####################################################################################
# TEST CASES EXERCICES 1.1, 1.2, 1.3
####################################################################################

def test_case_10(name, bits, cleartext):
    keys = UOC_RSA_KeyGenerate(bits)
    pubKey = keys[0]
    privKey = keys[1]
    signature = UOC_RSA_Sign(privKey, cleartext)
    print "Test", name + ":", length_in_bits(pubKey[1]) == bits and UOC_RSA_Verify(pubKey, cleartext, signature) == 1


def test_case_11(name, privKey, cleartext, exp_signature):
    signature = UOC_RSA_Sign(privKey, cleartext)
    print "Test", name + ":", signature == exp_signature


def test_case_12(name, pubKey, cleartext, signature):
    print "Test", name + ":", UOC_RSA_Verify(pubKey, cleartext, signature) == 0


# Test 10.1
test_case_10("10.1", 32, 45895945)

# Test 10.2
test_case_10("10.2", 128, 342023893898440138943938999999000111)

# Test 10.3
test_case_10("10.3", 512, 3732897342893234283434)

# Test 10.4
test_case_10("10.4", 1024, 34938748349434897348735738387349734734973573973934873934798329743429734293287324973)

# Test 11.1
test_case_11("11.1", [3034881043, 4138330393], 273832, 3075857530)

# Test 11.2
test_case_11("11.2", [4412316596805245597, 12963823593191307527], 4839480984, 6179419487857580071)

# Test 11.3
test_case_11("11.3", [20544521463621334350029950173533361679, 269412303009555869708122562309933272289], 483948098485484,
             152672891023208240631146216192255047826)

# Test 11.4
test_case_11("11.4", [4388729340823325514099612479856921292056975620242725321415411390513468181953,
                      60627871672171357440091449688477172390359806109398530204432997090583086915023],
             738975947544785494784, 19756180345426843834849968056923459138508029701617903260852373475402489313459)

# Test 12.1
test_case_12("12.1", [2445121435, 4138330393], 273832, 3075057530)

# Test 12.2
test_case_12("12.2", [7466563220331159413, 12963823593191307527], 4839480984, 6179419487857500071)

# Test 12.3
test_case_12("12.3", [189444891036615105093797132823712938223, 269412303009555869708122562309933272289],
             483948098485484, 152672891023200240631146216192255047826)

# Test 12.4
test_case_12("12.4", [25777624522581365118424117875186079163589773818803072113175187067738623601737,
                      60627871672171357440091449688477172390359806109398530204432997090583086915023],
             738975947544785494784, 19756180345426843834849968056923459130508029701617903260852373475402489313459)
####################################################################################
# TEST CASES EXERCICES 2.2
####################################################################################

def test_case_20(name, transaction, exp_result):
    result = UOC_GenTransactionValidation(transaction)
    print "Test", name + ":", result == exp_result

# Ok
gen_transaction = transaction_struct()
gen_transaction.address_destination = "b7857e51c8c9894920ea8d4b1740e7df"
gen_transaction.tximport = BTC_IMPORT
gen_transaction.transaction_hash = "9ac7fc7d84387cbb748e32b733c66bb6"
test_case_20("20.1", gen_transaction, 1)

# Error: has source address
new_transaction = deepcopy(gen_transaction)
new_transaction.address_source = "e80a5186095312b79c2137114f9ad6ad"
new_transaction.transaction_hash = "a68d23498ee728ff365c24fd938cf734"
test_case_20("20.2", new_transaction, 0)

# Error: bad transaction hash
new_transaction.address_source = -1
test_case_20("20.3", new_transaction, 0)

# Error: bad import
new_transaction = deepcopy(gen_transaction)
new_transaction.tximport = 12
new_transaction.transaction_hash = "791d1ed02dd289de38af7294b0cecd21"
test_case_20("20.4", new_transaction, 0)

# Error: missing destination
new_transaction = deepcopy(gen_transaction)
new_transaction.address_destination = -1
new_transaction.transaction_hash = "166a0625686c345bb50deb1b5fca06d7"
test_case_20("20.5", new_transaction, 0)
####################################################################################
# TEST CASES EXERCICES 2.3
####################################################################################

def test_case_21(name, block_chain, transaction, exp_result):
    result = UOC_TransactionValidation(block_chain, transaction)
    print "Test", name + ":", result == exp_result

TEST_BLOCK_CHAIN = deepcopy(BLOCK_CHAIN)
hash_previous_transaction = "9ac7fc7d84387cbb748e32b733c66bb6"

# First block transaction keys
source_pubKey = [143215666995038625710871323573938500469, 434543060116374484113042052915150473283]
source_privKey = [303270606246917161111894863425056007389, 434543060116374484113042052915150473283]

# Destination
dest_pubKey = [287596291746952282592522248208111165, 664782059043916110559593144520118557]
dest_privKey = [297580611249569261840699295307367573, 664782059043916110559593144520118557]
addr_dest = UOC_MD5( concatenate_ints_as_strings( [dest_pubKey[0], dest_pubKey[1] ] ) )

# Create new transaction
TX1 = UOC_BitcoinPayment(source_privKey, source_pubKey, addr_dest, FIRST_TX.transaction_hash, BTC_IMPORT)

# Ok transaction
test_case_21("21.1", TEST_BLOCK_CHAIN, TX1, 1)

# Error: missing transaction hash
TEST_TX1 = deepcopy(TX1)
TEST_TX1.transaction_hash = -1
test_case_21("21.2", TEST_BLOCK_CHAIN, TEST_TX1, 0)

# Error: bad transaction hash
TEST_TX1 = deepcopy(TX1)
TEST_TX1.transaction_hash = "9ac7fc7d84387cbb748e32b733c66bb6"
test_case_21("21.3", TEST_BLOCK_CHAIN, TEST_TX1, 0)

# Error: previous transaction doesn't exist
TEST_TX1 = UOC_BitcoinPayment(source_privKey, source_pubKey, addr_dest, "00000000000000000000000000000000", BTC_IMPORT)
test_case_21("21.4", TEST_BLOCK_CHAIN, TEST_TX1, 0)

# Error: bad source address
[source_pubKey1, source_privKey1] = UOC_RSA_KeyGenerate(129)
TEST_TX1 = UOC_BitcoinPayment(source_privKey1, source_pubKey1, addr_dest, hash_previous_transaction, BTC_IMPORT)
test_case_21("21.5", TEST_BLOCK_CHAIN, TEST_TX1, 0)

# Error: bad signature
TEST_TX1 = deepcopy(TX1)
TEST_TX1.signature = TEST_TX1.signature + 1
test_case_21("21.6", TEST_BLOCK_CHAIN, TEST_TX1, 0)

# Error: bad transaction (ie. gen transactions don't validate)
TEST_TX1 = transaction_struct()
TEST_TX1.address_destination = "b7857e51c8c9894920ea8d4b1740e7df"
TEST_TX1.tximport = BTC_IMPORT
TEST_TX1.transaction_hash = "9ac7fc7d84387cbb748e32b733c66bb6"
test_case_21("21.7", TEST_BLOCK_CHAIN, TEST_TX1, 0)

# Error: double spending
TEST_TX1 = deepcopy(TX1)
keys0 = [[143215666995038625710871323573938500469, 434543060116374484113042052915150473283], [303270606246917161111894863425056007389, 434543060116374484113042052915150473283]]
addr2 = "97caa12c74b8d6e02fa94160537c09f5"

TX0 = transaction_struct()
TX0.address_destination = "e930cfd0f1fd3dd737379b1dbe883c6e"
TX0.tximport = BTC_IMPORT
TX0.transaction_hash = "53d123cb62196364eae433c91073a28d"

TX2 = UOC_BitcoinPayment(keys0[1], keys0[0], addr2, FIRST_TX.transaction_hash, BTC_IMPORT)

SECOND_BLOCK = block_struct()
SECOND_BLOCK.bitcoin_gen_transaction = TX0
SECOND_BLOCK.previous_block_hash = FIRST_BLOCK.block_hash
SECOND_BLOCK.target = MAX_TARGET
SECOND_BLOCK.transaction_list = [TX2]
SECOND_BLOCK.block_hash = "e76d68e73c2f10b3b56118542f130797"

TEST_BLOCK_CHAIN.append( SECOND_BLOCK )
test_case_21("21.8", TEST_BLOCK_CHAIN, TEST_TX1, 0)
####################################################################################
# TEST CASES EXERCICES 2.4
####################################################################################

def test_case_22(name, block_chain, block, exp_result):
    result = UOC_BlockValidation(block_chain, block)
    print "Test", name + ":", result == exp_result

TEST_BLOCK_CHAIN = deepcopy(BLOCK_CHAIN)

keys0 = [[143215666995038625710871323573938500469, 434543060116374484113042052915150473283], [303270606246917161111894863425056007389, 434543060116374484113042052915150473283]]
addr1 = "8e7e5601a8c13195fd314c3e01cf9fc5"
addr2 = "97caa12c74b8d6e02fa94160537c09f5"

TX0 = transaction_struct()
TX0.address_destination = "e930cfd0f1fd3dd737379b1dbe883c6e"
TX0.tximport = BTC_IMPORT
TX0.transaction_hash = "53d123cb62196364eae433c91073a28d"

TX1 = UOC_BitcoinPayment(keys0[1], keys0[0], addr1, FIRST_TX.transaction_hash, BTC_IMPORT)

BLOCK = block_struct()
BLOCK.bitcoin_gen_transaction = TX0
BLOCK.target = MAX_TARGET
BLOCK.transaction_list = [TX1]
BLOCK.block_hash = "b16e0ce9fcb7621ea74b42c73d54e10c"

# Ok block
test_case_22("22.1", TEST_BLOCK_CHAIN, BLOCK, 1)

# Error: invalid block hash
TEST_BLOCK = deepcopy(BLOCK)
TEST_BLOCK.target = TEST_BLOCK.target - 1
test_case_22("22.2", TEST_BLOCK_CHAIN, TEST_BLOCK, 0)

# Error: block's hash is greater than block's target
TEST_BLOCK.target = 0
TEST_BLOCK.block_hash = "6cf67d473690db2dcf7425563b529347"
test_case_22("22.3", TEST_BLOCK_CHAIN, TEST_BLOCK, 0)

# Error: invalid gen transaction
TEST_BLOCK = deepcopy(BLOCK)
TEST_BLOCK.target = MAX_TARGET
TEST_BLOCK.bitcoin_gen_transaction.tximport = BTC_IMPORT - 1
TEST_BLOCK.block_hash = "b16e0ce9fcb7621ea74b42c73d54e10c"
test_case_22("22.4", TEST_BLOCK_CHAIN, TEST_BLOCK, 0)

# Error: there is no generation transaction
TEST_BLOCK = deepcopy(BLOCK)
TEST_BLOCK.bitcoin_gen_transaction = transaction_struct()
TEST_BLOCK.block_hash = "d48d31676ec3a38efd9c8dc0bfe30638"
test_case_22("22.5", TEST_BLOCK_CHAIN, TEST_BLOCK, 0)

# Error: exists an invalid transaction
TEST_BLOCK = deepcopy(BLOCK)
TEST_BLOCK.target = MAX_TARGET
TEST_BLOCK.transaction_list[0].tximport = BTC_IMPORT - 1
TEST_BLOCK.block_hash = "b16e0ce9fcb7621ea74b42c73d54e10c"
test_case_22("22.6", TEST_BLOCK_CHAIN, TEST_BLOCK, 0)

# Error: double spending
TEST_BLOCK = deepcopy(BLOCK)
TX2 = UOC_BitcoinPayment(keys0[1], keys0[0], addr2, FIRST_TX.transaction_hash, BTC_IMPORT)
TEST_BLOCK.transaction_list.append(TX2)
TEST_BLOCK.block_hash = "ae6989d3ae312b86477328cfe9944271"
test_case_22("22.7", TEST_BLOCK_CHAIN, TEST_BLOCK, 0)
####################################################################################
# TEST CASES EXERCICES 2.5, 3.1, 3.2
####################################################################################

TEST_BLOC_CHAIN = deepcopy(BLOCK_CHAIN)

# Test 30.1
reset_Random_in_TestCase([26691370495166471133L, 80127129408747881516L, 98345797444211954986L])

gen_transac0_pubKey = [178019804268323973284035513448722069813, 368203688893838443970411372970907961033]
gen_transac0_privKey = [305078713808614619220610684751911540921, 368203688893838443970411372970907961033]
previous_block_hash = UOC_BlockChainValidation(TEST_BLOC_CHAIN)
block_transactions = []
gen_transac_address = "7439dbcb4b1c7b28b1f8fd3d612e61cf"
BK = UOC_CreateNewBlock(previous_block_hash, block_transactions, BTC_IMPORT, gen_transac_address)

target = MAX_TARGET/100
TEST_BLOC_CHAIN = UOC_AddBlock2Blockchain(TEST_BLOC_CHAIN, BK, target)

print "Test 30.1:", len(TEST_BLOC_CHAIN) == 2 and TEST_BLOC_CHAIN[0].block_hash == "b482f2b7458c897489cb847936f4ef34" and TEST_BLOC_CHAIN[1].block_hash == "0013b218d8530cee08154388cb562a99"

# Test 30.2
reset_Random_in_TestCase([64330930875704977197L, 60572445449872098483L, 37610299889502600756L, 16743175325893034553L, 87914491244582150435L, 94020913167681268118L, 58236869368545941960L, 71713381380400320411L, 41402759483052789815L, 91640045842830232985L, 37496445766506726781L, 68257513720313600678L, 94602350865439768749L, 62911582067704405585L, 86181397491286690176L, 78068553704472580939L, 48365136619550455273L])

gen_transac1_pubKey = [221601141111882573786952959886924471961L, 350171720124793489411434865737865485341]
gen_transac1_privKey = [347237979392376226191539049693055449641, 350171720124793489411434865737865485341]
[source1_pubKey, source1_privKey] = [gen_transac0_pubKey, gen_transac0_privKey]
dest1_pubKey = [206754035374233520163394689655901323839L, 466957194443490228175110689874552742357]
dest1_privKey = [361819436301061196395575749904586961519, 466957194443490228175110689874552742357]
addr_dest = "60204900e9b613ed76984e5934fbd3d5"
hash_previous_transaction = "ff68b859cd9fd3f28760d1fc3a63060e"

TX1 = UOC_BitcoinPayment(source1_privKey, source1_pubKey, addr_dest, hash_previous_transaction, BTC_IMPORT)
if UOC_TransactionValidation(TEST_BLOC_CHAIN, TX1) == 1:
    previous_block_hash = UOC_BlockChainValidation(TEST_BLOC_CHAIN)
    block_transactions = [TX1]
    gen_transac_address = "1aab81459a0807383d6ae0829fdb440a"
    target = MAX_TARGET/70
    BK = UOC_CreateNewBlock(previous_block_hash, block_transactions, BTC_IMPORT, gen_transac_address)
    TEST_BLOC_CHAIN = UOC_AddBlock2Blockchain(TEST_BLOC_CHAIN, BK, target)

print "Test 30.2:", len(TEST_BLOC_CHAIN) == 3 and TEST_BLOC_CHAIN[0].block_hash == "b482f2b7458c897489cb847936f4ef34" and TEST_BLOC_CHAIN[1].block_hash == "0013b218d8530cee08154388cb562a99" and TEST_BLOC_CHAIN[2].block_hash == "00f892ead0d10056a8663e98d00584d2"

# Test 30.3 (depends on Test 30.2)
if len(TEST_BLOC_CHAIN) == 3 and TEST_BLOC_CHAIN[2].block_hash == "00f892ead0d10056a8663e98d00584d2":
    BK = TEST_BLOC_CHAIN[len(TEST_BLOC_CHAIN) - 1]
    BK.previous_block_hash = "25"
    BK.target = MAX_TARGET
    BK.block_hash = "89b94944d2275acbdde51190b1a6a256"
    result = UOC_BlockChainValidation(TEST_BLOC_CHAIN)
    print "Test 30.3:", result == 0
else:
    print "Test 30.3: false"

# Test 30.4 (depends on Test 30.3)
if len(TEST_BLOC_CHAIN) == 3 and TEST_BLOC_CHAIN[2].block_hash == "89b94944d2275acbdde51190b1a6a256":
    BK = TEST_BLOC_CHAIN[len(TEST_BLOC_CHAIN) - 1]
    BK.previous_block_hash = previous_block_hash
    BK.target = 0
    BK.block_hash = "08ee70eec233605fb4be7919b9d3a765"
    result = UOC_BlockChainValidation(TEST_BLOC_CHAIN)
    print "Test 30.4:", result == 0
else:
    print "Test 30.4: false"