import socket
import rsa

inverntory_list = {'ProductX': "53.9", "ProductY": "45.9", "ProductZ": "34.9", "ProductA": "78.9", "ProductB": "12.9", "ProductC": "90.9", "ProductD": "67.67", "ProductE": "53.9", "ProductF": "10.25", "ProductG": "56.9"}
product_string = ""
for product in inverntory_list:
    product_string += product + " "
def public_private_keys():
    public_key, private_key = rsa.newkeys(1024)
    with open("merhcant_public.pem", "wb") as f:
        f.write(public_key.save_pkcs1("PEM"))
    return public_key, private_key


def broker_merchant_authentication(brokersocket, public_key):
    challenge_1 = input("Enter challenge: ")
    encrypt_challenge_1 = rsa.encrypt(challenge_1.encode(), public_key)
    brokersocket.send(encrypt_challenge_1)
    return challenge_1


def decrypt(message, private_key):
    clear_message = rsa.decrypt(message, private_key)
    return clear_message

str_dict = {'a': "101", 'b': "102", 'c': "103", 'd': "104", 'e': "105", 'f': "106", 'g': "107", 'h': "108",
            'i': "109", 'j': "110", 'k': "111", 'l': "112", 'm': "113", 'n': "114", 'o': "115", 'p': "116",
            'q': "117", 'r': "118", 's': "119", 't': "120", 'u': "121", 'v': "122", 'w': "123", 'x': "124",
            'y': "125", 'z': "126", " ": "127", 'A': "201", 'B': "202", 'C': "203", 'D': "204", 'E': "205",
            'F': "206", 'G': "207", 'H': "208", 'I': "209", 'J': "210", 'K': "211", 'L': "212", 'M': "213",
            'N': "214", 'O': "215", 'P': "216", 'Q': "217", 'R': "218", 'S': "219", 'T': "220", 'U': "221",
            'V': "222", 'W': "223", 'X': "224", 'Y': "225", 'Z': "226", ",": "301", ".": "302"}

def encrypt_string(string_in, secret_key):

    string_as_num = "".join((str_dict[string_in[n]] for n in range(0,len(string_in))))

    return int(string_as_num) * secret_key


# Decrypt a string
def decrypt_string(encrypted_str, secret_key):
    string_as_num = str(int(encrypted_str // secret_key))
    start_index = 0
    end_index = 3
    string_out = ""

    for _ in range(0, len(string_as_num) // 3):
        string_out += "".join([k for k,v in str_dict.items() if v == string_as_num[start_index:end_index]])
        start_index += 3
        end_index += 3

    return string_out

merchant_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip_address = "192.168.1.123"
merchant_server.bind((ip_address, 12020))
merchant_server.listen(5)

brokersocket, broaddr = merchant_server.accept()
print(f"Got connection from broker: {broaddr}")
print("-------------------------------------------------------------------------------------------------------------")

# Generate public and private keys
merhcant_public_key, merchant_private_key = public_private_keys()

with open("broker_public.pem", "rb") as f:
    broker_public_key = rsa.PublicKey.load_pkcs1(f.read())

challenge_1 = broker_merchant_authentication(brokersocket, broker_public_key)
receiving_challenge_1_response = brokersocket.recv(2048).decode()
if challenge_1 != receiving_challenge_1_response:
    print("Not an Authorized broker")
    brokersocket.close()
else:
    print("Authorized broker")
    print("-------------------------------------------------------------------------------------------------------------")

# broker authenticating merchant
challenge_to_merchant_encrypted = brokersocket.recv(2048)
challenge_to_merchant_decrypted = challenge_to_merchant_encrypted
brokersocket.send(bytes(challenge_to_merchant_decrypted))

# diffie hellman
# Receiving Diffie-Hellman parameters
prime_numbers = brokersocket.recv(1024).decode()
p , q = prime_numbers.split()
p_number = int(p)
q_number = int(q)
merchant_dh_private_key = int(input("Enter private key for diffie-hellman: "))
public_diffie_hellman_key = (q_number**merchant_dh_private_key) % p_number
public_key_dh_customer = brokersocket.recv(2048).decode()
public_dh_customer = int(public_key_dh_customer)
brokersocket.send(bytes(str(public_diffie_hellman_key), "utf-8"))
session_key = (public_dh_customer**merchant_dh_private_key) % p_number

# diffie hellman key generated now authenticating that customer has same key
message = input("Enter the diffie-hellman challenge for customer: ")
messsage_encrypted = encrypt_string(message, session_key)
brokersocket.send(bytes(str(messsage_encrypted), "utf-8"))
merchant_message_decrpyt = brokersocket.recv(2048).decode()
if message != merchant_message_decrpyt:
    print("Diffie hellman session key failed")
    brokersocket.close()
else:
    print("Diffie hellman session key generated, and successfully decrypted")
    print("-------------------------------------------------------------------------------------------------------------")

# diffie hellman authentication done, sending product list
brokersocket.send(bytes(product_string, "utf-8"))

# receving product list
product_choice_encrypted = brokersocket.recv(4096).decode()
product_choice_decrypted = decrypt_string(int(product_choice_encrypted),session_key)
product_choice_list = product_choice_decrypted.split()

# sending total amount to customer
total_amount = 0
for product in product_choice_list:
    total_amount += float(inverntory_list[product])

brokersocket.send(bytes(str(total_amount), "utf-8"))

# payment by broker to merchant
# broker_transaction_id = brokersocket.recv(1024).decode()
broker_transaction_amount = brokersocket.recv(1024).decode()
if float(broker_transaction_amount) == total_amount:
    broker_transaction_message = "Transaction Successful"
    brokersocket.send(bytes(broker_transaction_message, "utf-8"))
else:
    broker_transaction_message = "Transaction Un-Successful"
    brokersocket.send(bytes(broker_transaction_message, "utf-8"))

print("E-products send successfully")

brokersocket.close()
