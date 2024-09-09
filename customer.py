import socket
import rsa

def public_private_keys():
    public_key, private_key = rsa.newkeys(1024)
    with open("customer_public.pem", "wb") as f:
        f.write(public_key.save_pkcs1("PEM"))
    return public_key, private_key


def broker_customer_authentication(socket, public_key):
    challenge_1 = input("Enter challenge: ")
    encrypt_challenge_1 = rsa.encrypt(challenge_1.encode(), public_key)
    socket.send(encrypt_challenge_1)
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

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip_address = "192.168.1.123"
s.connect((ip_address, 12016))

# Generate public and private keys
customer_public_key, customer_private_key = public_private_keys()

credentials_username = input("Username of customer: " )
credentials_password = input("Password of customer: " )
print("-------------------------------------------------------------------------------------------------------------")
s.send(f"{credentials_username} {credentials_password}".encode("utf-8"))


# Customer-broker authentication
with open("broker_public.pem", "rb") as f:
    broker_public_key = rsa.PublicKey.load_pkcs1(f.read())
broker_challenge_1 = s.recv(2048)
decrypt_broker_challenge_1 = decrypt(broker_challenge_1, customer_private_key)
s.send(decrypt_broker_challenge_1)

customer_challenge_1 = broker_customer_authentication(s, broker_public_key)
customer_challenge_1_response = s.recv(1024)

if customer_challenge_1 != customer_challenge_1_response.decode():
    print("Broker is not authorized")
    s.close()
else:
    print("Authorized broker! Broker connecting to merchant!")
    print("-------------------------------------------------------------------------------------------------------------")

#diffie hellman
prime_numbers = s.recv(1024).decode()
p, q = prime_numbers.split()
p_number = int(p)
q_number = int(q)
customer_dh_private_key = int(input("Enter private key for diffie-hellman: "))
print("Diffie-hellman session key generated and authenticated")
print("-------------------------------------------------------------------------------------------------------------")
public_diffie_hellman_key = (q_number**customer_dh_private_key) % p_number
s.send(bytes(str(public_diffie_hellman_key), "utf-8"))
public_diffie_hellman_key_merhcant = s.recv(1024).decode()
public_dh_merhcant = int(public_diffie_hellman_key_merhcant)
session_key = (public_dh_merhcant**customer_dh_private_key) % p_number

# now diffie hellman key generated now sending and receving response for authenticating that customer has same session key
merchant_message = s.recv(2048).decode()
merchat_message_decrpyt = decrypt_string(int(merchant_message), session_key)
s.send(bytes(merchat_message_decrpyt, "utf-8"))

# diffie hellman authentication done
product_string = s.recv(4096).decode()
product_list = product_string.split()
print("This is product list: ", product_list)
print("Please choose from these product list!")

# customer choosing from this list
product_choice = input("Enter products: ")
print("-------------------------------------------------------------------------------------------------------------")
product_choice_encrypted = encrypt_string(product_choice, session_key)
s.send(bytes(str(product_choice_encrypted), "utf-8"))

# amount and payment information
total_amount = s.recv(1024).decode()
print(f"Total Amount: {total_amount}$")
print("-------------------------------------------------------------------------------------------------------------")

# sending broker payment details
transaction_id = input("Enter transaction id: ")
# s.send(bytes(transaction_id, "utf-8"))
s.send(bytes(total_amount, "utf-8"))
transaction_message = s.recv(1024).decode()
print(transaction_message)


s.close()
