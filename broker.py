import socket
import rsa

def public_private_keys():
    public_key, private_key = rsa.newkeys(1024)
    with open("broker_public.pem", "wb") as f:
        f.write(public_key.save_pkcs1("PEM"))
    return public_key, private_key


def broker_customer_authentication(clientsocket, public_key):
    challenge_1 = input("Enter challenge: ")
    encrypt_challenge_1 = rsa.encrypt(challenge_1.encode(), public_key)
    clientsocket.send(encrypt_challenge_1)
    return challenge_1

def broker_merchant_authentication(merchantsocket, public_key):
    challenge_1 = input("Enter challenge: ")
    encrypt_challenge_1 = rsa.encrypt(challenge_1.encode(), public_key)
    merchantsocket.send(encrypt_challenge_1)
    return challenge_1

def decrypt(message, private_key):
    clear_message = rsa.decrypt(message, private_key)
    return clear_message

def database(username, database):
    return database[username]

# Set up server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip_address = "192.168.1.123"
server_socket.bind((ip_address, 12016))
server_socket.listen(5)


clientsocket, addr = server_socket.accept()
print(f"Got connection from customer: {addr}")
print("-------------------------------------------------------------------------------------------------------------")
#database for server
databse = {"Moksh555": "moksh555", "Vatsal": "Vatsal29"}

# Generate public and private keys
broker_public_key, broker_private_key = public_private_keys()
customer_credentials = clientsocket.recv(1024).decode("utf-8")
customer_credentials_username, customer_credentials_password = customer_credentials.split()


if customer_credentials_password != database(customer_credentials_username, databse):
    print("Not registered user")
    clientsocket.close()
    server_socket.close()
else:
    print("Customer Credentials are correct! Now please challenge customer")
    print("-------------------------------------------------------------------------------------------------------------")


# sending challenge to customer
with open("customer_public.pem", "rb") as f:
    customer_public_key = rsa.PublicKey.load_pkcs1(f.read())
challenge_1 = broker_customer_authentication(clientsocket, customer_public_key)
receiving_challenge_1_response = clientsocket.recv(1024).decode()
if challenge_1 != receiving_challenge_1_response:
    print("Not an Authorized user")
    clientsocket.close()
    server_socket.close()
else:
    print("Authorized customer! Now, wait for customer challenge!")
    print("-------------------------------------------------------------------------------------------------------------")

customer_challenge_1 = clientsocket.recv(1024)
decrypt_customer_challenge_1 = decrypt(customer_challenge_1, broker_private_key)
clientsocket.send(decrypt_customer_challenge_1)

#merchant and broker authentication
merchantsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
merchantsocket.connect((ip_address, 12020))
with open("merhcant_public.pem", "rb") as f:
    merchant_public_key = rsa.PublicKey.load_pkcs1(f.read())

merchant_challenge_1 = merchantsocket.recv(2048)
decrypt_merchant_challenge_1 = decrypt(merchant_challenge_1, broker_private_key)
merchantsocket.send(decrypt_merchant_challenge_1)

# BROKER AUTHENTICATING MERCHANT
challenge_to_merchant = input("Enter the challenge: ")
challenge_to_merchant_authentication = rsa.encrypt(challenge_to_merchant.encode(), merchant_public_key)
merchantsocket.send(challenge_to_merchant_authentication)
challenge_to_merchant_authentication_decrypted_response = merchantsocket.recv(2048)

if challenge_to_merchant != challenge_to_merchant:
    print("Not an Authorized Merchant! Cancelling connection")
    merchantsocket.close()
else:
    print("Authorized Merchant lets generate diffie-hellman key for communication!")
    print("-------------------------------------------------------------------------------------------------------------")

#diffie hellman key exchange
p = input("Select prime p: ")
q = input("Select prime q: ")
print("-------------------------------------------------------------------------------------------------------------")

p_merhcant = p
q_merhcant = q
merchantsocket.send(f"{p_merhcant} {q_merhcant}".encode("utf-8"))
clientsocket.send(f"{p} {q}".encode("utf-8"))

public_key_dh_customer = clientsocket.recv(2048).decode()
merchantsocket.send(bytes(public_key_dh_customer, "utf-8"))
public_key_dh_merhcant = merchantsocket.recv(1024).decode()
clientsocket.send(bytes(public_key_dh_merhcant, "utf-8"))

# receving data for authenticating after dh
merchant_message = merchantsocket.recv(2048).decode()
clientsocket.send(bytes(merchant_message, "utf-8"))
merchant_message_decpyt = clientsocket.recv(2048).decode()
merchantsocket.send(bytes(merchant_message_decpyt, "utf-8"))

# diffie hellman authentication done by both parties now exchanging product list
product_list = merchantsocket.recv(4096).decode()
clientsocket.send(bytes(product_list, "utf-8"))

# product choose by customer
product_list_encrypted = clientsocket.recv(4096).decode()
merchantsocket.send(bytes(product_list_encrypted, "utf-8"))

# payment information
total_amount = merchantsocket.recv(1024).decode()
total_amount_to_customer = float(total_amount) + 20
clientsocket.send(bytes(str(total_amount_to_customer), "utf-8"))

# receive customer payment transaction id
# transaction_id = clientsocket.recv(1024).decode()
transaction_amount = clientsocket.recv(1024).decode()
if float(transaction_amount) == total_amount_to_customer:
    transaction_message = "Transaction Successful"
    clientsocket.send(bytes(transaction_message, "utf-8"))
else:
    transaction_message = "Transaction Un-Successful"
    clientsocket.send(bytes(transaction_message, "utf-8"))

# payment to merchant by broker
broker_transaction_id = input("Enter transaction id: ")
# merchantsocket.send(bytes(broker_transaction_id, "utf-8"))
merchantsocket.send(bytes(total_amount, "utf-8"))
transaction_message = merchantsocket.recv(1024).decode()
print(transaction_message)
# Close the connection with the current customer
clientsocket.close()
