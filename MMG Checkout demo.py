from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import json
import time
import configparser

# Create a ConfigParser object
config = configparser.ConfigParser()

# Read the config file
config.read('setup.cfg')

# Access data
merchant = config['DEFAULT']['merchant']
merchant_msisdn = config['DEFAULT']['merchant_msisdn']
secret_key = config['DEFAULT']['secret_key']
amount =  config['DEFAULT']['amount']
clientId = config['DEFAULT']['clientId']
checkout_response = config['DEFAULT']['checkout_response_token']


merchantName = f"{merchant} ({merchant_msisdn})"
description = f"Lorem Ipsum Oil"


# Load private key 
with open(f'keys/{merchant_msisdn}.private.pem', 'rb') as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),password=None,backend=default_backend())

# Load public key
with open(f'keys/{merchant_msisdn}.public.pem', 'rb') as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

def generateUrl(token, msisdn, clientId):
   token = base64.urlsafe_b64encode(token).decode()
   print("-- CHECKOUT URL PARAMS --")
   print(f"MSISDN: {msisdn}")
   print(f"CLIENTID: {clientId}")
   print(f"TOKEN: {token}\n\n")

   print("-- CHECKOUT URL --")
   print(f"https://gtt-uat-checkout.qpass.com:8743/checkout-endpoint/home?token={token}&merchantId={msisdn}&X-Client-ID={clientId}")


def encrypt(checkout_object):
    json_object = json.dumps(checkout_object, indent=4)
    print(f"Checkout Object:\n {json_object}\n")

    # message to bytes
    json_bytes = json_object.encode("ISO-8859-1")
    
    # encrypt message
    ciphertext = public_key.encrypt(
        json_bytes, 
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
        algorithm=hashes.SHA256(), 
        label=None)
    )
    return ciphertext

def decrypt(ciphertext):
    # pad if necessary
    padding_needed = 4 - (len(ciphertext) % 4)
    if padding_needed:
        ciphertext += '=' * padding_needed

    # urlsafe decode
    ciphertext = base64.urlsafe_b64decode(ciphertext.encode())

    decrypted_data = private_key.decrypt(
        ciphertext, 
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                     algorithm=hashes.SHA256(), 
                     label=None
                     )
    )

    # bytes to string
    decrypted_string = decrypted_data.decode()

    print(decrypted_string)
    #convert to object
    decrypted_json = json.loads(decrypted_string)
    return decrypted_json


def run(merchant_msisdn, amount, secretKey,description, merchantName, clientId):
    timestamp = int(time.time())

    tokenParams = {
                "secretKey":secretKey,
                "amount":amount,
                "merchantId":merchant_msisdn,
                "merchantTransactionId":str(timestamp),
                "productDescription":description,
                "requestInitiationTime":timestamp,
                "merchantName":merchantName
            }
    
    token = encrypt(tokenParams)
    generateUrl(token, merchant_msisdn, clientId)    

run(merchant_msisdn, amount, secret_key, description,merchantName, clientId)


if checkout_response:
    print(f"Decrypted response: {decrypt(checkout_response)}")



