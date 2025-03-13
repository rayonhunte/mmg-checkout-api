"""
MMG Checkout API Integration Script

This script demonstrates the integration with MMG's payment processing system.
It handles the creation of secure checkout tokens, URL generation, and response processing.

Key Components:
- Merchant Authentication: Uses merchant ID and MSISDN for identification
- Encryption: RSA encryption for secure data transmission
- Token Generation: Creates encrypted checkout tokens
- URL Generation: Builds checkout URLs for payment processing
- Response Handling: Decrypts and processes checkout responses
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import json
import time
import configparser

# Initialize configuration parser to read merchant settings
config = configparser.ConfigParser()
config.read('setup.cfg')

# Extract merchant configuration from setup.cfg
# These values are essential for identifying the merchant and transaction details
merchant = config['DEFAULT']['merchant']
merchant_msisdn = config['DEFAULT']['merchant_msisdn']
secret_key = config['DEFAULT']['secret_key']
amount =  config['DEFAULT']['amount']
clientId = config['DEFAULT']['clientId']
checkout_response = config['DEFAULT']['checkout_response_token']

# Format merchant display name and transaction description
merchantName = f"{merchant} ({merchant_msisdn})"
description = f"Lorem Ipsum Oil"

# Load RSA private key for decrypting responses
# The private key should be kept secure and never shared
with open(f'keys/{merchant_msisdn}.private.pem', 'rb') as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),password=None,backend=default_backend())

# Load RSA public key for encrypting requests
# The public key is used to secure the checkout token
with open(f'keys/{merchant_msisdn}.public.pem', 'rb') as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

def generateUrl(token, msisdn, clientId):
    """
    Generates the checkout URL that customers will use to make payments.
    
    Args:
        token (bytes): Encrypted checkout token
        msisdn (str): Merchant's MSISDN (phone number)
        clientId (str): Client identifier for API access
        
    Returns:
        None - Prints the URL and parameters
    """
    token = base64.urlsafe_b64encode(token).decode()
    print("-- CHECKOUT URL PARAMS --")
    print(f"MSISDN: {msisdn}")
    print(f"CLIENTID: {clientId}")
    print(f"TOKEN: {token}\n\n")

    print("-- CHECKOUT URL --")
    print(f"https://gtt-uat-checkout.qpass.com:8743/checkout-endpoint/home?token={token}&merchantId={msisdn}&X-Client-ID={clientId}")


def encrypt(checkout_object):
    """
    Encrypts the checkout parameters using RSA encryption.
    
    Args:
        checkout_object (dict): Contains transaction details like amount, merchant ID, etc.
        
    Returns:
        bytes: Encrypted checkout token
    """
    json_object = json.dumps(checkout_object, indent=4)
    print(f"Checkout Object:\n {json_object}\n")

    # Convert JSON to bytes using ISO-8859-1 encoding (required by MMG)
    json_bytes = json_object.encode("ISO-8859-1")
    
    # Encrypt using RSA-OAEP with SHA256
    ciphertext = public_key.encrypt(
        json_bytes, 
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
        algorithm=hashes.SHA256(), 
        label=None)
    )
    return ciphertext

def decrypt(ciphertext):
    """
    Decrypts the checkout response from MMG.
    
    Args:
        ciphertext (str): Base64 encoded encrypted response
        
    Returns:
        dict: Decrypted response containing transaction status and details
    """
    # Handle base64 padding
    padding_needed = 4 - (len(ciphertext) % 4)
    if padding_needed:
        ciphertext += '=' * padding_needed

    # Decode from URL-safe base64
    ciphertext = base64.urlsafe_b64decode(ciphertext.encode())

    # Decrypt using RSA-OAEP with SHA256
    decrypted_data = private_key.decrypt(
        ciphertext, 
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                     algorithm=hashes.SHA256(), 
                     label=None
                     )
    )

    # Convert decrypted bytes to string and parse JSON
    decrypted_string = decrypted_data.decode()
    print(decrypted_string)
    decrypted_json = json.loads(decrypted_string)
    return decrypted_json


def run(merchant_msisdn, amount, secretKey, description, merchantName, clientId):
    """
    Main function to initiate the checkout process.
    
    Args:
        merchant_msisdn (str): Merchant's MSISDN
        amount (str): Transaction amount
        secretKey (str): Merchant's secret key for authentication
        description (str): Product/Service description
        merchantName (str): Display name of the merchant
        clientId (str): Client identifier for API access
        
    Returns:
        None - Generates and prints checkout URL
    """
    # Generate unique transaction ID using timestamp
    timestamp = int(time.time())

    # Prepare checkout token parameters
    tokenParams = {
                "secretKey": secretKey,
                "amount": amount,
                "merchantId": merchant_msisdn,
                "merchantTransactionId": str(timestamp),
                "productDescription": description,
                "requestInitiationTime": timestamp,
                "merchantName": merchantName
            }
    
    # Encrypt parameters and generate checkout URL
    token = encrypt(tokenParams)
    generateUrl(token, merchant_msisdn, clientId)    

# Initialize checkout process
run(merchant_msisdn, amount, secret_key, description, merchantName, clientId)

# Process checkout response if available
if checkout_response:
    print(f"Decrypted response: {decrypt(checkout_response)}")
