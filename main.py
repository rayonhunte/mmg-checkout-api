from flask import Flask, request
from flask_restx import Api, Resource, fields
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from functools import wraps
import base64
import json
import time
import os
from dotenv import load_dotenv

# Load environment variables
from dotenv import load_dotenv
import os

# Explicitly load .env file from current directory
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
print("Debug: Loading environment from:", os.path.join(os.path.dirname(__file__), '.env'))

app = Flask(__name__)
api = Api(app, version='1.0', title='MMG Checkout API',
          description='API for MMG payment processing')

# Environment Variables
MERCHANT = os.getenv("MERCHANT", "GEDT")
MERCHANT_MSISDN = os.getenv("MERCHANT_MSISDN", "7771003")
SECRET_KEY = os.getenv("SECRET_KEY", "m7771003gxgd")
CLIENT_ID = os.getenv("CLIENT_ID", "2ae426d409aa4b3cae1ef2eeb87a5388")

# Set a default API key if not provided in environment
DEFAULT_API_KEY = "your-secure-api-key-here"
API_KEY = os.getenv("API_KEY", DEFAULT_API_KEY)

print(f"Server starting with API_KEY: {API_KEY}")

# API Models
checkout_model = api.model('CheckoutRequest', {
    'amount': fields.String(required=True, description='Transaction amount'),
    'product_description': fields.String(required=True, description='Description of the product/service'),
    'merchant_name': fields.String(required=False, description='Override default merchant name')
})

decrypt_model = api.model('DecryptResponse', {
    'token': fields.String(required=True, description='Encrypted response token from MMG')
})

# Load RSA keys
def load_keys():
    try:
        with open(f'keys/{MERCHANT_MSISDN}.private.pem', 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend())

        with open(f'keys/{MERCHANT_MSISDN}.public.pem', 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(), backend=default_backend())
            
        return private_key, public_key
    except Exception as e:
        raise Exception(f"Error loading keys: {str(e)}")

private_key, public_key = load_keys()

# Security decorator
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        print(f"Debug: Received auth header: [{auth_header}]")
        
        if not auth_header:
            api.abort(401, "Missing Authorization header")
            
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            api.abort(401, "Invalid Authorization header format. Use: Bearer <token>")
            
        provided_key = parts[1]
        print(f"Debug: Comparing keys - Provided: [{provided_key}] vs Expected: [{API_KEY}]")
        
        if provided_key != API_KEY:
            api.abort(401, "Invalid API key")
            
        return f(*args, **kwargs)
    return decorated

# Helper Functions
def encrypt(checkout_object: dict) -> bytes:
    """Encrypts checkout parameters using RSA encryption."""
    json_bytes = json.dumps(checkout_object).encode("ISO-8859-1")
    return public_key.encrypt(
        json_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt(ciphertext: str) -> dict:
    """Decrypts MMG response token."""
    # Handle base64 padding
    padding_needed = 4 - (len(ciphertext) % 4)
    if padding_needed:
        ciphertext += '=' * padding_needed

    # Decode and decrypt
    encrypted_data = base64.urlsafe_b64decode(ciphertext.encode())
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return json.loads(decrypted_data.decode())

def generate_checkout_url(token: bytes, msisdn: str, client_id: str) -> str:
    """Generates MMG checkout URL."""
    token_str = base64.urlsafe_b64encode(token).decode()
    return f"https://gtt-uat-checkout.qpass.com:8743/checkout-endpoint/home?token={token_str}&merchantId={msisdn}&X-Client-ID={client_id}"

# API Endpoints
@api.route('/api/v1/checkout')
class Checkout(Resource):
    @api.doc('create_checkout',
             security='apikey',
             responses={
                 200: 'Success',
                 401: 'Unauthorized',
                 500: 'Server Error'
             })
    @api.expect(checkout_model)
    @require_api_key
    def post(self):
        try:
            data = request.json
            timestamp = int(time.time())
            merchant_name = data.get('merchant_name') or f"{MERCHANT} ({MERCHANT_MSISDN})"
            
            token_params = {
                "secretKey": SECRET_KEY,
                "amount": data['amount'],
                "merchantId": MERCHANT_MSISDN,
                "merchantTransactionId": str(timestamp),
                "productDescription": data['product_description'],
                "requestInitiationTime": timestamp,
                "merchantName": merchant_name
            }
            
            token = encrypt(token_params)
            checkout_url = generate_checkout_url(token, MERCHANT_MSISDN, CLIENT_ID)
            
            return {
                "checkout_url": checkout_url,
                "merchant_transaction_id": str(timestamp),
                "merchant_id": MERCHANT_MSISDN
            }
        except Exception as e:
            api.abort(500, str(e))

@api.route('/api/v1/decrypt-response')
class DecryptResponse(Resource):
    @api.doc('decrypt_response',
             security='apikey',
             responses={
                 200: 'Success',
                 400: 'Bad Request',
                 401: 'Unauthorized'
             })
    @api.expect(decrypt_model)
    @require_api_key
    def post(self):
        try:
            data = request.json
            decrypted_data = decrypt(data['token'])
            return {"decrypted_response": decrypted_data}
        except Exception as e:
            api.abort(400, f"Error decrypting token: {str(e)}")

# Authorization scheme for Swagger UI
authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Type in the *'Value'* input box below: **'Bearer <API key>'**"
    }
}
api.authorizations = authorizations

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
