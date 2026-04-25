# doesnt verify on purpose
import base64
import json

print("This decodes a PASETO token without verifying the signature")
token_str = input("Enter the PASETO token: ")
print("\n")

parts = token_str.split(".")

version = parts[0]
purpose = parts[1]
payload = parts[2]
footer  = parts[3] if len(parts) > 3 else ""

def decode_base64url(s):
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)

raw_payload = decode_base64url(payload)

if purpose == "public":
    raw_payload = raw_payload[:-64]

data = json.loads(raw_payload)
print(data)