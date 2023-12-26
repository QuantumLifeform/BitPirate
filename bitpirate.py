import requests
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from binascii import hexlify, unhexlify
import hashlib
import base58
import random

def generate_keypair(bits):
    # Sprawdź czy liczba bitów jest podzielna przez 8, jeśli nie, dostosuj długość
    if bits % 8 != 0:
        bits += 8 - (bits % 8)
    
    private_key_int = random.getrandbits(bits)
    private_key_hex = format(private_key_int, 'x')

    private_key_bytes = unhexlify(private_key_hex.zfill(bits // 4))
    private_key = ec.derive_private_key(int.from_bytes(private_key_bytes, 'big'), ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()

    uncompressed_public_key = hexlify(public_key.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)).decode()
    compressed_public_key = hexlify(public_key.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.CompressedPoint)).decode()

    uncompressed_address = generate_bitcoin_address(uncompressed_public_key)
    compressed_address = generate_bitcoin_address(compressed_public_key)

    return {
        "private_key": private_key_hex,
        "uncompressed_public_key": uncompressed_public_key,
        "compressed_public_key": compressed_public_key,
        "uncompressed_address": uncompressed_address,
        "compressed_address": compressed_address
    }

def generate_bitcoin_address(public_key_hex):
    public_key_bytes = unhexlify(public_key_hex)
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    ripemd160_hash = hashlib.new("ripemd160", sha256_hash).digest()
    extended_hash = b"\x00" + ripemd160_hash
    checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]
    binary_address = extended_hash + checksum
    bitcoin_address = base58.b58encode(binary_address).decode("utf-8")
    return bitcoin_address

def check_and_save_with_satoshi(address, private_key):
    api_url = f"https://blockchain.info/q/getreceivedbyaddress/{address}"
    response = requests.get(api_url)

    try:
        satoshi_received = int(response.text)
    except ValueError:
        print(f"Error decoding Satoshi response for address {address}. Skipping...")
        return

    if satoshi_received > 0:
        save_to_file(address, private_key, satoshi_received)
        print(f"Address {address} has received {satoshi_received} satoshi. Saved to file.")

def save_to_file(address, private_key, satoshi_received):
    with open("D:\\bitcoinpirate.txt", "a") as file:
        file.write(f"Address: {address}\nPrivate Key: {private_key}\nSatoshi Received: {satoshi_received}\n\n")

# Pozostałe funkcje bez zmian

if __name__ == "__main__":
    bits_range = int(input("Enter the bitrange for random generated addresses : "))
    
    current_key = 0
    while current_key < 2**bits_range:
        keypair = generate_keypair(bits_range)
        
        print("\nChecking Uncompressed Address:", keypair["uncompressed_address"])
        check_and_save_with_satoshi(keypair["uncompressed_address"], keypair["private_key"])

        print("\nChecking Compressed Address:", keypair["compressed_address"])
        check_and_save_with_satoshi(keypair["compressed_address"], keypair["private_key"])

        current_key += 1

        time.sleep(10)  # Ogranicz liczbę zapytań do jednego na 10 sekund

