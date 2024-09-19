import hashlib
import random
import string

# Rotate left function
def rotate_left(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

# Function to convert a value to a hexadecimal string
def cvt_hex(val):
    return ''.join([f'{(val >> (i * 4)) & 0xF:x}' for i in range(7, -1, -1)])

# UTF-8 encoding
def utf8_encode(string):
    return string.encode('utf-8')

# SHA-1 hashing algorithm
def sha1(message):
    message = utf8_encode(message)
    msg_len = len(message)
    word_array = []

    # Prepare the word array
    for i in range(0, msg_len - 3, 4):
        j = (message[i] << 24) | (message[i+1] << 16) | (message[i+2] << 8) | message[i+3]
        word_array.append(j)

    i = {
        0: 0x080000000,
        1: (message[msg_len - 1] << 24) | 0x0800000,
        2: (message[msg_len - 2] << 24) | (message[msg_len - 1] << 16) | 0x08000,
        3: (message[msg_len - 3] << 24) | (message[msg_len - 2] << 16) | (message[msg_len - 1] << 8) | 0x80
    }.get(msg_len % 4, 0)

    word_array.append(i)
    
    while len(word_array) % 16 != 14:
        word_array.append(0)
    
    word_array.append((msg_len * 8) >> 32)
    word_array.append((msg_len * 8) & 0xFFFFFFFF)

    # Initialize variables
    H0 = 0x67452301
    H1 = 0xefcdab89
    H2 = 0x98badcfe
    H3 = 0x10325476
    H4 = 0xc3d2e1f0

    for blockstart in range(0, len(word_array), 16):
        W = word_array[blockstart:blockstart + 16] + [0] * 64
        for i in range(16, 80):
            W[i] = rotate_left(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1)
        
        A = H0
        B = H1
        C = H2
        D = H3
        E = H4

        for i in range(80):
            if 0 <= i <= 19:
                f = (B & C) | (~B & D)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = B ^ C ^ D
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (B & C) | (B & D) | (C & D)
                k = 0x8F1BBCDC
            else:
                f = B ^ C ^ D
                k = 0xCA62C1D6

            temp = (rotate_left(A, 5) + f + E + k + W[i]) & 0xFFFFFFFF
            E = D
            D = C
            C = rotate_left(B, 30)
            B = A
            A = temp

        H0 = (H0 + A) & 0xFFFFFFFF
        H1 = (H1 + B) & 0xFFFFFFFF
        H2 = (H2 + C) & 0xFFFFFFFF
        H3 = (H3 + D) & 0xFFFFFFFF
        H4 = (H4 + E) & 0xFFFFFFFF

    return ''.join([cvt_hex(h) for h in [H0, H1, H2, H3, H4]]).lower()

# HMAC-SHA1 implementation
def hmac_sha1(key, message):
    block_size = 64
    if len(key) > block_size:
        key = sha1(key)
    if len(key) < block_size:
        key = key.ljust(block_size, '\0')

    o_key_pad = ''.join([chr(ord(c) ^ 0x5C) for c in key])
    i_key_pad = ''.join([chr(ord(c) ^ 0x36) for c in key])

    return sha1(o_key_pad + sha1(i_key_pad + message))

# Generate random hex string
def generate_random_hex(length):
    return ''.join(random.choice(string.hexdigits.lower()) for _ in range(length))

# Wrapped HMAC-SHA1 function
def wrapped_crypto_token(salt=None, wrapped_crypto_string=''):
    try:
        if salt is None:
            salt = generate_random_hex(16)

        hash_value = hmac_sha1(salt, wrapped_crypto_string)
        return {
            'salt': salt,
            'success': True,
            'hash': hashlib.sha1(hash_value.encode()).digest().hex()
        }
    except Exception as err:
        return {
            'success': False,
            'salt': None,
            'hash': None,
            'message': str(err)
        }

# Example usage
result = wrapped_crypto_token(salt='6f27a28e58f950b1',wrapped_crypto_string="ccccc")
x = result['salt']
print(x)
print(result)
