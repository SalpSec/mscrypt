from Crypto.Cipher import AES

# Microsoft uses a weird implementation of PBKDF1 with support for extending to length beyond the default 20 bytes of algorithms like SHA1
# It uses the last hash from the primary iteration combined with a control counter to generate the padding hash
# Warning for storing hardcoded keys: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.passwordderivebytes?view=netframework-4.8.1#remarks ;-)
# https://referencesource.microsoft.com/#mscorlib/system/security/cryptography/passwordderivebytes.cs
def ms_password_derived_bytes(passphrase: str, salt_value: str, hash_algorithm, password_iterations: int, key_size: int):
    iterations = password_iterations
    if iterations > 0:
        lasthash = hash_algorithm.new(passphrase.encode("UTF-8") + salt_value.encode("ascii")).digest()
        iterations -= 1
    else:
        raise ValueError("Iterations must be greater than 0")
    
    for _ in range(iterations - 1):
        lasthash = hash_algorithm.new(lasthash).digest()

    derived_key = hash_algorithm.new(lasthash).digest()
    counter = 1
    while len(derived_key) < key_size:
        derived_key += hash_algorithm.new(str(counter).encode("ascii") + lasthash).digest()
        counter += 1
    return derived_key[:key_size]

# Microsoft uses a implementation of Rijndael (AES) with CBC where PKCS7 padding is used by default, so we need to unpad after grabbing the data.
# Padding issues are mentioned in deprecation warning: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rijndaelmanagedtransform?view=netframework-4.8.1#remarks
# https://referencesource.microsoft.com/#mscorlib/system/security/cryptography/rijndaelmanagedtransform.cs
def ms_decrypt_aes_cbc(data: bytes, key: bytes, init_vector = b'\x00'*16):
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=init_vector)
    decrypted_bytes = cipher.decrypt(data)
    padding_length = decrypted_bytes[-1] # Unpadding (assuming PKCS7 padding which is default in C# RijndaelManaged)
    return decrypted_bytes[:-padding_length]

def ms_decrypt_aes_pbkdf1(data: bytes, passphrase: str, salt_value: str, hash_algorithm, password_iterations: int, key_size: int, init_vector = b'\0'*16):
    key = ms_password_derived_bytes(passphrase, salt_value, hash_algorithm, password_iterations, key_size)
    return ms_decrypt_aes_cbc(data, key, init_vector)
