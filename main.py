from password_generator import generate_password
from rsa_encrypt import generate_rsa_key_pair, encrypt_with_rsa
from rsa_decrypt import decrypt_with_rsa

def main():
    # Generate a random password
    password = generate_password()
    print("Generated Password:", password)

    # Generate RSA key pair
    private_key = generate_rsa_key_pair()
    public_key = private_key.public_key()

    # Encrypt the password
    encrypted_password = encrypt_with_rsa(public_key, password)
    print("Encrypted Password:", encrypted_password)

    # Decrypt the password
    decrypted_password = decrypt_with_rsa(private_key, encrypted_password)
    print("Decrypted Password:", decrypted_password)

if __name__ == "__main__":
    main()
