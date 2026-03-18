import os
import hashlib
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

def derivar_clave(password, salt, iteraciones=5000000):
    """Genera una clave derivada con PBKDF2 usando SHA-256"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # ← CORRECCIÓN: Usar cryptography.hazmat.primitives.hashes
        length=32,
        salt=salt,
        iterations=iteraciones,
        backend=default_backend()
    )
    return kdf.derive(password.encode())




def cifrar_mensaje(mensaje, password):
    """Cifra un mensaje con AES y una clave derivada de PBKDF2"""
    salt = os.urandom(16)  # Generar un salt aleatorio
    clave = derivar_clave(password, salt)  # Derivar clave con alto coste computacional

    iv = os.urandom(16)  # Vector de inicialización
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding para que el mensaje sea múltiplo de 16
    padding_len = 16 - (len(mensaje) % 16)
    mensaje += chr(padding_len) * padding_len

    mensaje_cifrado = encryptor.update(mensaje.encode()) + encryptor.finalize()
    return base64.b64encode(salt + iv + mensaje_cifrado).decode()  # Codificar en Base64




def descifrar_mensaje(mensaje_cifrado, password, iteraciones=500000):
    """Descifra un mensaje cifrado con AES y PBKDF2, debería llevar varios segundos"""
    datos = base64.b64decode(mensaje_cifrado)
    salt, iv, mensaje_encriptado = datos[:16], datos[16:32], datos[32:]

    start = time.time()  # Medir tiempo de descifrado
    clave = derivar_clave(password, salt, iteraciones)  # Coste alto en tiempo
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    mensaje_descifrado = decryptor.update(mensaje_encriptado) + decryptor.finalize()
    padding_len = ord(mensaje_descifrado[-1:])
    mensaje_descifrado = mensaje_descifrado[:-padding_len].decode()

    end = time.time()
    print(f"Tiempo de descifrado: {end - start:.2f} segundos")

    return mensaje_descifrado



#pruebas

password = "clave_super_segura_indescifrable_y_mágica"
mensaje = "Suspenso el que lo lea"

# Cifrar
mensaje_cifrado = cifrar_mensaje(mensaje, password)
print(f"Mensaje cifrado: {mensaje_cifrado}")

# Descifrar
mensaje_descifrado = descifrar_mensaje(mensaje_cifrado, password)
print(f"Mensaje descifrado: {mensaje_descifrado}")