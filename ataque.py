import base64
import multiprocessing
import os
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- CONFIGURACIÓN ---
ARCHIVO_MENSAJES = "mensajes_cifrados_3078.txt"
ARCHIVO_DICCIONARIO = "diccionario.txt"
ITERACIONES = 500_000

def derivar_clave(password, salt):
    """Deriva la clave usando el costoso PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERACIONES,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def descifrar_mensaje(mensaje_cifrado, password):
    """Intenta descifrar un mensaje. Lanza excepción si la clave es mala."""
    datos = base64.b64decode(mensaje_cifrado)
    salt, iv, cifrado = datos[:16], datos[16:32], datos[32:]
    clave = derivar_clave(password, salt)
    
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    descifrado = decryptor.update(cifrado) + decryptor.finalize()

    # Desaplicar padding. Si la clave es incorrecta, esto suele fallar y lanzar excepción.
    unpadder = padding.PKCS7(128).unpadder()
    mensaje = unpadder.update(descifrado) + unpadder.finalize()

    return mensaje.decode('utf-8')

def intentar_descifrar(args):
    """Función de trabajo para los procesos hijos."""
    mensaje_cifrado, claves = args
    for clave in claves:
        clave = clave.strip() # Limpiar saltos de línea invisibles
        if not clave: 
            continue
        try:
            # Si logra descifrar sin dar error, ¡bingo!
            mensaje = descifrar_mensaje(mensaje_cifrado, clave)
            return mensaje, clave
        except Exception:
            # Si hay error (padding inválido), la contraseña es incorrecta. Seguimos.
            continue
    return None, None

def dividir_lista(lista, n):
    """Divide el diccionario en 'n' partes iguales para repartir el trabajo."""
    k, m = divmod(len(lista), n)
    return [lista[i*k+min(i, m):(i+1)*k+min(i+1, m)] for i in range(n)]

if __name__ == '__main__':
    # 1. Cargar los mensajes
    if not os.path.exists(ARCHIVO_MENSAJES):
        print(f"❌ Error: No se encuentra {ARCHIVO_MENSAJES}")
        exit(1)
        
    with open(ARCHIVO_MENSAJES, 'r') as f:
        mensajes_cifrados = [m.strip() for m in f.readlines() if m.strip()]

    # 2. Cargar el diccionario
    if not os.path.exists(ARCHIVO_DICCIONARIO):
        print(f"❌ Error: No se encuentra {ARCHIVO_DICCIONARIO}")
        exit(1)
        
    with open(ARCHIVO_DICCIONARIO, 'r', encoding='utf-8', errors='ignore') as f:
        diccionario = f.readlines()

    print(f"[*] Se cargaron {len(diccionario)} contraseñas del diccionario.")
    print(f"[*] Objetivo: {len(mensajes_cifrados)} mensajes ocultos.")
    
    # Solo necesitamos romper la clave del PRIMER mensaje. Esa clave abrirá los demás.
    mensaje_objetivo = mensajes_cifrados[0]

    # 3. Preparar el procesado en paralelo
    num_procesos = multiprocessing.cpu_count()
    print(f"[*] 🚀 Iniciando ataque paralelo usando {num_procesos} núcleos de tu CPU...")
    
    chunks_diccionario = dividir_lista(diccionario, num_procesos)
    args_pool = [(mensaje_objetivo, chunk) for chunk in chunks_diccionario]

    clave_correcta = None
    inicio = time.time()

    # 4. Lanzar el Pool
    with multiprocessing.Pool(processes=num_procesos) as pool:
        # imap_unordered va devolviendo resultados según acaban. 
        for mensaje, clave in pool.imap_unordered(intentar_descifrar, args_pool):
            if clave:
                clave_correcta = clave
                pool.terminate() # ¡Mata a todos los demás procesos, ya ganamos!
                break

    fin = time.time()

    # 5. Revelar el secreto
    if clave_correcta:
        print("\n" + "="*55)
        print(f"✅ ¡HACK COMPLETO! La contraseña maestra")