import multiprocessing
import base64
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ITERACIONES = 500_000

def derivar_clave(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERACIONES,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def descifrar_mensaje(mensaje_cifrado, password):
    datos = base64.b64decode(mensaje_cifrado)
    salt, iv, cifrado = datos[:16], datos[16:32], datos[32:]
    
    clave = derivar_clave(password, salt)
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    descifrado = decryptor.update(cifrado) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(descifrado) + unpadder.finalize()).decode()

def probar_clave(args):
    mensaje, clave = args
    try:
        texto = descifrar_mensaje(mensaje, clave)
        return clave, texto
    except Exception:
        return None, None

def main():
    print("Iniciando ataque de diccionario...")
    
    try:
        with open("diccionario.txt", "r", encoding="utf-8") as f:
            claves = [line.strip() for line in f if line.strip()]
        with open("mensajes_cifrados_3078.txt", "r", encoding="utf-8") as f:
            mensajes = [line.strip() for line in f if line.strip()]
    except FileNotFoundError as e:
        print(f"Error al leer archivos: {e}")
        return

    num_cores = multiprocessing.cpu_count()
    print(f"Utilizando {num_cores} nucleos de procesamiento.\n")


    inicio_total = time.time()

    for i, mensaje in enumerate(mensajes):
        print(f"Analizando mensaje {i+1}/{len(mensajes)}...")
        
        inicio_mensaje = time.time()
        tareas = [(mensaje, clave) for clave in claves]
        encontrado = False
        
        with multiprocessing.Pool(processes=num_cores) as pool:
            for clave, texto in pool.imap_unordered(probar_clave, tareas):
                if clave:
                    fin_mensaje = time.time()
                    tiempo_mensaje = fin_mensaje - inicio_mensaje
                    
                    print(f"EXITO - Clave encontrada: {clave}")
                    print(f"Mensaje: {texto}")
                    print(f"Tiempo en esta frase: {tiempo_mensaje:.2f} segundos\n")
                    
                    pool.terminate() 
                    encontrado = True
                    break
            
            if not encontrado:
                fin_mensaje = time.time()
                tiempo_mensaje = fin_mensaje - inicio_mensaje
                
                print("FALLO - Clave no encontrada para este mensaje.")
                print(f"Tiempo en esta frase: {tiempo_mensaje:.2f} segundos\n")

    # Calculamos el tiempo total restando el momento actual del inicio global
    tiempo_total = time.time() - inicio_total
    
    print("-" * 50)
    print("RESUMEN DEL ATAQUE")
    print(f"Tiempo total de ejecucion: {tiempo_total:.2f} segundos.")
    print("-" * 50)

if __name__ == "__main__":
    main()