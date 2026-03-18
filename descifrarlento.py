from cifrado import descifrar
from multiprocessing import Pool, cpu_count
import time
import os
 
def probar_contraseña(args):
    """
    Función que CADA PROCESO ejecutará
    Recibe una tupla (mensaje_cifrado, contraseña)
    Devuelve los resultados si encuentra algo
    """
    mensaje_cifrado, contraseña = args
    resultado = descifrar(mensaje_cifrado, contraseña)
    
    if resultado is not None:
        return (True, mensaje_cifrado, contraseña, resultado)
    return (False, None, None, None)
 
def main():
    print("="*70)
    print("DESCIFRADOR DE MENSAJES - VERSIÓN 2 (CON MULTIPROCESOS)")
    print("="*70)
    
    # PASO 1: Leer el diccionario
    print("\n[1] Leyendo diccionario...")
    with open('diccionario.txt', 'r') as f:
        diccionario = [linea.strip() for linea in f.readlines()]
    print(f"    ✓ Diccionario cargado: {len(diccionario)} palabras")
    
    # PASO 2: Pedir número de grupo
    print("\n[2] ¿Cuál es tu número de grupo?")
    numero_grupo = input("    Ingresa el número (1949, 2965, 3078, 4002, 6935, 7493, 7967): ").strip()
    
    archivo_mensajes = f"mensajes_cifrados_{numero_grupo}.txt"
    
    if not os.path.exists(archivo_mensajes):
        print(f"    ✗ ERROR: No encontré {archivo_mensajes}")
        exit(1)
    
    print(f"    ✓ Archivo encontrado: {archivo_mensajes}")
    
    # PASO 3: Leer los mensajes cifrados
    print("\n[3] Leyendo mensajes cifrados...")
    with open(archivo_mensajes, 'r') as f:
        mensajes_cifrados = [m.strip() for m in f.readlines() if m.strip()]
    print(f"    ✓ Mensajes cargados: {len(mensajes_cifrados)} mensajes")
    
    # PASO 4: Crear TODAS las combinaciones (mensaje, contraseña)
    print("\n[4] Preparando combinaciones para probar...")
    combinaciones = []
    for mensaje in mensajes_cifrados:
        for contraseña in diccionario:
            combinaciones.append((mensaje, contraseña))
    
    print(f"    Total de combinaciones: {len(combinaciones):,}")
    
    # PASO 5: Mostrar información del sistema
    num_cpus = cpu_count()
    print(f"\n[5] Información del sistema:")
    print(f"    CPUs disponibles: {num_cpus}")
    print(f"    Pool size: {num_cpus} procesos en paralelo")
    
    # PASO 6: MULTIPROCESOS - El trabajo se divide entre todos los CPUs
    print(f"\n[6] Iniciando ataque de diccionario (MULTIPROCESOS)...")
    print(f"    Esto debería ser MUCHO más rápido\n")
    
    inicio = time.time()
    
    # Crear un Pool con tantos procesos como CPUs tenga la máquina
    with Pool(processes=num_cpus) as pool:
        # map() distribuye las combinaciones entre los procesos
        resultados = pool.map(probar_contraseña, combinaciones)
    
    tiempo_v2 = time.time() - inicio
    
    # PASO 7: Procesar resultados
    print("\n" + "="*70)
    print("RESULTADOS")
    print("="*70)
    
    mensajes_encontrados = [r for r in resultados if r[0]]
    
    if mensajes_encontrados:
        # Agrupar por contraseña única
        por_contraseña = {}
        for _, msg_cifrado, pwd, msg_desc in mensajes_encontrados:
            if pwd not in por_contraseña:
                por_contraseña[pwd] = []
            por_contraseña[pwd].append(msg_desc)
        
        print(f"\n✓ Se encontraron {len(mensajes_encontrados)} mensaje(s)\n")
        
        for idx, (pwd, mensajes) in enumerate(por_contraseña.items(), 1):
            print(f"{idx}. Contraseña: {pwd}")
            for msg in mensajes:
                print(f"   Mensaje: {msg}")
            print()
    else:
        print("\n  No se encontraron mensajes")
    
    # PASO 8: Estadísticas finales
    print("="*70)
    print("ESTADÍSTICAS")
    print("="*70)
    print(f"Tiempo CON multiprocesos: {tiempo_v2:.2f} segundos")
    print(f" Mensajes descifrados: {len(mensajes_encontrados)}/{len(mensajes_cifrados)}")
    print(f" Combinaciones probadas: {len(combinaciones):,}")
    print(f" Velocidad: {len(combinaciones)/tiempo_v2:,.0f} intentos/segundo")
    print("="*70)
    
    return tiempo_v2
 
if __name__ == '__main__':
    main()