#EQUIPO 
#Arianna Michelle Segura Valdes
#Ximena Mitchel Gallegos Gallegos

import subprocess
import re

# Lista de puertos estándar conocidos
puertos_estandar = [22, 25, 80, 465, 587, 8080]

def ejecutar_script_bash():
    # Ejecuta el script de Bash y captura la salida
    resultado = subprocess.run(['./monitor_conexiones.sh'], capture_output=True, text=True)
    return resultado.stdout

def analizar_conexiones(salida_bash):
    conexiones_sospechosas = []
    for linea in salida_bash.splitlines():
        # Buscar el puerto usando una expresión regular
        match = re.search(r':(\d+)\s+ESTABLISHED', linea)
        if match:
            puerto = int(match.group(1))
            # Si el puerto no es estándar, lo consideramos sospechoso
            if puerto not in puertos_estandar:
                conexiones_sospechosas.append(linea)
    return conexiones_sospechosas

def generar_reporte(conexiones_sospechosas):
    with open('reporte_conexiones_sospechosas.txt', 'w') as f:
        if conexiones_sospechosas:
            f.write("Conexiones sospechosas encontradas:\n")
            f.writelines(conexion + '\n' for conexion in conexiones_sospechosas)
        else:
            f.write("No se encontraron conexiones sospechosas.\n")

def main():
    # Ejecuta el script de Bash y analiza las conexiones
    salida_bash = ejecutar_script_bash()
    conexiones_sospechosas = analizar_conexiones(salida_bash)
    generar_reporte(conexiones_sospechosas)
    print("Análisis completado. El reporte ha sido generado.")

if __name__ == "__main__":
    main()
