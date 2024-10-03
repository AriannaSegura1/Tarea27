#equipo:
#Arianna Michelle Segura Valdes
#Ximena Mitchel Gallegos Gallegos

import pyautogui
import subprocess
import datetime

try:
    #Fecha y hora actual
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    #Captura de pantalla
    imagen_nombre = f'SSPC62_{timestamp}.png'
    pyautogui.screenshot(imagen_nombre)
    print(f'Captura de pantalla guardada: {imagen_nombre}')

    #Registro de procesos con 'tasklist'
    procesos_nombre = f'procesos_{timestamp}.txt'
    resultado = subprocess.run('tasklist', capture_output=True, text=True, shell=True)

    #Archivo de texto
    with open(procesos_nombre, 'w') as archivo:
        archivo.write(resultado.stdout)
    print(f'Lista de procesos guardada: {procesos_nombre}')

except Exception as e:
    print(f'Ocurrió un error: {e}')
