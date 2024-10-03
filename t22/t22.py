import requests
import logging
import getpass
import argparse
import sys

# Verificación de la versión de Python
if sys.version_info[0] < 3:
    raise Exception("Este script debe ejecutarse con Python 3.")

# Configuración de logging
logging.basicConfig(filename='hibpINFO.log',
                    format="%(asctime)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                    level=logging.INFO)

# Solicitar la API Key
key = getpass.getpass(prompt="Ingrese su API Key de Have I Been Pwned: ")

headers = {
    'hibp-api-key': key,
    'User-Agent': 'python-script',
    'content-type': 'application/json'
}

# Manejo de argumentos con argparse
parser = argparse.ArgumentParser(description="Verifica si un correo ha sido comprometido.")
parser.add_argument('email', help="Correo electrónico a investigar")
args = parser.parse_args()
email = args.email

# URL para la solicitud a la API
url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false'

try:
    # Realizar solicitud a la API
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Verifica si hay errores HTTP

    data = response.json()  
    if data:
        print(f"Filtraciones encontradas para el correo {email}:")
        
        #archivo de reporte
        with open('reporte_filtraciones.txt', 'w') as report_file:
            report_file.write(f"Filtraciones encontradas para el correo {email}:\n")
            for filtracion in data:
                nombre = filtracion.get("Name", "N/A")
                dominio = filtracion.get("Domain", "N/A")
                fecha = filtracion.get("BreachDate", "N/A")
                descripcion = filtracion.get("Description", "N/A")
                
                print(f"Nombre: {nombre}")
                print(f"Dominio: {dominio}")
                print(f"Fecha: {fecha}")
                print(f"Descripción: {descripcion}")
                print()
                
                # Guardar detalles en el archivo
                report_file.write(f"Nombre: {nombre}\n")
                report_file.write(f"Dominio: {dominio}\n")
                report_file.write(f"Fecha: {fecha}\n")
                report_file.write(f"Descripción: {descripcion}\n\n")
            
            # Registrar el número de filtraciones
            logging.info(f"{email}: {len(data)} filtraciones encontradas.")
    else:
        print(f"No se encontraron filtraciones para el correo {email}.")
        logging.info(f"{email}: No se encontraron filtraciones.")
        
except requests.exceptions.HTTPError as err:
    print(f"Error HTTP: {err}")
    logging.error(f"Error HTTP: {err}")

except requests.exceptions.RequestException as err:
    print(f"Error de conexión: {err}")
    logging.error(f"Error de conexión: {err}")

finally:
    print("Proceso terminado.")
