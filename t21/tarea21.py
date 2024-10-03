import requests
import json
import logging
import getpass

# Configuración de logging
logging.basicConfig(filename='hibpINFO.log',
                    format="%(asctime)s %(message)s",
                    datefmt="%m/%d/%Y %I:%M:%S %p",
                    level=logging.INFO)

# Solicitar la API Key
key = getpass.getpass(prompt="Ingrese su API Key de Have I Been Pwned: ")

headers = {
    'content-type': 'application/json',
    'api-version': '3',
    'User-Agent': 'python',
    'hibp-api-key': key
}

# Solicitar el correo a investigar
email = input("Ingrese el correo a investigar: ")

# URL para la solicitud
url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false'

try:
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Lanza una excepción para códigos de estado 4xx/5xx
    
    # Solo si la respuesta es 200 OK
    data = response.json()
    encontrados = len(data)
    
    if encontrados > 0:
        print(f"Los sitios en los que se ha filtrado el correo {email} son:")
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
                
                report_file.write(f"Nombre: {nombre}\n")
                report_file.write(f"Dominio: {dominio}\n")
                report_file.write(f"Fecha: {fecha}\n")
                report_file.write(f"Descripción: {descripcion}\n")
                report_file.write("\n")
                
            msg = f"{email} Filtraciones encontradas: {encontrados}"
            logging.info(msg)
            print(msg)
    else:
        msg = f"El correo {email} no ha sido filtrado"
        logging.info(msg)
        print(msg)
        
except requests.exceptions.HTTPError as http_err:
    msg = f"Error HTTP en la solicitud: {http_err}"
    logging.error(msg)
    print(msg)
    
except requests.exceptions.RequestException as req_err:
    msg = f"Error en la solicitud: {req_err}"
    logging.error(msg)
    print(msg)
    
finally:
    print("Proceso terminado.")
