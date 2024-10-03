#EQUIPO
#XIMENA MITCHEL GALLEGOS GALLEGOS
#ARIANNA MICHELLE SEGURA VALDES

import subprocess
import csv
from openpyxl import Workbook
import os

# Ruta del script de PowerShell
ruta_script_ps = r"C:\Users\galle\OneDrive\Escritorio\monitor_servicios.ps1"

# Ruta del archivo CSV 
ruta_csv = r"C:\Users\galle\OneDrive\Escritorio\servicios.csv"

# Ruta del archivo Excel
ruta_excel = r"C:\Users\galle\OneDrive\Escritorio\servicios.xlsx"

def run_ps():
    try:
        # Ejecutar el script de PowerShell
        subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", ruta_script_ps], check=True)
    except:
        print("Error ejecutando PowerShell.")
        exit(1)

def csv_to_excel():
    if not os.path.exists(ruta_csv):
        print("Archivo CSV no encontrado.")
        exit(1)

    try:
        # Crear y llenar el archivo Excel
        wb = Workbook()
        ws = wb.active
        ws.title = "Servicios"

        with open(ruta_csv, mode="r", newline='', encoding="utf-8") as file:
            reader = csv.reader(file)
            for row in reader:
                ws.append(row)

        wb.save(ruta_excel)
        print(f"Guardado en {ruta_excel}")
    except:
        print("Error procesando CSV.")
        exit(1)

if __name__ == "__main__":
    # Llamar a las funciones para ejecutar
    run_ps()
    csv_to_excel()
