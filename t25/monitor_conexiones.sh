#!/bin/bash

# Integrantes del equipo
# Ximena Mitchel Gallegos Gallegos
# Arianna Michelle Segura Valdes

# Manejo de errores
function check_returncode() {
    if [ $? -ne 0 ]; then
        echo "Error: No se pudo ejecutar el comando netstat."
        exit 1
    fi
}

# Monitorear conexiones de red activas y mostrar la salida en la terminal
echo "Monitoreando conexiones establecidas..."

# Ejecutar el comando netstat y filtrar conexiones establecidas
netstat -tunapl | grep ESTABLISHED
check_returncode  # Verifica si el comando tuvo éxito

echo "Monitoreo completado."

