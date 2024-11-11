import requests
from country_mapping import get_country_name_in_spanish  # Importamos la función desde el otro script

# Tu clave de API de VirusTotal
API_KEY = "d9b874b4c567c89cbcda5f1c9992cb151d87ab85fdaf0e4905562473157c3510"
# URL base de la API de VirusTotal
BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

# Función para obtener el reporte de una IP
def get_ip_report(ip):
    headers = {
        "x-apikey": API_KEY
    }
    # Realizar la solicitud GET a la API
    response = requests.get(f"{BASE_URL}{ip}", headers=headers)
    
    if response.status_code == 200:
        # Si la solicitud fue exitosa, parsear la respuesta
        data = response.json()
        # Extraer la información relevante
        info_ip = data.get('data', {})
        attributes = info_ip.get('attributes', {})
        # Información relevante
        pais = get_country_name_in_spanish(attributes.get('country', 'Desconocido'))  # Usamos la función para obtener el país
        clasificacion = attributes.get('category', 'Desconocida')
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        # Mostrar la información obtenida
        print(f"IP: {ip}")
        print(f"País: {pais}")
        print(f"Clasificación: {clasificacion}")
        print("Análisis reciente:")
        print(f"  - Verdaderos Positivos: {last_analysis_stats.get('malicious', 0)}")
        print(f"  - Limpios: {last_analysis_stats.get('harmless', 0)}")
        print(f"  - Suspiciosos: {last_analysis_stats.get('suspicious', 0)}")
        print(f"  - Desconocidos: {last_analysis_stats.get('undetected', 0)}")
    else:
        # Si la solicitud falla, mostrar el error
        print(f"Error al obtener el reporte de la IP {ip}: {response.status_code} - {response.json().get('error', {}).get('message', 'Error desconocido')}")

# Función para procesar una lista de IPs
def analize_ip(ips):
    for ip in ips:
        get_ip_report(ip)
        print("-" * 50)

def get_ips():
    # Solicitar entrada de IPs, que pueden estar separadas por espacios, tabulaciones o saltos de línea
    raw_ip = input("IPs a analizar (separadas por saltos de línea, espacios o tabulaciones): ")
    # Reemplazar tabulaciones y saltos de línea con espacios y luego dividir por espacios
    ip_list = [ip.strip() for ip in raw_ip.replace("\t", " ").replace("\n", " ").split() if ip.strip()]
    return ip_list

# Llamar a la función para procesar la lista de IPs
ips = get_ips()
analize_ip(ips)
