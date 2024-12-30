import requests

# Tu clave de API de VirusTotal
API_KEY = "d-"
# URL base de la API de VirusTotal
BASE_URL = "https://www.virustotal.com/api/v3/files/"

# Función para obtener el reporte de un archivo por su hash
def get_file_report(file_hash):
    headers = {
        "x-apikey": API_KEY
    }
    try:
        # Realizar la solicitud GET a la API
        response = requests.get(f"{BASE_URL}{file_hash}", headers=headers)

        if response.status_code == 200:
            # Si la solicitud fue exitosa, parsear la respuesta
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            # Información relevante
            nombre_archivo = attributes.get('names', ['Desconocido'])[0]
            tipo_archivo = attributes.get('type_description', 'Desconocido')
            tamano = attributes.get('size', 'Desconocido')
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            
            # Mostrar la información obtenida
            print(f"Hash: {file_hash}")
            print(f"Nombre del archivo: {nombre_archivo}")
            print(f"Tipo de archivo: {tipo_archivo}")
            print(f"Tamaño: {tamano} bytes")
            print("Análisis reciente:")
            print(f"  - Maliciosos: {last_analysis_stats.get('malicious', 0)}")
            print(f"  - Limpios: {last_analysis_stats.get('harmless', 0)}")
            print(f"  - Suspiciosos: {last_analysis_stats.get('suspicious', 0)}")
            print(f"  - Desconocidos: {last_analysis_stats.get('undetected', 0)}")
        else:
            # Si la solicitud falla, mostrar el error
            error_msg = response.json().get('error', {}).get('message', 'Error desconocido')
            print(f"Error al obtener el reporte del hash {file_hash}: {response.status_code} - {error_msg}")
    except Exception as e:
        print(f"Error procesando el hash {file_hash}: {e}")

# Función para procesar una lista de hashes
def analyze_hashes(hashes):
    for file_hash in hashes:
        get_file_report(file_hash)
        print("-" * 50)

# Función para obtener la lista de hashes desde la entrada del usuario
def get_hashes():
    # Solicitar entrada de hashes, separados por espacios, tabulaciones o saltos de línea
    raw_hashes = input("Hashes a analizar (separados por saltos de línea, espacios o tabulaciones): ")
    # Reemplazar tabulaciones y saltos de línea con espacios y luego dividir por espacios
    hash_list = [file_hash.strip() for file_hash in raw_hashes.replace("\t", " ").replace("\n", " ").split() if file_hash.strip()]
    return hash_list

hashes = get_hashes()
analyze_hashes(hashes)
