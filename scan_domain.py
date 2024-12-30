import requests
from country_mapping import get_country_name_in_spanish  # Importamos la función desde el otro script

# Tu clave de API de VirusTotal
API_KEY = "d9b874b4c567c89cbcda5f1c9992cb151d87ab85fdaf0e4905562473157c3510"
# URL base de la API de VirusTotal
BASE_URL = "https://www.virustotal.com/api/v3/domains/"


# Función para obtener el reporte de un dominio
def get_domain_report(domain):
    headers = {
        "x-apikey": API_KEY
    }
    try:
        # Realizar la solicitud GET a la API
        response = requests.get(f"{BASE_URL}{domain}", headers=headers)

        if response.status_code == 200:
            # Si la solicitud fue exitosa, parsear la respuesta
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            # Información relevante
            pais = get_country_name_in_spanish(attributes.get('country', 'Desconocido'))
            clasificacion = attributes.get('categories', 'Desconocida')
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            proveedor = attributes.get('as_owner', 'Desconocido')
            asn = attributes.get('asn', 'Desconocido')

            # Mostrar la información obtenida
            print(f"Dominio: {domain}")
            print(f"País: {pais}")
            print(f"Clasificación: {clasificacion}")
            print(f"AS: {asn}")
            print(f"Proveedor: {proveedor}")
            print("Análisis reciente:")
            print(f"  - Maliciosos: {last_analysis_stats.get('malicious', 0)}")
            print(f"  - Limpios: {last_analysis_stats.get('harmless', 0)}")
            print(f"  - Suspiciosos: {last_analysis_stats.get('suspicious', 0)}")
            print(f"  - Desconocidos: {last_analysis_stats.get('undetected', 0)}")
        else:
            # Si la solicitud falla, mostrar el error
            error_msg = response.json().get('error', {}).get('message', 'Error desconocido')
            print(f"Error al obtener el reporte del dominio {domain}: {response.status_code} - {error_msg}")
    except Exception as e:
        print(f"Error procesando el dominio {domain}: {e}")

# Función para procesar una lista de dominios
def analyze_domains(domains):
    for domain in domains:
        get_domain_report(domain)
        print("-" * 50)

# Función para obtener la lista de dominios desde la entrada del usuario
def get_domains():
    # Solicitar entrada de dominios, separados por espacios, tabulaciones o saltos de línea
    raw_domains = input("Dominios a analizar (separados por saltos de línea, espacios o tabulaciones): ")
    # Reemplazar tabulaciones y saltos de línea con espacios y luego dividir por espacios
    domain_list = [domain.strip() for domain in raw_domains.replace("\t", " ").replace("\n", " ").split() if domain.strip()]
    return domain_list


domains = get_domains()
analyze_domains(domains)
