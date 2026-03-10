import re #busca patrones de texto. 
from supabase import create_client  #importa la funcion de la librería de Supabase. 

# conexión Supabase
url = "https://xdubkpxanuxhqkxvmcyp.supabase.co"
key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhkdWJrcHhhbnV4aHFreHZtY3lwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI3NDI0MTksImV4cCI6MjA4ODMxODQxOX0.j3K3LJWo2M-Yyr3AHs87ooFsPcQeVffQV55M5yiDpWQ"  #APIKEY

supabase = create_client(url, key) #Python envía los datos a la BD. 

log_file = "access.log" #guarda nombre archivo que contiene logs. 

pattern = r'(\d+\.\d+\.\d+\.\d+).*"(GET|POST) (.*?)".* (\d{3})'  #patron de búsqueda. IP, HTTP GET O POST, endpoint

failed_attempts = {}  #diccionario para contar intentos fallidos por IP
endpoint_access = {}  #diccionario para guardar endpoints visitados por IP

#lista de endpoints comúnmente atacados por bots
suspicious_endpoints = [
    "/admin",
    "/wp-admin",
    "/wp-login",
    "/phpmyadmin",
    "/config"
]

with open(log_file, "r") as file: #abre archivo en modo lectura
    for line in file: #recorre líneas del archivo
        match = re.search(pattern, line) #busca patrones 

        if match: #si hay un patron válido...
            ip = match.group(1) #primer grupo "192.168.1.0"
            endpoint = match.group(3) #extraer endpoint
            status = int(match.group(4)) #extraer código HTTP y lo convierte en entero-> ej:404

            event = "normal"

            # ---------------------------
            # detección de login fallido
            # ---------------------------

            if status == 401:
                event = "failed_login" #se detecta el login incorrecto

                #si la IP no está en el diccionario se crea
                if ip not in failed_attempts:
                    failed_attempts[ip] = 0

                #se suma un intento fallido
                failed_attempts[ip] += 1

                #si supera 5 intentos se considera posible fuerza bruta
                if failed_attempts[ip] >= 5:
                    event = "brute_force"

            # ---------------------------
            # detección de escaneo
            # ---------------------------

            if ip not in endpoint_access:
                endpoint_access[ip] = set()

            endpoint_access[ip].add(endpoint)

            #si una IP accede a muchos endpoints diferentes
            if len(endpoint_access[ip]) >= 5:
                event = "endpoint_scan"

            # ---------------------------
            # detección de endpoints sospechosos
            # ---------------------------

            if endpoint in suspicious_endpoints:
                event = "suspicious_endpoint"

            activity_text = f"IP {ip} accessed {endpoint} with status {status}" #mensaje que se guardará en la BD

            supabase.table("activities").insert({ # insert en supabase. (tabla entre "")
                "activity": activity_text,
                "type": event
            }).execute() #enviados los datos de arriba. 

            print("Log guardado:", activity_text) # se muestran los resultados en consola. 
            
# se lee el log, analiza eventos, detecta actividad sospechosa y guarda eventos en la BD. 
#¡Es una mini SIEM!    