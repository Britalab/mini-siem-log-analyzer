# Mini SIEM - Log Analyzer 🕵️‍♂️💻

Mini SIEM educativo para analizar logs de servidor y detectar actividad sospechosa en tiempo real.

---

## 🔹 Funcionalidades

- Leer logs de servidor (`access.log`)  
- Detectar eventos de seguridad:
  - `failed_login` – intentos de login fallidos
  - `brute_force` – posibles ataques de fuerza bruta
  - `endpoint_scan` – escaneo de endpoints por IP
  - `suspicious_endpoint` – acceso a endpoints sensibles  
- Guardar eventos en **Supabase**  
- Dashboard web interactivo con los últimos 20 eventos  

---

## 🔹 Tecnologías

- **Backend:** Python, Regex, Supabase  
- **Frontend:** HTML, JavaScript, Supabase JS client  

---

## 🔹 Estructura del proyecto
logAnalyzer/
│
├── venv/ # Entorno virtual
├── access.log # Archivo de logs
├── analyzer.py # Script principal
├── dashboard.html # Dashboard web
├── requirements.txt # Librerías de Python
└── .gitignore # Archivos a ignorar


---

## 🔹 Instalación

1. Clonar el repositorio:

```bash
git clone https://github.com/Britalab/mini-siem-log-analyzer.git
cd mini-siem-log-analyzer

Crear entorno virtual e instalar dependencias: 
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

EJECUTAR EL ANALIZADOR DE LOGS
python analyzer.py

<img width="992" height="612" alt="Dashboards" src="https://github.com/user-attachments/assets/531b610b-4b22-4f04-b1f1-d431ecfe1ed4" />

🔹 Licencia

Proyecto educativo, de aprendizaje y pruebas personales.
