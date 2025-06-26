# ttlock_manager.py - Versión Segura que no contiene credenciales

import requests
import time
import hashlib 

# Ya no hay variables de credenciales aquí.

# El servidor de la API que estamos usando.
API_BASE_URL = "https://euapi.ttlock.com"

def obtener_token_acceso(client_id, client_secret, username, password):
    """Se autentica con la API de TTLock usando las credenciales recibidas."""
    url = f"{API_BASE_URL}/oauth2/token"
    
    # Encriptamos la contraseña recibida
    md5_password = hashlib.md5(password.encode('utf-8')).hexdigest()
    
    payload = {
        'clientId': client_id,
        'clientSecret': client_secret,
        'username': username,
        'password': md5_password,
    }
    
    print(f"[TTLock Manager] Solicitando token de acceso a: {API_BASE_URL}")
    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()
        data = response.json()
        if 'access_token' in data:
            print("[TTLock Manager] Token de acceso obtenido con éxito.")
            return data.get('access_token')
        else:
            print(f"[TTLock Manager] Error al obtener token: {data}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[TTLock Manager] Error de conexión: {e}")
        return None

def obtener_lista_cerraduras(client_id, token):
    """Obtiene la lista de cerraduras (salas) desde la cuenta de TTLock."""
    if not token: return []
    url = f"{API_BASE_URL}/v3/lock/list"
    params = {'clientId': client_id, 'accessToken': token, 'pageNo': 1, 'pageSize': 20, 'date': int(time.time() * 1000)}
    lista_final_salas = []
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        if 'list' in data and data['list']:
            salas_reales = [{"lockId": lock['lockId'], "lockAlias": lock['lockAlias']} for lock in data['list']]
            lista_final_salas.extend(salas_reales)
    except requests.exceptions.RequestException as e:
        print(f"[TTLock Manager] Error al obtener cerraduras: {e}")
    
    # Añadimos salas falsas para demostración
    salas_falsas = [
        {"lockId": -1, "lockAlias": "Sala B (Próximamente)"},
        {"lockId": -2, "lockAlias": "Sala C (En Mantenimiento)"}
    ]
    lista_final_salas.extend(salas_falsas)
    return lista_final_salas

def generar_codigo_temporal(client_id, token, lock_id, start_time, end_time):
    """Genera un código de acceso real en la cerradura especificada."""
    if not token or lock_id < 0:
        return {"keyboardPwd": "000000"} 

    url = f"{API_BASE_URL}/v3/keyboardPwd/get"
    
    fecha_inicio_limpia = start_time.replace(minute=0, second=0, microsecond=0)
    fecha_fin_limpia = end_time.replace(minute=0, second=0, microsecond=0)
    
    start_timestamp = int(fecha_inicio_limpia.timestamp() * 1000)
    end_timestamp = int(fecha_fin_limpia.timestamp() * 1000)

    params = {
        'clientId': client_id,
        'accessToken': token,
        'lockId': lock_id,
        'keyboardPwdVersion': 4,
        'keyboardPwdType': 3,
        'keyboardPwdName': f'Reserva {start_time.strftime("%d-%m %H:%M")}',
        'startDate': start_timestamp,
        'endDate': end_timestamp,
        'date': int(time.time() * 1000)
    }
    
    print(f"[TTLock Manager] Generando código REAL para la cerradura {lock_id}...")
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[TTLock Manager] Ocurrió un error al generar el código: {e}")
        print(f"[TTLock Manager] Respuesta de la API (si hubo): {e.response.text if e.response else 'Sin respuesta'}")
        return {'errcode': 9999, 'errmsg': 'Error de conexión con la API de TTLock.'}
