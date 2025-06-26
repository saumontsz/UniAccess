# UniAccess - Sistema de Reserva de Salas Inteligentes

UniAccess es una aplicación web diseñada para la gestión y reserva de espacios de estudio y salas de reuniones en la Universidad Mayor. Integra cerraduras inteligentes TTLock para proporcionar un acceso seguro y sin llaves, y utiliza la autenticación de Microsoft para validar a los usuarios institucionales.

---

## Características Principales

* **Página de Inicio Profesional:** Landing page con descripción del proyecto, sección "Sobre Nosotros" y formulario de contacto.
* **Autenticación Segura:**
    * Inicio de sesión a través de **Microsoft Entra ID (Azure)**, restringido a dominios institucionales (`@mayor.cl` y `@umayor.cl`).
    * Login secundario con email/contraseña para cuentas de administrador.
    * Cierre de sesión completo que finaliza tanto la sesión local como la de Microsoft.
* **Sistema de Reservas Dinámico:**
    * Visualización de disponibilidad de salas para el día actual y el siguiente.
    * Interfaz de reserva por bloques de 1 hora, ocultando horarios pasados y mostrando los ocupados.
    * Confirmaciones de seguridad (JavaScript `confirm()`) antes de realizar o cancelar una reserva.
* **Gestión de Usuarios y Roles:**
    * Diferenciación entre **Estudiantes/Profesores** y **Administradores**.
    * Panel de administrador para crear nuevos usuarios autorizados.
* **Integración con API Real:**
    * Generación de códigos de acceso reales a través de la **API de TTLock**.
    * Manejo de errores y comunicación robusta con la API externa.
* **Diseño Responsivo:** Interfaz moderna construida con **Tailwind CSS** que se adapta a computadores, tabletas y celulares.
* **Seguridad:** Las credenciales y claves secretas se manejan de forma segura a través de variables de entorno (`.env`).

---

## Pila Tecnológica

* **Backend:** Python 3, Flask
* **Frontend:** HTML5, Tailwind CSS, JavaScript
* **Base de Datos:** SQLite (vía Flask-SQLAlchemy)
* **Autenticación:** Flask-Login, Flask-Bcrypt, Authlib (OAuth con Microsoft)
* **APIs Externas:** TTLock API
* **Envío de Correo:** Flask-Mail (con SendGrid o Gmail)

---

## Guía de Instalación y Entorno

Sigue estos pasos para levantar el proyecto en un entorno de desarrollo local.

### Prerrequisitos

* Python 3.10 o superior.
* `pip` (gestor de paquetes de Python).
* Un gestor de versiones como `git` (opcional pero recomendado).

### Pasos de Instalación

1.  **Clonar el repositorio:**
    ```bash
    git clone https://github.com/saumontsz/UniAccess.git
    cd UniAccess
    ```

2.  **Crear y activar un entorno virtual:**
    ```bash
    # Crear el entorno
    python -m venv venv

    # Activar en Windows
    venv\Scripts\activate

    # Activar en macOS/Linux
    source venv/bin/activate
    ```

3.  **Instalar las dependencias:**
    ```bash
    pip install -r requirements.txt
    ```

### Configuración

1.  En la raíz del proyecto, crea un archivo llamado `.env`.
2.  Copia y pega la siguiente estructura en tu archivo `.env` y rellena los valores con tus propias credenciales. **¡Este archivo nunca debe ser compartido!**

    ```env
    # Clave secreta de Flask para la seguridad de la sesión
    SECRET_KEY='TU_CLAVE_SECRETA_LARGA_Y_ALEATORIA'

    # Credenciales de la App de Microsoft Azure
    MICROSOFT_CLIENT_ID='TU_CLIENT_ID_DE_AZURE'
    MICROSOFT_CLIENT_SECRET='TU_CLIENT_SECRET_DE_AZURE'

    # Credenciales de la API de TTLock
    TTLOCK_CLIENT_ID='TU_CLIENT_ID_DE_TTLOCK'
    TTLOCK_CLIENT_SECRET='TU_CLIENT_SECRET_DE_TTLOCK'
    TTLOCK_USERNAME='EL_EMAIL_DE_TU_CUENTA_TTLOCK'
    TTLOCK_PASSWORD='LA_CONTRASEÑA_DE_TU_CUENTA_TTLOCK'

### Ejecución de la Aplicación

1.  **Inicializar la base de datos:**
    Este comando creará el archivo `reservas.db` y lo llenará con las salas de tu cuenta de TTLock.
    ```bash
    flask init-db
    ```

2.  **Crear una cuenta de administrador (Opcional):**
    ```bash
    flask shell
    >>> from app import db, Usuario
    >>> admin = Usuario(email='admin@mayor.cl', nombre='Admin', is_admin=True)
    >>> admin.set_password('tu-contraseña-segura')
    >>> db.session.add(admin)
    >>> db.session.commit()
    >>> exit()
    ```

3.  **Iniciar el servidor de desarrollo:**
    ```bash
    flask run
    ```
    La aplicación estará disponible en `http://127.0.0.1:5000`. Para verla desde tu celular, usa:
    ```bash
    flask run --host=0.0.0.0
    ```

---

## Autores

* **Sebastián Saumont**
* **Diego Parra**
* **Juan Baluarte**

