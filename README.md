# whapi - Una API de WhatsApp Basada en Go
Es un proyecto realizado como hobby y como herramienta de ayuda.
Una API basada en whatsmeow Go para interactuar con WhatsApp, permitiéndote enviar y recibir mensajes programáticamente.

> **Advertencia**
>
> Usar este software infringiendo las Condiciones de Servicio de WhatsApp puede provocar la suspensión de tu número.
> Ten mucho cuidado: no lo uses para enviar spam ni nada similar. Úsalo bajo tu propia responsabilidad. Si necesitas desarrollar algo con fines comerciales, contacta con un proveedor de soluciones globales de WhatsApp y suscríbete a la API de WhatsApp Business.

## Características

- Conexión a WhatsApp mediante código QR.
- Envío de varios tipos de mensajes:
    - Mensajes de texto (individuales y grupales)
    - Imágenes
    - Audio
    - Documentos
    - Videos
- Gestión de múltiples dispositivos/sesiones de WhatsApp.
- Recepción de mensajes entrantes mediante webhooks.
- Soporte SSL para comunicación segura.

## Prerrequisitos

- [Go](https://golang.org/doc/install) (versión 1.24 o superior)
- [SQLite](https://www.sqlite.org/index.html)

## Instalación

1.  **Clona el repositorio:**
    ```bash
    git clone https://github.com/braymarco/whapi
    cd whapi
    ```

2.  **Instala las dependencias:**
    El proyecto utiliza módulos de Go. Las dependencias normalmente se descargan automáticamente cuando compilas (`go build`) o ejecutas (`go run .`) el proyecto. Para asegurar que todas las dependencias estén presentes y correctas, puedes ejecutar:
    ```bash
    go mod tidy
    ```

## Configuración

La API se configura mediante variables de entorno. Crea un archivo `.env` en el directorio raíz del proyecto copiando el archivo `.env.example`:

```bash
cp .env.example .env
```

Luego, edita el archivo `.env` con tus configuraciones deseadas:

-   `KEY`: Una clave secreta para autenticar las solicitudes a la API.
-   `ADDRESS_DB`: La cadena de conexión para la base de datos SQLite (ej., `sqlite3:./whapi.db` para un archivo llamado `whapi.db` en el directorio actual).
-   `SERVER_ADDRESS`: La dirección y el puerto en el que el servidor API escuchará (ej., `localhost:8080` o `:8080` para escuchar en todas las interfaces).
-   `SSL_ACTIVE`: Configura en `true` para habilitar HTTPS, o `false` para HTTP.
-   `WEBHOOK_ADDRESS`: La URL completa a la que se enviarán las notificaciones webhook para los mensajes entrantes (separadas por comas si son múltiples).
-   `WEBHOOK_SECRET`: Clave secreta para firmar las peticiones del webhook (HMAC SHA256).
-   `UP_DEVICES`: Configura en `true` para intentar reconectar automáticamente todos los dispositivos previamente autenticados cuando se inicia la API.
-   `AUTO_DOWNLOAD`: Configura en `true` para descargar automáticamente los archivos multimedia recibidos.
-   `OS_NAME`: Nombre del sistema operativo que aparecerá en la sesión de WhatsApp (por defecto "Windows").

## Endpoints de la API

Todos los endpoints protegidos de la API tienen el prefijo `/v1`. Las solicitudes a estos endpoints deben incluir un encabezado `Token` con el valor de la `KEY` especificada en tu archivo `.env`.

### Autenticación

Existe un `authMiddleware` que verifica el encabezado `Token` en todas las rutas `/v1`. Si el token falta o es inválido, se devuelve un error `401 Unauthorized`.

### General

-   `GET /`: Verificación básica del estado de la API.
    -   **Respuesta:**
        ```json
        {
          "status": "OK"
        }
        ```

### Gestión de Dispositivos

-   `GET /v1/login`
    -   **Descripción:** Inicia el proceso de inicio de sesión para un nuevo dispositivo. Genera un UUID de sesión y devuelve una imagen de código QR codificada en base64 para ser escaneada con WhatsApp.
    -   **Cuerpo (JSON):**
        ```json
        {
            "apiToken": "token_opcional"
        }
        ```
    -   **Respuestas:**
        -   `200 OK`:
            ```json
            {
              "uuid": "uuid-de-sesion",
              "qr": "<base64_encoded_qr_image>"
            }
            ```
        -   `500 Internal Server Error`: Error al conectar o generar QR.
        -   `504 Gateway Timeout`: Tiempo de espera agotado generando el QR.

-   `GET /v1/reconnect`
    -   **Descripción:** Reconecta una sesión existente.
    -   **Parámetros de Consulta:**
        -   `phone` (obligatorio): El número de teléfono (ID de usuario) para reconectar.
    -   **Respuestas:**
        -   `200 OK`:
            ```json
            {
              "data": "Device found - Start Client"
            }
            ```
        -   `404 Not Found`: Cliente no encontrado.
        -   `500 Internal Server Error`: Error al reconectar.

-   `GET /v1/device`
    -   **Descripción:** Obtiene información sobre un dispositivo específico.
    -   **Parámetros de Consulta:**
        -   `phone` (obligatorio): El número de teléfono del dispositivo.
    -   **Respuesta (`200 OK`):**
        ```json
        {
          "data": {
            "user": "1234567890", // Número de teléfono
            "pushName": "Tu Nombre de WhatsApp",
            "status": "ACTIVE" // o "INACTIVE"
          }
        }
        ```
    -   **Respuestas:**
        -   `404 Not Found`: Dispositivo no encontrado o inactivo (dependiendo del caso).

-   `GET /v1/devices`
    -   **Descripción:** Obtiene una lista de todos los dispositivos configurados.
    -   **Respuesta (`200 OK`):**
        ```json
        {
          "data": [
            {
              "user": "1234567890",
              "pushName": "NombreDispositivo1",
              "status": "ACTIVE"
            },
            ...
          ]
        }
        ```

### Mensajería

-   `POST /v1/messages`
    -   **Descripción:** Envía un mensaje. La solicitud debe ser `multipart/form-data`.
    -   **Datos del Formulario:**
        -   `from` (obligatorio): El número de teléfono del dispositivo remitente (debe ser un dispositivo con sesión iniciada).
        -   `to` (obligatorio): El número de teléfono del destinatario o ID del grupo.
        -   `type` (obligatorio): El tipo de mensaje. Tipos soportados: `text`, `group_text`, `image`, `audio`, `document`, `video`.
        -   `text` (opcional): El contenido de texto del mensaje o pie de foto para medios.
        -   `file` (opcional, obligatorio para tipos de medios): El archivo a enviar.
        -   `fileName` (opcional, para tipo `document`): El nombre del archivo del documento.
    -   **Respuesta (`200 OK`):**
        ```json
        {
          "data": { /* Objeto WhatsApp SendResponse */ },
          "message": "Mensaje Enviado"
        }
        ```

### Configuración del Entorno

-   `GET /v1/load_env`
    -   **Descripción:** Recarga las variables de entorno desde el archivo `.env`.

-   `GET /v1/env`
    -   **Descripción:** Recupera la configuración actual de los webhooks.

## Webhooks

Si se configura una `WEBHOOK_ADDRESS` en tu archivo `.env`, la API enviará solicitudes POST a esta URL cuando se reciba un nuevo mensaje. Las peticiones incluyen una firma HMAC SHA256 en el encabezado `X-Hub-Signature-256`.

**Ejemplo de Payload del Webhook:**
```json
{
  "deviceNumber": "1234567890", // El número del dispositivo conectado
  "event": "Message",
  "data": {
    "type": "TextMessage", // O ImageMessage, etc.
    "id": "ID_DEL_MENSAJE",
    "text": "Contenido del mensaje",
    "from": "1234567890@s.whatsapp.net",
    "to": "0987654321@s.whatsapp.net",
    "timestamp": "2023-10-27 10:00:00",
    "isFromMe": false,
    "media": null, // Objeto MediaContent si hay archivo
    "contact": {
        "id": "1234567890@s.whatsapp.net",
        "name": "Nombre Contacto",
        "pushName": "Nombre Público",
        "isFound": true
    },
    "chat": {
        "id": "1234567890@s.whatsapp.net",
        "name": "Nombre Chat",
        "isGroup": false
    },
    "repliedId": "",
    "isForwarded": false
  }
}
```

## Configuración SSL

Para habilitar HTTPS, configura `SSL_ACTIVE=true` en tu archivo `.env`. También necesitarás proporcionar los archivos `cert.pem` y `key.pem` en el directorio raíz del proyecto.

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
