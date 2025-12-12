# whapi - A Go-based WhatsApp API
It is a project done as a hobby and as a helpful tool.
A Go-based API based in whatsmeow for interacting with WhatsApp, allowing you to send and receive messages programmatically.

> **Warning**
>
> Using this software in violation of WhatsApp's Terms of Service may result in your number being suspended.
> Be very careful: do not use it to send spam or anything similar. Use it at your own risk. If you need to develop something for commercial purposes, contact a global WhatsApp solutions provider and subscribe to the WhatsApp Business API.

## Features

- Connect to WhatsApp using QR code login.
- Send various message types:
    - Text messages (individual and group)
    - Images
    - Audio
    - Documents
    - Videos
- Manage multiple WhatsApp devices/sessions.
- Receive incoming messages via webhooks.
- SSL support for secure communication.

## Prerequisites

- [Go](https://golang.org/doc/install) (version 1.24 or higher)
- [SQLite](https://www.sqlite.org/index.html)

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/braymarco/whapi
   cd whapi
   ```

2. **Install dependencies:**
   The project uses Go modules. Dependencies are typically downloaded automatically when you build (`go build`) or run (`go run .`) the project. To ensure all dependencies are present and correct, you can run:
   ```bash
   go mod tidy
   ```

## Configuration

The API is configured using environment variables. Create a `.env` file in the project's root directory by copying the `.env.example` file:

```bash
cp .env.example .env
```

Then, edit the `.env` file with your desired settings:

- `KEY`: A secret key for authenticating API requests.
- `ADDRESS_DB`: The connection string for the SQLite database (e.g., `sqlite3:./whapi.db` for a file named `whapi.db` in the current directory).
- `SERVER_ADDRESS`: The address and port on which the API server will listen (e.g., `localhost:8080` or `:8080` to listen on all interfaces).
- `SSL_ACTIVE`: Set to `true` to enable HTTPS, or `false` for HTTP.
- `WEBHOOK_ADDRESS`: The full URL to which webhook notifications for incoming messages will be sent (comma-separated if multiple).
- `WEBHOOK_SECRET`: Secret key for signing webhook requests (HMAC SHA256).
- `UP_DEVICES`: Set to `true` to attempt to automatically reconnect all previously authenticated devices when the API starts.
- `AUTO_DOWNLOAD`: Set to `true` to automatically download received media files.
- `OS_NAME`: Operating system name to be displayed in the WhatsApp session (default "Windows").

## API Endpoints

All protected API endpoints are prefixed with `/v1`. Requests to these endpoints must include a `Token` header with the value of the `KEY` specified in your `.env` file.

### Authentication

An `authMiddleware` is in place, which checks for the `Token` header in all `/v1` routes. If the token is missing or invalid, a `401 Unauthorized` error is returned.

### General

- `GET /`: Basic API status check.
  - **Response:**
    ```json
    {
      "status": "OK"
    }
    ```

### Device Management

- `GET /v1/login`
  - **Description:** Initiates the login process for a new device. Generates a session UUID and returns a base64 encoded QR code image to be scanned with WhatsApp.
  - **Body (JSON):**
    ```json
    {
        "apiToken": "optional_token"
    }
    ```
  - **Responses:**
    - `200 OK`:
      ```json
      {
        "uuid": "session-uuid",
        "qr": "<base64_encoded_qr_image>"
      }
      ```
    - `500 Internal Server Error`: Error connecting or generating QR.
    - `504 Gateway Timeout`: Timeout generating QR.

- `GET /v1/reconnect`
  - **Description:** Reconnects an existing session.
  - **Query Parameters:**
    - `phone` (required): The phone number (user ID) to reconnect.
  - **Responses:**
    - `200 OK`:
      ```json
      {
        "data": "Device found - Start Client"
      }
      ```
    - `404 Not Found`: Client not found.
    - `500 Internal Server Error`: Error reconnecting.

- `GET /v1/device`
  - **Description:** Get information about a specific device.
  - **Query Parameters:**
    - `phone` (required): The phone number of the device.
  - **Response (`200 OK`):**
    ```json
    {
      "data": {
        "user": "1234567890", // Phone number
        "pushName": "Your WhatsApp Name",
        "status": "ACTIVE" // or "INACTIVE"
      }
    }
    ```
  - **Responses:**
    - `404 Not Found`: Device not found.

- `GET /v1/devices`
  - **Description:** Get a list of all configured devices.
  - **Response (`200 OK`):**
    ```json
    {
      "data": [
        {
          "user": "1234567890",
          "pushName": "Device1 Name",
          "status": "ACTIVE"
        },
        ...
      ]
    }
    ```

### Messaging

- `POST /v1/messages`
  - **Description:** Sends a message. The request should be `multipart/form-data`.
  - **Form Data:**
    - `from` (required): The phone number of the sender device (must be a logged-in device).
    - `to` (required): The recipient's phone number or group ID.
    - `type` (required): The type of message. Supported types: `text`, `group_text`, `image`, `audio`, `document`, `video`.
    - `text` (optional): The text content of the message or caption for media.
    - `file` (optional, required for media types): The file to be sent.
    - `fileName` (optional, for `document` type): The name of the document file.
  - **Response (`200 OK`):**
    ```json
    {
      "data": { /* WhatsApp SendResponse object */ },
      "message": "Mensaje Enviado" // "Message Sent"
    }
    ```

### Environment Configuration

- `GET /v1/load_env`
  - **Description:** Reloads environment variables from the `.env` file.

- `GET /v1/env`
  - **Description:** Retrieves current webhook configuration.

## Webhooks

If a `WEBHOOK_ADDRESS` is configured in your `.env` file, the API will send POST requests to this URL when a new message is received. Requests include an HMAC SHA256 signature in the `X-Hub-Signature-256` header.

**Webhook Payload Example:**
```json
{
  "deviceNumber": "1234567890", // The number of the connected device
  "event": "Message",
  "data": {
    "type": "TextMessage", // Or ImageMessage, etc.
    "id": "MESSAGE_ID",
    "text": "Message content",
    "from": "1234567890@s.whatsapp.net",
    "to": "0987654321@s.whatsapp.net",
    "timestamp": "2023-10-27 10:00:00",
    "isFromMe": false,
    "media": null, // MediaContent object if there is a file
    "contact": {
        "id": "1234567890@s.whatsapp.net",
        "name": "Contact Name",
        "pushName": "Public Name",
        "isFound": true
    },
    "chat": {
        "id": "1234567890@s.whatsapp.net",
        "name": "Chat Name",
        "isGroup": false
    },
    "repliedId": "",
    "isForwarded": false
  }
}
```

## SSL Configuration

To enable HTTPS, set `SSL_ACTIVE=true` in your `.env` file. You will also need to provide `cert.pem` and `key.pem` files in the root directory of the project.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
