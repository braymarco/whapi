# Etapa 1: Construcción del binario
FROM golang:1.23-alpine AS builder

# Instala dependencias necesarias
RUN apk add --no-cache git sqlite sqlite-dev build-base

# Establece el directorio de trabajo
WORKDIR /app

# Copia los archivos del proyecto
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compila el binario (modo producción)
RUN go build -o whapi .

# Etapa 2: Imagen final ligera
FROM alpine:latest

# Instala dependencias necesarias para runtime
RUN apk add --no-cache sqlite

# Establece el directorio de trabajo
WORKDIR /app

# Copia el binario desde la etapa anterior
COPY --from=builder /app/whapi .
#COPY --from=builder /app/.env.example .env

# Copia certificados SSL opcionales
#COPY cert.pem key.pem ./

# Expone el puerto (modifícalo si tu API usa otro)
EXPOSE 8080

# Variables de entorno por defecto (pueden ser sobreescritas en docker run)
ENV SSL_ACTIVE=false
ENV ADDRESS_DB=sqlite3:./whapi.db
ENV SERVER_ADDRESS=:8080

# Comando para ejecutar el binario
CMD ["./whapi"]
