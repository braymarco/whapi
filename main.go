package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"github.com/skip2/go-qrcode"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waCompanionReg"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
)

type MyClient struct {
	WAClient       *whatsmeow.Client
	eventHandlerID uint32
	nroQR          int
	tmpName        string
	WebhookURL     string
	ApiToken       string
	Status         string
}

func (mycli *MyClient) register() {
	mycli.eventHandlerID = mycli.WAClient.AddEventHandler(mycli.myEventHandler)
}
func postWebhook(url string, data []byte, signature string) error {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		msg := "Error al realizar new request: " + err.Error()

		return errors.New(msg)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hub-Signature-256", "sha256="+signature)

	client := &http.Client{}
	res, err := client.Do(req)

	if err != nil {
		msg := "Error al enviar webhook  . " + err.Error()

		return errors.New(msg)
	}
	if res.StatusCode != http.StatusOK {
		msg := "Error en el servidor al enviar webhook. Código: " + strconv.Itoa(res.StatusCode)

		return errors.New(msg)
	} else {

		return nil
	}
}
func sendWebhook(dataContent WebHook) {
	if len(webhook) > 0 {
		data, err := json.Marshal(dataContent)

		h := hmac.New(sha256.New, []byte(webhookKey))

		// 2. Escribir el cuerpo del mensaje (bytes) en el firmador
		h.Write(data)

		// 3. Obtener la firma en formato hexadecimal
		signature := hex.EncodeToString(h.Sum(nil))

		fmt.Println(string(data))
		if err != nil {
			msg := "Error al encodear  webhook. " + err.Error()

			color.Red(msg)
		} else {
			for _, url := range webhook {
				println(url)
				err := postWebhook(url, data, signature)
				if err != nil {
					color.Red(err.Error())
				} else {
					color.Green("Webhook enviado - Message")
				}
			}

		}
	}

}

type WebHook struct {
	DeviceNumber string      `json:"deviceNumber"`
	Event        string      `json:"event"`
	Content      interface{} `json:"data"`
}

type Message struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Text      string `json:"text"`
	From      string `json:"from"`
	To        string `json:"to"`
	Timestamp string `json:"timestamp"`
	IsFromMe  bool   `json:"isFromMe"`

	Media   *MediaContent `json:"media"`
	Contact *ContactData  `json:"contact"`

	Chat ChatInfo `json:"chat"`

	RepliedId     string `json:"repliedId"`
	IsForwarded   bool   `json:"isForwarded"`
	QuotedMessage string `json:"quotedMessage"`
}
type ChatInfo struct {
	ID      string `json:"id"`      // ID del chat (número o g.us)
	Name    string `json:"name"`    // Nombre del Grupo o del Contacto (si es privado)
	IsGroup bool   `json:"isGroup"` // Para saber si es grupo fácilmente en Laravel
}
type ContactData struct {
	ID       string `json:"id"`
	Name     string `json:"name"`         // Nombre como lo tienes agendado (FullName)
	PushName string `json:"pushName"`     // Nombre público que el usuario se puso
	Business string `json:"businessName"` // Nombre de empresa (si aplica)
	IsFound  bool   `json:"isFound"`      // ¿Lo tenemos en la agenda?
}
type MediaContent struct {
	Path     string `json:"path"`
	Caption  string `json:"caption"`
	MimeType string `json:"mimeType"`
	FileName string `json:"fileName"`
	FileSize string `json:"fileSize"`
}

func writeMedia(device string, chatUser string,
	dateFolder string, msgID string,
	mimeT string,
	data []byte) string {
	baseDir := filepath.Join("medias", device, chatUser, dateFolder)
	exts, _ := mime.ExtensionsByType(mimeT)
	ext := "bin"
	if len(exts) > 0 {
		ext = strings.TrimPrefix(exts[0], ".")
	}

	_ = os.MkdirAll(baseDir, 0755)

	filename := fmt.Sprintf("%s.%s", msgID, ext)
	fullpath := filepath.Join(baseDir, filename)

	_ = os.WriteFile(fullpath, data, 0644)
	fmt.Println("✅ Media guardado:", fullpath)
	return fullpath
}

func GetTextFromMessage(msg *waE2E.Message) string {
	if msg == nil {
		return ""
	}

	// 1. Texto Simple
	if msg.Conversation != nil {
		return *msg.Conversation
	}

	// 2. Texto Extendido (Menciones, respuestas, links)
	if msg.ExtendedTextMessage != nil && msg.ExtendedTextMessage.Text != nil {
		return *msg.ExtendedTextMessage.Text
	}

	// 3. Descripción de Imagen (Caption)
	if msg.ImageMessage != nil && msg.ImageMessage.Caption != nil {
		return *msg.ImageMessage.Caption
	}

	// 4. Descripción de Video (Caption)
	if msg.VideoMessage != nil && msg.VideoMessage.Caption != nil {
		return *msg.VideoMessage.Caption
	}

	// 5. Descripción de Documento (Caption)
	if msg.DocumentMessage != nil && msg.DocumentMessage.Caption != nil {
		return *msg.DocumentMessage.Caption
	}

	return "" // No se encontró texto (era un sticker, audio sin texto, etc.)
}

func (mycli *MyClient) eventReceiptHandler(v *events.Receipt) {
	println("Received a receipt")
	println(v.MessageIDs)
}
func (mycli *MyClient) eventMessageHandler(v *events.Message) {
	msg := v.Message
	if msg == nil {
		return
	}
	device := mycli.WAClient.Store.ID.User
	info := v.Info
	chatUser := info.Chat.User
	dateFolder := info.Timestamp.Format("2006-01-02")
	msgID := info.ID
	ctx := context.Background()

	// 1. Lógica de From/To (Routing)
	myJID := mycli.WAClient.Store.ID.ToNonAD().String()
	var fromJID, toJID string

	if info.IsFromMe {
		fromJID = myJID
		toJID = info.Chat.ToNonAD().String()
	} else {
		fromJID = info.Chat.ToNonAD().String()
		toJID = myJID
	}
	if fromJID == "status@broadcast" {
		return
	}

	var contactData *ContactData = nil
	if !info.IsFromMe {
		contactData = &ContactData{}
		senderJID := info.Sender
		contactData.ID = senderJID.ToNonAD().String()

		// Buscamos en la memoria local (Store)
		contact, err := mycli.WAClient.Store.Contacts.GetContact(ctx, senderJID)
		if err == nil && contact.Found {
			contactData.Name = contact.FullName
			contactData.PushName = contact.PushName
			contactData.Business = contact.BusinessName
			contactData.IsFound = true
		} else {
			contactData.PushName = info.PushName
			contactData.IsFound = false
		}
	}

	var chatInfo ChatInfo
	chatInfo.ID = info.Chat.ToNonAD().String()
	chatInfo.IsGroup = info.IsGroup

	if info.IsGroup {
		if groupInfo, err := mycli.WAClient.GetGroupInfo(ctx, info.Chat); err == nil {
			chatInfo.Name = groupInfo.Name
		} else {
			chatInfo.Name = info.Chat.User
		}
	} else {
		if contactData != nil && contactData.Name != "" {
			chatInfo.Name = contactData.Name
		} else if contactData != nil && contactData.PushName != "" {
			chatInfo.Name = contactData.PushName
		} else {
			chatInfo.Name = ""
		}
	}

	messageData := Message{
		ID:          msgID,
		From:        fromJID,
		To:          toJID,
		Timestamp:   info.Timestamp.Format("2006-01-02 15:04:05"),
		IsFromMe:    info.IsFromMe,
		Contact:     contactData,
		Chat:        chatInfo,
		IsForwarded: false,
	}

	handleMedia := func(downloadable whatsmeow.DownloadableMessage, mimeType string, contextInfo *waE2E.ContextInfo, caption *string, fileName string, fileLength uint64) bool {
		if !autoDownload {
			return true
		}
		data, err := mycli.WAClient.Download(ctx, downloadable)
		if err != nil {
			fmt.Println("Error descargando:", err)
			return false
		}

		fullPath := writeMedia(device, chatUser, dateFolder, msgID, mimeType, data)

		captionText := ""
		if caption != nil {
			captionText = *caption
		}

		if contextInfo != nil {
			messageData.RepliedId = contextInfo.GetStanzaID()
		}

		fileSizeStr := fmt.Sprintf("%d", fileLength)

		messageData.Media = &MediaContent{
			Path:     fullPath,
			Caption:  captionText,
			MimeType: mimeType,
			FileName: fileName,
			FileSize: fileSizeStr,
		}
		return true
	}

	var messageType string
	var text string
	if ext := msg.GetExtendedTextMessage(); ext != nil {
		messageType = "ExtendedMessage"
		text = *ext.Text
		if ctxInfo := ext.GetContextInfo(); ctxInfo != nil {
			messageData.IsForwarded = ctxInfo.GetIsForwarded()
			messageData.RepliedId = ctxInfo.GetStanzaID()
			messageData.QuotedMessage = GetTextFromMessage(ctxInfo.QuotedMessage)
		}

	} else if img := msg.GetImageMessage(); img != nil {
		messageType = "ImageMessage"
		ctxInfo := img.GetContextInfo()
		messageData.IsForwarded = ctxInfo.GetIsForwarded()
		if img.Caption != nil {
			text = *img.Caption
		}
		if !handleMedia(img, img.GetMimetype(), ctxInfo, img.Caption, "", img.GetFileLength()) {
			return
		}

	} else if audio := msg.GetAudioMessage(); audio != nil {
		messageType = "AudioMessage"

		ctxInfo := audio.GetContextInfo()

		messageData.IsForwarded = ctxInfo.GetIsForwarded()
		mimetype := audio.GetMimetype()
		if !handleMedia(audio, mimetype, ctxInfo, nil, "", audio.GetFileLength()) {
			return
		}

	} else if doc := msg.GetDocumentMessage(); doc != nil {
		messageType = "DocumentMessage"
		fName := doc.GetFileName()
		if fName == "" {
			fName = doc.GetTitle()
		}

		ctxInfo := doc.GetContextInfo()
		if doc.Caption != nil {
			text = *doc.Caption
		}
		messageData.IsForwarded = ctxInfo.GetIsForwarded()
		if !handleMedia(doc, doc.GetMimetype(), ctxInfo, doc.Caption, fName, doc.GetFileLength()) {
			return
		}

	} else if video := msg.GetVideoMessage(); video != nil {
		messageType = "VideoMessage"
		ctxInfo := video.GetContextInfo()
		if video.Caption != nil {
			text = *video.Caption
		}
		messageData.IsForwarded = ctxInfo.GetIsForwarded()
		if !handleMedia(video, video.GetMimetype(), ctxInfo, video.Caption, "", video.GetFileLength()) {
			return
		}

	} else if convo := msg.GetConversation(); len(convo) > 0 {
		messageType = "TextMessage"
		text = convo

	}
	messageData.Text = text
	if messageType != "" {
		messageData.Type = messageType
		deviceNumber := mycli.WAClient.Store.ID.User

		webHook := WebHook{
			DeviceNumber: deviceNumber,
			Event:        "Message",
			Content:      messageData,
		}
		sendWebhook(webHook)
	}
}
func (mycli *MyClient) myEventHandler(evt interface{}) {

	fmt.Println("Event: ")
	fmt.Println(reflect.TypeOf(evt))
	switch v := evt.(type) {
	case *events.Connected:
		fmt.Println("Connected: ", mycli.WAClient.Store.ID.User)
		break
	case *events.Message:
		mycli.eventMessageHandler(v)
		break
	case *events.Receipt:
		mycli.eventReceiptHandler(v)
		break
	case *events.HistorySync:
		mycli.eventHistorySyncHandler(v)
		break
	case *events.Disconnected:
		color.Red("Cliente desconectado!" + mycli.tmpName)
		/*err := container.DeleteDevice(mycli.WAClient.Store)
		if err != nil {
			println("Error al eliminar cliente")
		}*/
		break
	case *events.LoggedOut:
		color.Blue("Cliente LoggedOut!" + mycli.tmpName)
		clManager.Delete(mycli.tmpName)
		break
	case *events.QR:
		color.Blue("QR: " + mycli.tmpName)
		mycli.nroQR++
		if mycli.nroQR > 1 {
			color.Red("Segundo intento QR Code")
			mycli.WAClient.Disconnect()
			ctx := context.Background()
			err := container.DeleteDevice(ctx, mycli.WAClient.Store)
			if err != nil {
				color.Red("Error al eliminar Devices de container - QR: " + err.Error())
				return
			}
			clManager.Delete(mycli.tmpName)
		}
		break
	}
}

func (mycli *MyClient) eventHistorySyncHandler(v *events.HistorySync) {
	for _, conversation := range v.Data.Conversations {
		for _, message := range conversation.Messages {
			println(message)
		}
	}
}

var container = (*sqlstore.Container)(nil)

type ClientManager struct {
	clients map[string]*MyClient
	mu      sync.RWMutex
}

var clManager = ClientManager{
	clients: make(map[string]*MyClient),
}

func (cm *ClientManager) Add(id string, client *MyClient) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.clients[id] = client
}

func (cm *ClientManager) Get(id string) (*MyClient, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	client, ok := cm.clients[id]
	return client, ok
}

func (cm *ClientManager) Delete(id string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.clients, id)
}

var globalKey string
var webhookKey string
var webhook []string
var osName string
var upDevices bool
var autoDownload bool
var serverAddress string
var sslActive bool
var addressDB string

func dbInit() {
	println("Iniciando DB")
	dbLog := waLog.Stdout("Database", "DEBUG", true)
	// Make sure you add appropriate DB connector imports, e.g. github.com/mattn/go-sqlite3 for SQLite
	var err error
	ctx := context.Background()
	container, err = sqlstore.New(ctx, "sqlite3", addressDB, dbLog)
	if err != nil {
		panic(err)
	}
}

func initServer() {

	router := gin.Default()
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowCredentials = true
	config.AddAllowHeaders("token")
	router.Use(cors.New(config))

	router.GET("/", infoApi)
	v1 := router.Group("/v1", authMiddleware())
	{
		v1.GET("/login", login)
		v1.GET("/reconnect", reconnect)
		v1.GET("/load_env", loadEnv)
		v1.GET("/device", info)
		v1.GET("/env", envHandler)
		v1.GET("/devices", devices)
		v1.POST("/messages", sendMessage)
	}
	//err := router.Run(serverAddress)
	certFile := "cert.pem"
	keyFile := "key.pem"
	var err error
	if sslActive {
		err = router.RunTLS(serverAddress, certFile, keyFile)
	} else {
		err = router.Run(serverAddress)
	}

	if err != nil {
		println("Error al iniciar API")
		return
	}

}

type envData struct {
	Webhooks []string `json:"webhooks"`
}

func envHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": envData{
			Webhooks: webhook,
		},
	})
}
func loadEnv(c *gin.Context) {
	ok := env()
	if ok {
		c.JSON(http.StatusOK, gin.H{
			"data": "ok",
		})
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{
			"data": "Error al cargar variables de entorno",
		})
	}
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header["Token"]
		if len(token) == 0 || token[0] != globalKey {
			c.JSON(401, gin.H{
				"error": "Unauthorized",
			})
			c.Abort()
			return
		}

	}
}
func infoApi(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "OK",
	})
}
func env() bool {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}
	var ok bool
	globalKey, ok = os.LookupEnv("KEY")
	if !ok || len(globalKey) == 0 {
		log.Fatal("KEY in env not found")

	}

	addressDB, ok = os.LookupEnv("ADDRESS_DB")
	if !ok {
		log.Fatal("ADDRESS_DB in env not found")
	}
	serverAddress, ok = os.LookupEnv("SERVER_ADDRESS")
	if !ok {
		log.Fatal("SERVER_ADDRESS in env not found")
	}
	sslActiveTmp, ok := os.LookupEnv("SSL_ACTIVE")
	if !ok {
		sslActive = true
	} else {
		sslActive = sslActiveTmp == "true"
	}
	webhookKey, ok = os.LookupEnv("WEBHOOK_SECRET")
	if !ok {
		log.Fatal("WEBHOOK_SECRET in env not found")
	}
	webhookTmp, ok := os.LookupEnv("WEBHOOK_ADDRESS")
	if !ok {
		log.Fatal("WEBHOOK_ADDRESS in env not found")
	}
	if len(webhookTmp) > 0 {
		webhook = strings.Split(webhookTmp, ",")
	}
	osName, ok = os.LookupEnv("OS_NAME")
	if !ok {
		osName = ""
	}
	upTmp, ok := os.LookupEnv("UP_DEVICES")
	if !ok {
		log.Fatal("UP_DEVICES in env not found")
	} else {
		upDevices = upTmp == "true"
	}
	autoDownloadTmp, ok := os.LookupEnv("AUTO_DOWNLOAD")
	if !ok {
		autoDownload = false
	} else {
		autoDownload = autoDownloadTmp == "true"
	}
	println("Variables cargadas")
	return true

}

func upAllDevices() {
	color.Blue("Iniciando todos los dispositivos")
	ctx := context.Background()
	devicesStore, err := container.GetAllDevices(ctx)
	if err != nil {
		color.Red("No es posible obtener los dispositivos")
		panic(err)
	}
	for _, deviceStore := range devicesStore {
		client, err := loadClient(deviceStore)
		if client != nil {
			println("Cliente activo: " + client.WAClient.Store.ID.User)
		} else {
			if err != nil {
				println("Error al eliminar cliente: " + deviceStore.ID.User)
			} else {
				println("Device eliminado: " + deviceStore.ID.User)
			}
		}
	}
}
func main() {

	env()
	if len(osName) > 0 {
		store.DeviceProps.Os = &osName
	} else {
		store.DeviceProps.Os = proto.String("Windows")
		store.DeviceProps.PlatformType = waCompanionReg.DeviceProps_CHROME.Enum()
	}
	dbInit()
	if upDevices {
		upAllDevices()
	}
	initServer()
	println("Saliendo")
}

type MessageForm struct {
	From     string                `form:"from" json:"from" binding:"required"`
	To       string                `form:"to" json:"to" binding:"required"`
	Type     string                `form:"type" json:"type" binding:"required"`
	Text     string                `form:"text" json:"text"`
	File     *multipart.FileHeader `form:"file"`
	FileName string                `form:"fileName"`
}

func sendDocument(connection *MyClient, to string, textMessage string, files *multipart.FileHeader, fileName string) (*whatsmeow.SendResponse, error) {

	resp, mimetype, err := uploadFile(connection, files, whatsmeow.MediaDocument)
	if err != nil {
		println(err.Error())
		return nil, err
	}

	msg := &waE2E.Message{
		DocumentMessage: &waE2E.DocumentMessage{
			Mimetype:      &mimetype,
			Caption:       &textMessage,
			FileName:      &fileName,
			URL:           &resp.URL,
			DirectPath:    &resp.DirectPath,
			MediaKey:      resp.MediaKey,
			FileEncSHA256: resp.FileEncSHA256,
			FileSHA256:    resp.FileSHA256,
			FileLength:    &resp.FileLength,
		},
	}

	sendResponse, err := connection.WAClient.SendMessage(context.Background(), types.JID{
		User:   to,
		Server: types.DefaultUserServer,
	}, msg)

	if err != nil {
		println("Error al enviar un mensaje")
		return nil, err
	}

	//una vez enviado el texto lo borramos
	textMessage = ""
	return &sendResponse, nil
}
func uploadFile(connection *MyClient, files *multipart.FileHeader, mediaType whatsmeow.MediaType) (resp *whatsmeow.UploadResponse, mimetype string, err error) {
	file, erra := files.Open()
	if erra != nil {
		println("Error al abrir el archivo")
		return nil, "", erra
	}
	fileByte, erra := io.ReadAll(file)
	if erra != nil {
		println("Error al leer el archivo")
		return nil, "", erra
	}

	mimetype = files.Header.Get("Content-Type")

	a, err := connection.WAClient.Upload(context.Background(), fileByte, mediaType)
	if err != nil {
		return nil, "", err
	}
	return &a, mimetype, err
}
func sendImage(connection *MyClient, to string, textMessage string, files *multipart.FileHeader) (*whatsmeow.SendResponse, error) {

	resp, mimetype, err := uploadFile(connection, files, whatsmeow.MediaImage)
	if err != nil {
		println(err.Error())
		return nil, err
	}

	msg := &waE2E.Message{
		ImageMessage: &waE2E.ImageMessage{
			Mimetype:      &mimetype,
			Caption:       &textMessage,
			URL:           &resp.URL,
			DirectPath:    &resp.DirectPath,
			MediaKey:      resp.MediaKey,
			FileEncSHA256: resp.FileEncSHA256,
			FileSHA256:    resp.FileSHA256,
			FileLength:    &resp.FileLength,
		},
	}

	sendResponse, err := connection.WAClient.SendMessage(context.Background(), types.JID{
		User:   to,
		Server: types.DefaultUserServer,
	}, msg)

	if err != nil {
		println("Error al enviar un mensaje")
		return nil, err
	}

	//una vez enviado el texto lo borramos
	textMessage = ""
	return &sendResponse, nil
}
func sendAudio(connection *MyClient, to string, textMessage string, files *multipart.FileHeader) (*whatsmeow.SendResponse, error) {

	resp, mimetype, err := uploadFile(connection, files, whatsmeow.MediaAudio)
	if err != nil {
		println(err.Error())
		return nil, err
	}
	msg := &waE2E.Message{
		AudioMessage: &waE2E.AudioMessage{
			Mimetype: &mimetype,

			URL:           &resp.URL,
			DirectPath:    &resp.DirectPath,
			MediaKey:      resp.MediaKey,
			FileEncSHA256: resp.FileEncSHA256,
			FileSHA256:    resp.FileSHA256,
			FileLength:    &resp.FileLength,
		},
	}

	sendResponse, err := connection.WAClient.SendMessage(context.Background(), types.JID{
		User:   to,
		Server: types.DefaultUserServer,
	}, msg)

	if err != nil {
		println("Error al enviar un mensaje")
		return nil, err
	}

	//una vez enviado el texto lo borramos
	textMessage = ""
	return &sendResponse, nil
}
func sendVideo(connection *MyClient, to string, textMessage string, files *multipart.FileHeader) (*whatsmeow.SendResponse, error) {

	resp, mimetype, err := uploadFile(connection, files, whatsmeow.MediaVideo)
	if err != nil {
		println(err.Error())
		return nil, err
	}

	msg := &waE2E.Message{
		VideoMessage: &waE2E.VideoMessage{
			Mimetype: &mimetype,
			Caption:  &textMessage,

			URL:           &resp.URL,
			DirectPath:    &resp.DirectPath,
			MediaKey:      resp.MediaKey,
			FileEncSHA256: resp.FileEncSHA256,
			FileSHA256:    resp.FileSHA256,
			FileLength:    &resp.FileLength,
		},
	}

	sendResponse, err := connection.WAClient.SendMessage(context.Background(), types.JID{
		User:   to,
		Server: types.DefaultUserServer,
	}, msg)

	if err != nil {
		println("Error al enviar un mensaje")
		return nil, err
	}

	//una vez enviado el texto lo borramos
	textMessage = ""
	return &sendResponse, nil
}
func sendTextMessage(connection *MyClient, to string, textMessage string, isGroup bool) (*whatsmeow.SendResponse, error) {
	fmt.Println("Enviando: " + to)

	msg := &waE2E.Message{
		Conversation: proto.String(textMessage),
	}
	var jid types.JID
	var err error
	if strings.Contains(to, "@") {
		jid, err = types.ParseJID(to)
		if err != nil {
			return nil, err
		}
	} else {
		server := types.DefaultUserServer
		if isGroup {
			server = types.GroupServer
		}
		jid = types.JID{
			User:   to,
			Server: server,
		}

	}

	sendResponse, err := connection.WAClient.SendMessage(context.Background(), jid, msg)

	//dataErr, err := connection.Send(msg)
	if err != nil {
		fmt.Println("Error al enviar el mensaje " + err.Error())
		return nil, err
	}
	return &sendResponse, nil
}
func sendMessage(c *gin.Context) {
	var jsonForm MessageForm
	fmt.Println("messages method")
	//form, _ := c.MultipartForm()

	if err := c.ShouldBind(&jsonForm); err == nil {
		client, ok := clManager.Get(jsonForm.From)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"data": "", "message": "Cliente no encontrado"})
			return
		}

		err := c.Request.ParseMultipartForm(32 << 20)
		if err == nil {

			//verifica key y demás parámetros

			to := jsonForm.To
			typeMessage := jsonForm.Type
			textMessage := jsonForm.Text
			file := jsonForm.File
			var resM *whatsmeow.SendResponse
			switch typeMessage {
			case "group_text":
				//verifica el campo texto
				resM, err = sendTextMessage(client, to, textMessage, true)
				break
			case "text":
				//verifica el campo texto
				resM, err = sendTextMessage(client, to, textMessage, false)
				break
			case "image":
				resM, err = sendImage(client, to, textMessage, file)
				break
			case "audio":
				resM, err = sendAudio(client, to, textMessage, file)
				break
			case "document":
				if file != nil {
					fileName := jsonForm.FileName
					if len(fileName) == 0 {
						fileName = file.Filename
					}
					resM, err = sendDocument(client, to, textMessage, file, fileName)
				} else {
					resM = nil
					err = errors.New("file not found - nil")
				}

				break
			case "video":
				resM, err = sendVideo(client, to, textMessage, file)
				break
			default:
				resM = nil
				err = errors.New("type undefined")
				break
			}

			if err == nil {
				c.JSON(http.StatusOK, gin.H{"data": resM, "message": "Mensaje Enviado"})
				color.HiGreen("Mensaje Enviado")
			} else {
				color.Red("Error al enviar un mensaje: " + err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"data": resM, "message": err.Error()})

			}

		} else {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Error max memory - " + err.Error()})
		}

	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error params", "message": err.Error()})
	}
}

type LoginForm struct {
	ApiToken string `json:"apiToken"`
}

type InfoForm struct {
	Phone string `form:"phone" json:"phone" binding:"required"`
}

func reconnect(c *gin.Context) {
	var jsonForm InfoForm
	fmt.Println("reconnect method")
	if err := c.ShouldBind(&jsonForm); err == nil {
		fmt.Println(jsonForm.Phone)
		deviceStore, err := searchByUser(jsonForm.Phone)
		if deviceStore != nil {
			//inteta realiza la conexioón
			client, err := loadClient(deviceStore)
			if client != nil {
				c.JSON(http.StatusOK, gin.H{"data": "Device found - Start Client"})
			} else {
				if err != nil {
					println("Error al eliminar cliente")
					c.JSON(http.StatusInternalServerError, gin.H{"message": "Error al eliminar device sin ID"})
				} else {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "Reintentar login, device eliminado, phone remote" + jsonForm.Phone})

				}
			}
			return

		}
		c.JSON(http.StatusNotFound, gin.H{"data": "", "message": "Cliente no encontrado. " + err.Error()})
		return
	}
}

func info(c *gin.Context) {
	var jsonForm InfoForm
	fmt.Println("info method")
	if err := c.ShouldBind(&jsonForm); err == nil {
		fmt.Println(jsonForm.Phone)

		if _, ok := clManager.Get(jsonForm.Phone); !ok {
			//busca en el container
			deviceStore, err := searchByUser(jsonForm.Phone)
			if deviceStore != nil {
				c.JSON(http.StatusOK, gin.H{"data": DeviceJson{
					User:     deviceStore.ID.User,
					PushName: deviceStore.PushName,
					Status:   "INACTIVE",
				},
				})
				return

			}
			c.JSON(http.StatusNotFound, gin.H{"data": "", "message": "Cliente no encontrado. " + err.Error()})
			return
		}
		cl, _ := clManager.Get(jsonForm.Phone)
		c.JSON(http.StatusOK, gin.H{"data": DeviceJson{
			User:     cl.WAClient.Store.ID.User,
			PushName: cl.WAClient.Store.PushName,
			Status:   "ACTIVE",
		},
		})
		return
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error params", "message": err.Error()})
	}
}

type DeviceJson struct {
	User     string `json:"user"`
	PushName string `json:"pushName"`
	Status   string `json:"status"`
}

func devices(c *gin.Context) {
	fmt.Println("devices method")
	devicesData, err := container.GetAllDevices(c)
	if err != nil {
		println("Error al cargar all devices" + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error al cargar all devices. " + err.Error()})
		return
	}
	var r []DeviceJson
	for _, device := range devicesData {
		_, ok := clManager.Get(device.ID.User)
		status := "INACTIVE"
		if ok {
			status = "ACTIVE"
		}
		r = append(r, DeviceJson{
			User:     device.ID.User,
			PushName: device.PushName,
			Status:   status,
		})
	}
	c.JSON(http.StatusOK, gin.H{"data": r})

}

func loadClient(deviceStore *store.Device) (*MyClient, error) {
	clientLog := waLog.Stdout("Client", "DEBUG", true)
	clientS := whatsmeow.NewClient(deviceStore, clientLog)
	client := MyClient{WAClient: clientS}
	client.register()

	//valida sesión existente
	if client.WAClient.Store.ID == nil {
		println("Error Store.ID no encontrado eliminando cliente")
		ctx := context.Background()
		err := container.DeleteDevice(ctx, deviceStore)
		if err != nil {
			println("Error al eliminar cliente")
			return nil, err
		} else {
			return nil, nil
		}
	} else {
		// intenta conectar sesión no inicializada
		err := client.WAClient.Connect()
		if err != nil {
			return nil, err
		}
		client.tmpName = client.WAClient.Store.ID.User
		clManager.Add(client.WAClient.Store.ID.User, &client)
		fmt.Println("Cliente existente conectado")
		fmt.Println("USER: " + client.WAClient.Store.ID.User)
		return &client, nil
	}
}

/*
Devuelve nil si no existe un cliente junto a un error
*/
func searchByUser(user string) (*store.Device, error) {
	ctx := context.Background()
	devicesStore, err := container.GetAllDevices(ctx)
	if err != nil {
		return nil, err
	}
	for _, deviceStore := range devicesStore {

		if deviceStore.ID.User == user {
			return deviceStore, nil
		}
	}
	return nil, errors.New("dispositivo no encontrado")
}
func login(c *gin.Context) {
	var jsonForm LoginForm
	fmt.Println("Login method")
	if err := c.ShouldBind(&jsonForm); err == nil {
		sessionID := uuid.New().String()
		fmt.Println(sessionID)

		clientLog := waLog.Stdout("Client", "DEBUG", true)

		uuidSession := uuid.New().String()
		deviceStore := container.NewDevice()
		cli := whatsmeow.NewClient(deviceStore, clientLog)

		mClient := &MyClient{
			WAClient: cli,
			tmpName:  uuidSession,
			Status:   "WAITING_QR",
		}
		clManager.Add(uuidSession, mClient)
		qrCtx, cancelQR := context.WithCancel(context.Background())

		qrChan, _ := cli.GetQRChannel(qrCtx)
		if err := cli.Connect(); err != nil {
			cancelQR()
			cli.Disconnect()
			c.JSON(500, gin.H{"error": "Error al conectar con WhatsApp"})
			return
		}

		select {
		case evt := <-qrChan:
			if evt.Event == "code" {

				png, _ := qrcode.Encode(evt.Code, qrcode.Medium, 256)
				qrBase64 := base64.StdEncoding.EncodeToString(png)

				// Responder al cliente (El QR es válido por ~60 s)
				c.JSON(200, gin.H{
					"uuid": uuidSession,
					"qr":   qrBase64,
				})

				go oneShotMonitor(qrChan, cli, uuidSession, cancelQR)

				return
			} else {
				// Si el primer evento no es un código
				cancelQR()
				cli.Disconnect()
				clManager.Delete(uuidSession)
				c.JSON(500, gin.H{"error": "No se pudo obtener QR inicial"})
			}

		case <-time.After(10 * time.Second):
			// Timeout del servidor esperando generar el QR
			cancelQR()
			cli.Disconnect()
			clManager.Delete(uuidSession)
			c.JSON(504, gin.H{"error": "Timeout generando QR"})
		}

	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error params", "message": err.Error()})
	}
}

func oneShotMonitor(qrChan <-chan whatsmeow.QRChannelItem, cli *whatsmeow.Client, uuidSession string, cancelQR context.CancelFunc) {
	// Escuchamos lo que pase DESPUÉS de haber entregado el primer QR
	for evt := range qrChan {
		println("QR Channel Item1: " + evt.Event)
		switch evt.Event {
		case "success":
			fmt.Println("¡Éxito! Login completado para:", uuidSession)

			currentSession, _ := clManager.Get(uuidSession)
			clManager.Add(uuidSession, currentSession)
			clManager.Delete(uuidSession)

			return

		case "timeout":
			fmt.Println("Timeout en login:", uuidSession)
			cli.Disconnect()
			clManager.Delete(uuidSession)
			return

		case "code":
			fmt.Println("QR Cambiado:", uuidSession)
			cancelQR()
			cli.Disconnect()
			clManager.Delete(uuidSession)
			return
		default:
			println("Evento oneShotMonitor: ", evt.Event)
		}
	}
}
