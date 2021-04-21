package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"server/msg"
	"server/user"
)

type commonResponse struct {
	Code   int         `json:"code"`
	ErrMsg string      `json:"err_msg"`
	Data   interface{} `json:"data"`
}

type registerRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type msgRequest struct {
	Content string `json:"content"`
}

var clientConn map[string]chan *msg.Msg
var clientConnLock sync.RWMutex

func init() {
	clientConn = make(map[string]chan *msg.Msg, 1000)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/register", register)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/logout", logout)
	mux.HandleFunc("/send/msg", sendMsg)
	mux.HandleFunc("/msg", getMsg)
	mux.HandleFunc("/watch/msg", watchMsg)
	err := http.ListenAndServe("127.0.0.1:8888", mux)
	if err != nil {
		fmt.Println("ListenAndServe err:", err)
	}
}

func preCors(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Access-Control-Allow-Methods", "*")
	writer.Header().Set("Access-Control-Allow-Headers", "*")
	if request.Method == "OPTIONS" {
		writer.WriteHeader(http.StatusOK)
	}
}

func health(writer http.ResponseWriter, request *http.Request) {
	preCors(writer, request)
	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte("ok"))
}

func watchMsg(writer http.ResponseWriter, request *http.Request) {
	preCors(writer, request)

	response := &commonResponse{}
	if request.Method != "GET" {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = "请求方式不对"
		writer.WriteHeader(response.Code)
		data, _ := json.Marshal(response)
		writer.Write(data)
		return
	}

	// 验证用户是否登录
	token := request.Header.Get("token")
	loginUser := &user.User{}
	newUser := loginUser.FindUserByToken(token)
	if newUser == nil {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = "请求的token未授权"
		data, _ := json.Marshal(response)
		writer.Write(data)
		return
	}

	// 判断客户端是否支持http.Flusher
	flusher, ok := writer.(http.Flusher)
	if !ok {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = "客户端不支持http.Flusher"
		data, _ := json.Marshal(response)
		writer.Write(data)
		return
	}

	// 注册客户端消息队列 key md5(用户名)-当时时间戳-随机数
	key := fmt.Sprintf("%s-%d-%d", user.Md5Str(loginUser.Name), time.Now().Unix(), rand.Int())
	msgChan := make(chan *msg.Msg, 1000)
	clientConnLock.Lock()
	clientConn[key] = msgChan
	clientConnLock.Unlock()

	// 告诉客户端 当前连接是chunked
	writer.Header().Set("Transfer-Encoding", "chunked")
	writer.WriteHeader(http.StatusOK)

	// 监听消息的变化 且实时推送信息给客户端
	for {
		select {
		case msg, ok := <-msgChan:
			if ok {
				data, _ := json.Marshal(msg)
				writer.Write(data)
				writer.Write([]byte{'\n'})
				flusher.Flush()
			}
		case <-request.Context().Done():
			clientConnLock.Lock()
			delete(clientConn, key)
			clientConnLock.Unlock()
		}
	}
}

func getMsg(writer http.ResponseWriter, request *http.Request) {
	preCors(writer, request)
	response := &commonResponse{}
	defer func() {
		data, _ := json.Marshal(response)
		writer.WriteHeader(response.Code)
		writer.Write(data)
	}()

	if request.Method != "GET" {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = "请求方式不对"
		return
	}

	// 身份校验
	token := request.Header.Get("token")
	user := &user.User{}
	newUser := user.FindUserByToken(token)
	if newUser == nil {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = "请求的token未授权"
		return
	}

	// 获取聊天消息列表
	response.Code = http.StatusOK
	if len(msg.MsgDB) < 20 {
		response.Data = msg.MsgDB
		return
	}
	response.Data = msg.MsgDB[len(msg.MsgDB)-20:]
}

func sendMsg(writer http.ResponseWriter, request *http.Request) {
	preCors(writer, request)
	response := &commonResponse{}
	defer func() {
		data, _ := json.Marshal(response)
		writer.WriteHeader(response.Code)
		writer.Write(data)
	}()

	if request.Method != "POST" {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = "请求方式不对"
		return
	}

	resByte, err := ioutil.ReadAll(request.Body)
	if err != nil {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = err.Error()
		return
	}

	var paramRequest msgRequest
	err = json.Unmarshal(resByte, &paramRequest)
	if err != nil {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = err.Error()
		return
	}

	// 身份校验
	token := request.Header.Get("token")
	user := &user.User{}
	newUser := user.FindUserByToken(token)
	if newUser == nil {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = "请求的token未授权"
		return
	}

	// 发送消息的逻辑
	msg := &msg.Msg{}
	newMsg := msg.SendMsg(paramRequest.Content, newUser.Name)

	// 分发消息给每一个客户端连接
	clientConnLock.RLock()
	for _, msgChan := range clientConn {
		msgChan <- newMsg
	}
	clientConnLock.RUnlock()

	response.Code = http.StatusCreated
	response.Data = map[string]string{
		"content":   newMsg.Content,
		"send_time": newMsg.SendTime,
		"send_user": newMsg.SendUser,
	}
}

func logout(writer http.ResponseWriter, request *http.Request) {
	preCors(writer, request)
	response := &commonResponse{}
	defer func() {
		data, _ := json.Marshal(response)
		writer.WriteHeader(response.Code)
		writer.Write(data)
	}()

	if request.Method != "DELETE" {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = "请求方式不对"
		return
	}

	token := request.Header.Get("token")
	user := &user.User{}
	newUser := user.FindUserByToken(token)
	if newUser == nil {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = "请求的token未授权"
		return
	}
	newUser.Logout()

	response.Code = http.StatusNoContent
}

func login(writer http.ResponseWriter, request *http.Request) {
	preCors(writer, request)
	response := &commonResponse{}
	defer func() {
		data, _ := json.Marshal(response)
		writer.WriteHeader(response.Code)
		writer.Write(data)
	}()

	if request.Method != "POST" {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = "请求方式不对"
		return
	}

	resByte, err := ioutil.ReadAll(request.Body)
	if err != nil {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = err.Error()
		return
	}

	var paramRequest registerRequest
	err = json.Unmarshal(resByte, &paramRequest)
	if err != nil {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = err.Error()
		return
	}

	// 用户登录
	user := &user.User{}
	newUser, err := user.Login(paramRequest.Name, paramRequest.Password)
	if err != nil {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = err.Error()
		return
	}

	response.Code = http.StatusCreated
	response.Data = map[string]string{
		"lastLogin_time": newUser.LastLoginTime,
		"name":           newUser.Name,
		"register_time":  newUser.RegisterTime,
		"token":          newUser.Token,
	}
}

func register(writer http.ResponseWriter, request *http.Request) {
	preCors(writer, request)
	response := &commonResponse{}
	defer func() {
		data, _ := json.Marshal(response)
		writer.WriteHeader(response.Code)
		writer.Write(data)
	}()

	if request.Method != "POST" {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = "请求方式不对"
		return
	}

	resByte, err := ioutil.ReadAll(request.Body)
	if err != nil {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = err.Error()
		return
	}

	var paramRequest registerRequest
	err = json.Unmarshal(resByte, &paramRequest)
	if err != nil {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = err.Error()
		return
	}

	// 注册用户
	user := &user.User{}
	newUser, err := user.Register(paramRequest.Name, paramRequest.Password)
	if err != nil {
		response.Code = http.StatusInternalServerError
		response.ErrMsg = err.Error()
		return
	}

	response.Code = http.StatusCreated
	response.Data = map[string]string{
		"lastLogin_time": newUser.LastLoginTime,
		"name":           newUser.Name,
		"register_time":  newUser.RegisterTime,
		"token":          newUser.Token,
	}
}
