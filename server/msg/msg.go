package msg

import "time"

var MsgDB []*Msg

type Msg struct {
	Content  string `json:"content"`
	SendTime string `json:"send_time"`
	SendUser string `json:"send_user"`
}

func (m *Msg) SendMsg(content, sendUser string) *Msg {
	newMsg := &Msg{}
	newMsg.Content = content
	newMsg.SendUser = sendUser
	newMsg.SendTime = time.Now().Format("2006-01-02 15:04:05")

	MsgDB = append(MsgDB, newMsg)
	return newMsg
}
