package user

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"sync"
	"time"
)

var UserDB map[string]*User
var UserDBLock sync.RWMutex

func init() {
	UserDB = make(map[string]*User, 1000)
}

const randStr = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

type User struct {
	password      string
	salt          string
	Name          string
	RegisterTime  string
	LastLoginTime string
	Token         string
}

func (u *User) Logout() {
	u.Token = ""
}

func (u *User) FindUserByToken(token string) *User {
	for _, user := range UserDB {
		if user.Token == token {
			return user
		}
	}
	return nil
}

func (u *User) Login(name, password string) (*User, error) {
	UserDBLock.RLock()
	newUser, ok := UserDB[name]
	UserDBLock.RUnlock()

	if !ok {
		return nil, fmt.Errorf("用户名或者密码不正确")
	}
	if len(password) < 6 {
		return nil, fmt.Errorf("用户名或者密码不正确")
	}
	if newUser.password != Md5Str(password+newUser.salt) {
		return nil, fmt.Errorf("用户名或者密码不正确")
	}

	newUser.LastLoginTime = time.Now().Format("2006-01-02 15:04:05")
	newUser.Token = createToken()

	UserDBLock.Lock()
	UserDB[newUser.Name] = newUser
	UserDBLock.Unlock()
	return newUser, nil
}

func (u *User) Register(name, password string) (*User, error) {
	UserDBLock.RLock()
	_, ok := UserDB[name]
	UserDBLock.RUnlock()

	if ok {
		return nil, fmt.Errorf("用户名[%s]已经被注册过了", name)
	}
	if len(password) < 6 {
		return nil, fmt.Errorf("密码长度不符合要求.")
	}

	newUser := &User{}
	newUser.Name = name
	newUser.RegisterTime = time.Now().Format("2006-01-02 15:04:05")
	newUser.LastLoginTime = newUser.RegisterTime
	newUser.salt = strconv.Itoa(int(time.Now().Unix()))

	// 密码算法 md5(password+salt)
	newUser.password = Md5Str(password + newUser.salt)

	newUser.Token = createToken()

	UserDBLock.Lock()
	UserDB[newUser.Name] = newUser
	UserDBLock.Unlock()
	return newUser, nil
}

func Md5Str(str string) string {
	has := md5.Sum([]byte(str))
	return fmt.Sprintf("%x", has)
}

func createToken() string {
	strArr := []byte{}
	for i := 0; i < 32; i++ {
		index, _ := rand.Int(rand.Reader, big.NewInt(int64(len(randStr))))
		strArr = append(strArr, randStr[index.Int64()])
	}
	return string(strArr)
}
