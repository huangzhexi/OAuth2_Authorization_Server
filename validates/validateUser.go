package validates

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/huangzhexi/oauth2/errors"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/argon2"
	"log"
)

// var (
//
//	Err
//
// )

type UserStore struct {
	hostName       string
	dbUsername     string
	dbPassword     string
	dbDatabaseName string
	dbTableName    string
	dbSSLmode      string
	saltSize       int
	db             *sql.DB
	//dbName 	   string
}

var (
	ErrPasswordIncorrect = errors.New("Password is incorrect")
)

func NewUserStore(hostName string, dbUsername string, dbPassword string) *UserStore {
	u := &UserStore{hostName: hostName, dbUsername: dbUsername, dbPassword: dbPassword}
	u.dbSSLmode = "require"
	u.dbDatabaseName = "oauth"
	u.dbTableName = "oauthUser"
	u.saltSize = 16

	connStr := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=%s",
		u.hostName, u.dbUsername, u.dbPassword, u.dbDatabaseName, u.dbSSLmode)
	//connStr := "user= password= dbname= sslmode=require"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	u.db = db
	//defer func(db *sql.DB) {
	//	err := db.Close()
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//}(db)
	return u
}

func generateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}

	return string(bytes), nil
}
func HashPassword(password, salt string) (string, error) {
	time := uint32(1)           // 迭代次数
	memory := uint32(64 * 1024) // 内存使用量（以字节为单位）
	threads := uint8(4)         // 并行线程数
	keyLen := uint32(32)        // 输出密钥长度为 32 字节
	hashedPassword := argon2.IDKey([]byte(password), []byte(salt), time, memory, threads, keyLen)
	encodedKey := base64.StdEncoding.EncodeToString(hashedPassword)
	return encodedKey, nil
}
func ComparePasswords(byteHashedPassword []byte, password, salt string) bool {
	time := uint32(1)           // 迭代次数
	memory := uint32(64 * 1024) // 内存使用量（以字节为单位）
	threads := uint8(4)         // 并行线程数
	keyLen := uint32(32)        // 输出密钥长度为 32 字节
	derivedKey := argon2.IDKey([]byte(password), []byte(salt), time, memory, threads, keyLen)
	return subtle.ConstantTimeCompare(byteHashedPassword, derivedKey) == 1
}

//func (u *UserStore) ModifyUserName(username string, password string, userNameString string) {
//
//}

func (u *UserStore) ModifyPassword(username string, password string, newPassword string) error {
	_, isCorrect, err := u.Validates(username, password)
	if err != nil {
		return err
	}
	if !isCorrect {
		return ErrPasswordIncorrect
	}
	salt, err := generateRandomString(u.saltSize)
	if err != nil {
		return err
	}
	hashPassword, err := HashPassword(password, salt)
	if err != nil {
		return err
	}
	_, err = u.db.Query("UPDATE \"oauthUser\" SET password=$1 salt=$2 WHERE username=$3", hashPassword, salt, username)
	if err != nil {
		return err
	}
	return nil
}
func (u *UserStore) Validates(username string, password string) (string, bool, error) {
	//rows, err := u.db.Query(fmt.Sprintf("SELECT * FROM TABLE ( %s ) WHERE username = %s", u.dbTableName, username))
	rows, err := u.db.Query("SELECT * FROM \"oauthUser\" WHERE username= $1", username)

	if err != nil {
		log.Fatal(err)
		return "", false, err
	}

	//defer rows.Close()
	if !rows.Next() {
		return "", false, err
	}
	var hashPassword string
	var salt string
	var name string
	if err := rows.Scan(&username, &hashPassword, &salt, &name); err != nil {
		log.Fatal(err)
		return "", false, err
	}
	//encodedKey := base64.StdEncoding.EncodeToString(hashedPassword)
	decodedKey, err := base64.StdEncoding.DecodeString(hashPassword)
	if err != nil {
		log.Fatal(err)
		return "", false, err
	}
	if !ComparePasswords(decodedKey, password, salt) {
		return "", false, nil
	}
	return name, true, nil
	//return false
}

func (u *UserStore) Store(username string, password string, nameStr ...string) error {
	salt, err := generateRandomString(u.saltSize)
	if err != nil {
		return err
	}
	hashPassword, err := HashPassword(password, salt)
	if err != nil {
		return err
	}
	fmt.Println(len(hashPassword))
	_, err = u.db.Exec("INSERT INTO \"oauthUser\"(username, password, salt, namestring) VALUES($1, $2, $3, $4)",
		username, hashPassword, salt, nameStr)
	if err != nil {
		return err
	}

	return nil
}
