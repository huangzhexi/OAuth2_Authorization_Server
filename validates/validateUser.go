package validates

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
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

func NewUserStore(hostName string, dbUsername string, dbPassword string) *UserStore {
	u := &UserStore{hostName: hostName, dbUsername: dbUsername, dbPassword: dbPassword}
	u.dbSSLmode = "require"
	u.dbDatabaseName = "oauth"
	u.dbTableName = "oauthUser"
	u.saltSize = 16

	connStr := fmt.Sprintf("host= %s user=%s password=%s dbname=%s sslmode=%s",
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

func (u *UserStore) Validates(username string, password string) bool {
	//rows, err := u.db.Query(fmt.Sprintf("SELECT * FROM TABLE ( %s ) WHERE username = %s", u.dbTableName, username))
	rows, err := u.db.Query("SELECT * FROM \"oauthUser\" WHERE username= $1", username)

	if err != nil {
		log.Fatal(err)
		return false
	}
	//defer rows.Close()
	rows.Next()
	var hashPassword string
	var salt string
	if err := rows.Scan(&username, &hashPassword, &salt); err != nil {
		log.Fatal(err)
		return false
	}
	//encodedKey := base64.StdEncoding.EncodeToString(hashedPassword)
	decodedKey, err := base64.StdEncoding.DecodeString(hashPassword)
	if err != nil {
		log.Fatal(err)
		return false
	}
	return ComparePasswords(decodedKey, password, salt)
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
	//fmt.Println(len(hashPassword))
	//fmt.Println(hashPassword)
	//tableName := u.dbTableName
	fmt.Println(len(hashPassword))
	_, err = u.db.Exec("INSERT INTO \"oauthUser\"(username, password, salt, namestring) VALUES($1, $2, $3, $4)",
		username, hashPassword, salt, nameStr)
	if err != nil {
		return err
	}
	//defer func(db *sql.DB) {
	//	err := db.Close()
	//	if err != nil {
	//		return
	//	}
	//}(u.db)
	return nil
}
