package store

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-session/session"
	"io"
	"net/http"
	//"io/ioutil"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/huangzhexi/oauth2/models"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/argon2"
	"log"
	"os"
)

var (
	ErrFileHandleError      = errors.New("file Parser Error")
	ErrPasswordIncorrect    = errors.New("password is incorrect")
	ErrSqlCannotEstablished = errors.New("sql cannot established")
	ErrNoSuchUser           = errors.New("no such user")
)

type AuthUserStore struct {
	saltSize            int
	DbDatabaseName      string `json:"dbDatabaseName,omitempty"`
	DbWebAuthnTableName string `json:"dbWebAuthnTableName,omitempty"`
	DbTableName         string `json:"dbTableName,omitempty"`
	db                  *sql.DB
	webauthn            *webauthn.WebAuthn
}
type UserConfFile struct {
	Name                string `json:"name,omitempty"`
	HostName            string `json:"hostName,omitempty"`
	DbUsername          string `json:"dbUsername,omitempty"`
	DbPassword          string `json:"dbPassword,omitempty"`
	DbDatabaseName      string `json:"dbDatabaseName,omitempty"`
	DbWebAuthnTableName string `json:"dbWebAuthnTableName,omitempty"`
	DbTableName         string `json:"dbTableName,omitempty"`
	DbSSLmode           string `json:"dbSSLmode,omitempty"`
}

type ClientUser struct {
	Username string `json:"username,omitempty"`
}

func NewDefaultAuthUserStore(path string) (u *AuthUserStore, e error) {
	if path == "" {
		path = "user.json"
	}
	jsonFile, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)

	var data UserConfFile
	err = json.Unmarshal(byteValue, &data)
	if err != nil {
		return nil, ErrFileHandleError
	}
	connStr := fmt.Sprintf("host= %s user=%s password=%s dbname=%s sslmode=%s",
		data.HostName, data.DbUsername, data.DbPassword, data.DbDatabaseName, data.DbSSLmode)
	fmt.Println(connStr)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	if db == nil {
		return nil, ErrSqlCannotEstablished
	}

	wconfig := &webauthn.Config{

		RPDisplayName: "CHD Oauth",                                                                    // Display Name for your site
		RPID:          "localhost",                                                                    // Generally the FQDN for your site
		RPOrigins:     []string{"http://localhost", "http://localhost:3001", "http://localhost:9096"}, // The origin URLs allowed for WebAuthn requests
		//Timeouts: webauthn.TimeoutsConfig{
		//	Login: webauthn.TimeoutConfig{
		//		Enforce:    true,             // Require the response from the client comes before the end of the timeout.
		//		Timeout:    time.Second * 60, // Standard timeout for login sessions.
		//		TimeoutUVD: time.Second * 60, // Timeout for login sessions which have user verification set to discouraged.
		//	},
		//	Registration: webauthn.TimeoutConfig{
		//		Enforce:    true,             // Require the response from the client comes before the end of the timeout.
		//		Timeout:    time.Second * 60, // Standard timeout for registration sessions.
		//		TimeoutUVD: time.Second * 60, // Timeout for login sessions which have user verification set to discouraged.
		//	},
		//},
	}
	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		fmt.Println(err)
	}
	u = &AuthUserStore{}
	u.db = db
	u.webauthn = webAuthn
	u.DbDatabaseName = data.DbDatabaseName
	u.DbTableName = data.DbTableName
	u.DbWebAuthnTableName = data.DbWebAuthnTableName
	return u, nil
}

//func NewAuthUserStore(hostName, dbUsername, dbPassword, dbDatabaseName, dbSSLMode string) (u *AuthUserStore) {
//	u.dbSSLmode = "require"
//	u.dbDatabaseName = "oauth"
//	u.dbTableName = "oauthUser"
//	u.saltSize = 16
//
//	connStr := fmt.Sprintf("host= %s user=%s password=%s dbname=%s sslmode=%s",
//		hostName, dbUsername, dbPassword, dbDatabaseName, dbSSLMode)
//	//connStr := "user= password= dbname= sslmode=require"
//	db, err := sql.Open("postgres", connStr)
//	if err != nil {
//		log.Fatal(err)
//		return nil
//	}
//	u.db = db
//	return u
//}

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

func (u *AuthUserStore) FindName(username string) (string, error) {
	rows, err := u.db.Query("SELECT * FROM \"oauthUser\" WHERE username= $1", username)
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	if !rows.Next() {
		return "", err
	}
	var hashPassword string
	var salt string
	var name string
	if err := rows.Scan(&username, &hashPassword, &salt, &name); err != nil {
		log.Fatal(err)
		return "", err
	}
	return name, nil
}

func (u *AuthUserStore) ModifyPassword(username string, password string, newPassword string) error {
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
func (u *AuthUserStore) Validates(username string, password string) (string, bool, error) {
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
func (u *AuthUserStore) Store(username string, password string, nameStr ...string) error {
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

func JSONResponse(w http.ResponseWriter, data interface{}, statusCode int) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(data)
	w.WriteHeader(statusCode)
	return nil
}

//func getUser() {
//	var formdata ClientUser
//	err = json.NewDecoder(r.Body).Decode(&formdata)
//}

// username is like 210012 id.
func (u *AuthUserStore) getWebauthnUser(username string) (webauthn.User, error) {
	rows, err := u.db.Query("SELECT * FROM \"oauthUser\" WHERE username= $1", username)

	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	//defer rows.Close()
	if !rows.Next() {
		return nil, ErrNoSuchUser
	}
	var hashPassword string
	var salt string
	var name string
	if err := rows.Scan(&username, &hashPassword, &salt, &name); err != nil {
		log.Fatal(err)
		return nil, err
	}

	authRow, err := u.db.Query("SELECT * FROM \"webauthnUser\" WHERE username= $1", username)

	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	//defer rows.Close()
	if !authRow.Next() {
		//create user
		var length int = 64
		bytes := make([]byte, length)
		_, err := rand.Read(bytes)
		if err != nil {
			return nil, err
		}
		_, err = u.db.Exec("INSERT INTO \"webauthnUser\"(username, authid) VALUES($1, $2)",
			username, bytes)
		if err != nil {
			return nil, err
		}
		var user models.WebAuthnUser
		user.SetCredentials(make([]webauthn.Credential, 0))
		user.SetName(username)
		user.SetId([]byte(username))
		user.SetDisplayName(name)
		return user, nil

	}

	var id []byte
	var credentials models.CredentialsStruct
	var scanJson []byte
	if err := authRow.Scan(&username, &id, &scanJson); err != nil {
		log.Fatal(err)
		return nil, err
	}
	//if scanJson == nil {
	//
	//}
	err = json.Unmarshal(scanJson, &credentials)

	var user models.WebAuthnUser
	user.SetCredentials(credentials.Data)
	user.SetName(username)
	user.SetId(id)
	user.SetDisplayName(name)
	return user, nil
}

func (u *AuthUserStore) saveUser(user *models.WebAuthnUser) error {
	var credentials models.CredentialsStruct
	credentials.Data = user.WebAuthnCredentials()
	fmt.Println("Credential Data:")
	fmt.Println(credentials.Data)
	credentialsJson, err := json.Marshal(credentials)
	if err != nil {
		return err
	}
	//pq: syntax error at or near "credentials"
	////sql: converting argument $2 type: unsupported type []webauthn.Credential, a slice of struct
	_, err = u.db.Query("UPDATE \"webauthnUser\" SET authid=$1, credentials=$2 WHERE username=$3",
		user.WebAuthnID(), credentialsJson, user.WebAuthnName())
	if err != nil {
		return err
	}
	return nil
}

func (u *AuthUserStore) BeginRegistration(w http.ResponseWriter, r *http.Request, username string) error {
	//var clientUser ClientUser
	////err := json.NewDecoder(r.Body).Decode(&clientUser)
	////if err != nil {
	////	return err
	////}
	//clientUser.Username = username
	//var user webauthn.User
	user, err := u.getWebauthnUser(username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}
	//user := datastore.GetUser() // Find or create the new user
	options, sessionData, err := u.webauthn.BeginRegistration(user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	// handle errors if present
	// store the sessionData values
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}
	store.Set("webauthnData", sessionData)
	store.Set("webauthnUser", user)
	err = store.Save()
	if err != nil {
		return err
	}
	//sStore.
	err = JSONResponse(w, options, http.StatusOK)
	if err != nil {
		return err
	} // return the options generated
	// options.publicKey contain our registration options
	return nil
}

func (u *AuthUserStore) FinishRegistration(w http.ResponseWriter, r *http.Request) error {
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}
	//var user webauthn.User
	d, ok := store.Get("webauthnUser")
	user := d.(models.WebAuthnUser)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return err
	}
	sessionD, ok := store.Get("webauthnData")
	sessionData := sessionD.(*webauthn.SessionData)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return err
	}
	//user := datastore.GetUser() // Get the user

	// Get the session data stored from the function above
	//session := datastore.GetSession()
	err = store.Save()
	if err != nil {
		return err
	}
	credential, err := u.webauthn.FinishRegistration(user, *sessionData, r)
	if err != nil {
		// Handle Error and return.
		return err
	}

	// If creation was successful, store the credential object
	// Pseudocode to add the user credential.
	user.AddCredential(credential)
	//datastore.SaveUser(user)
	err = u.saveUser(&user)
	if err != nil {
		return err
	}

	err = JSONResponse(w, "Registration Success", http.StatusOK)
	if err != nil {
		return err
	} // Handle next steps
	return nil
}

func (u *AuthUserStore) BeginLogin(w http.ResponseWriter, r *http.Request, username string) error {
	user, err := u.getWebauthnUser(username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}
	sessionStore, err := session.Start(r.Context(), w, r)
	options, sessionData, err := u.webauthn.BeginLogin(user)
	if err != nil {
		// Handle Error and return.

		return err
	}
	sessionStore.Set("webauthnLoginData", sessionData)
	sessionStore.Set("webauthnUser", user)
	// store the session values
	//datastore.SaveSession(session)
	err = sessionStore.Save()
	if err != nil {
		return err
	}
	err = JSONResponse(w, options, http.StatusOK)
	if err != nil {
		return err
	} // return the options generated
	// options.publicKey contain our registration options
	return nil
}

func (u *AuthUserStore) FinishLogin(w http.ResponseWriter, r *http.Request) error {
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}
	//var user webauthn.User
	d, ok := store.Get("webauthnUser")
	user := d.(models.WebAuthnUser)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return err
	}
	sessionD, ok := store.Get("webauthnLoginData")
	sessionData := sessionD.(*webauthn.SessionData)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return err
	}

	//// Get the session data stored from the function above
	//session := datastore.GetSession()

	credential, err := u.webauthn.FinishLogin(user, *sessionData, r)
	if err != nil {
		// Handle Error and return.
		w.WriteHeader(http.StatusBadRequest)
		return err
	}
	store.Set("LoggedInUserID", user.WebAuthnName())
	err = store.Save()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// Handle credential.Authenticator.CloneWarning

	// If login was successful, update the credential object
	// Pseudocode to update the user credential.
	user.UpdateCredential(credential)
	err = u.saveUser(&user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	err = JSONResponse(w, "Login Success", http.StatusOK)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}
	return nil
}
