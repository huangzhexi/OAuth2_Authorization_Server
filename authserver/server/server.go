package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/huangzhexi/oauth2/errors"
	"github.com/huangzhexi/oauth2/generates"
	"github.com/huangzhexi/oauth2/manage"
	"github.com/huangzhexi/oauth2/models"
	"github.com/huangzhexi/oauth2/server"
	"github.com/huangzhexi/oauth2/store"
	//"validates"
	"github.com/go-session/session"
)

var (
	dumpvar                bool
	idvar                  string
	secretvar              string
	domainvar              string
	portvar                int
	tlsvar                 bool
	clientURL              string
	userValidateDBAddr     string
	userValidateDBName     string
	userValidateDBPassword string
)

// 函数执行或者包导入后自动执行init函数
func init() {
	// flag ，用于命令行传参 如 --d
	flag.BoolVar(&dumpvar, "d", true, "Dump requests and responses")
	flag.StringVar(&idvar, "i", "395785444978-7b9v7l0ap2h3308528vu1ddnt3rqftjc.apps.huangusercontent.com", "The client id being passed in")
	flag.StringVar(&secretvar, "s", "yQ1mK5xrm106vxTOjLOwKBGUQsBxFXToSUd", "The client secret being passed in")
	flag.StringVar(&domainvar, "r", "https://blog.chd.huangzhexi.eu.org:9090/api/callback", "The domain of the redirect url")
	flag.IntVar(&portvar, "p", 9096, "the base port for the server")
	flag.BoolVar(&tlsvar, "t", false, "Use tls")
	flag.StringVar(&clientURL, "cu", "localhost:3000", "The client url")
	flag.StringVar(&userValidateDBAddr, "sa", "localhost", "The database url")
	flag.StringVar(&userValidateDBName, "su", "", "username")
	flag.StringVar(&userValidateDBPassword, "sp", "", "password")

}

func main() {
	// 所用flag定义之后Parse。
	flag.Parse()
	if dumpvar {
		log.Println("Dumping requests")
	}
	//userdb := validates.NewUserStore(userValidateDBAddr, userValidateDBName, userValidateDBPassword)
	userStore, err := store.NewDefaultAuthUserStore("user.json")
	if err != nil {
		fmt.Println(err)
	}
	//var allowOrigin string = "http://localhost:3000"
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	// manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512))
	manager.MapAccessGenerate(generates.NewAccessGenerate())

	//client store 记录客户端
	clientStore := store.NewClientStore()
	clientStore.Set(idvar, &models.Client{
		ID:     idvar,
		Secret: secretvar,
		Domain: domainvar,
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)

	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (userID string, err error) {
		if username == "test" && password == "test" {
			userID = "test"
			return userID, nil
		}
		return "", nil
	})

	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	//http.Handle("/static/", )
	http.Handle("/static/", http.StripPrefix("/static", http.FileServer(http.Dir("static/"))))

	//http.HandleFunc("/login", loginHandler)
	//http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/main", mainHandler)
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		if dumpvar {
			dumpRequest(os.Stdout, "/", request)
		}
		writer.Header().Set("Location", "/login")
		writer.WriteHeader(302)
	})
	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		if dumpvar {
			dumpRequest(os.Stdout, "authorize", r)
		}
		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var form url.Values
		if v, ok := store.Get("ReturnUri"); ok {
			form = v.(url.Values)
			if dumpvar {
				fmt.Println(store)
			}
		}
		r.Form = form

		store.Delete("ReturnUri")
		store.Save()

		err = srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		uri := w.Header().Get("Location")
		fmt.Println("uri: " + uri)
		if uri != "/login" {
			var data map[string]string
			data["Location"] = uri
			w.WriteHeader(200)
			e := json.NewEncoder(w)
			e.SetIndent("", "  ")
			e.Encode(data)
		}
	})
	http.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		if dumpvar {
			dumpRequest(os.Stdout, "authorize", r)
		}
		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var form url.Values
		if v, ok := store.Get("ReturnUri"); ok {
			form = v.(url.Values)
			if dumpvar {
				fmt.Println(store)
			}
		}
		r.Form = form

		store.Delete("ReturnUri")
		store.Save()

		err = srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if dumpvar {
			_ = dumpRequest(os.Stdout, "token", r) // Ignore the error
		}

		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	http.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if dumpvar {
			_ = dumpRequest(os.Stdout, "token", r) // Ignore the error
		}

		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/asdjkfbgewqfqwei", func(w http.ResponseWriter, r *http.Request) {
		_ = dumpRequest(os.Stdout, "token", r) // Ignore the error
		_, err := w.Write([]byte("test"))
		if err != nil {
			return
		}
	})
	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		if dumpvar {
			_ = dumpRequest(os.Stdout, "test", r) // Ignore the error
		}

		token, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		data := map[string]interface{}{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"user_id":    token.GetUserID(),
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(data)
	})

	http.HandleFunc("/getUserID", func(w http.ResponseWriter, r *http.Request) {
		if dumpvar {
			_ = dumpRequest(os.Stdout, "getUserID", r) // Ignore the error
		}
		token, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			fmt.Println("bad req")
			return
		}

		data := map[string]interface{}{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"user_id":    token.GetUserID(),
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(data)
	})
	//http.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
	//	if dumpvar {
	//		_ = dumpRequest(os.Stdout, "test", r) // Ignore the error
	//	}
	//	token, err := srv.ValidationBearerToken(r)
	//	if err != nil {
	//		http.Error(w, err.Error(), http.StatusBadRequest)
	//		return
	//	}
	//
	//	data := map[string]interface{}{
	//		"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
	//		"client_id":  token.GetClientID(),
	//		"user_id":    token.GetUserID(),
	//	}
	//	e := json.NewEncoder(w)
	//	e.SetIndent("", "  ")
	//	e.Encode(data)
	//})
	//http.Handle("/static/")
	http.HandleFunc("/modifyPassword", func(w http.ResponseWriter, r *http.Request) {

		if dumpvar {
			_ = dumpRequest(os.Stdout, "modify", r) // Ignore the error
		}
		sStore, err := session.Start(r.Context(), w, r)
		if _, ok := sStore.Get("LoggedInUserID"); ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		type submitRequest struct {
			Username    string `json:"username"`
			Password    string `json:"password"`
			NewPassword string `json:"newPassword"`
		}
		var formdata submitRequest
		err = json.NewDecoder(r.Body).Decode(&formdata)
		fmt.Println(formdata)
		if err != nil {
			http.Error(w, "StatusBadRequest", http.StatusBadRequest)
		}
		if !(validatePassword(userStore, formdata.Username, formdata.Password)) {
			fmt.Println("password validation failed")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		err = userStore.ModifyPassword(formdata.Username, formdata.Password, formdata.NewPassword)
		if err != nil {
			//w.WriteHeader(http.StatusInternalServerError)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

	})
	http.HandleFunc("/getUserInfo", func(w http.ResponseWriter, r *http.Request) {
		if dumpvar {
			_ = dumpRequest(os.Stdout, "getInfo", r) // Ignore the error
		}
		sStore, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if _, ok := sStore.Get("LoggedInUserID"); ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		UsernameString, ok := sStore.Get("UsernameString")
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		data := map[string]interface{}{
			"UsernameString": UsernameString,
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		err = e.Encode(data)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if dumpvar {
			_ = dumpRequest(os.Stdout, "login", r) // Ignore the error
		}
		//if r.Method != "POST" {
		//	w.WriteHeader(404)
		//}
		sStore, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if _, ok := sStore.Get("LoggedInUserID"); ok {
			w.Header().Set("Location", "/main")

			w.WriteHeader(http.StatusFound)
			return
		}

		if r.Form == nil {
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		}

		type submitUser struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		var formdata submitUser
		err = json.NewDecoder(r.Body).Decode(&formdata)
		fmt.Println(formdata)
		if err != nil {
			http.Error(w, "StatusBadRequest", http.StatusBadRequest)
			return
		}
		usernameString, isCorrect, err := userStore.Validates(formdata.Username, formdata.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !isCorrect {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sStore.Set("UsernameString", usernameString)
		//if isCorrect
		//if !(validatePassword(userdb, formdata.Username, formdata.Password)) {
		//	fmt.Println("fail to login")
		//	w.WriteHeader(404)
		//	return
		//}
		//if !(validatePassword(r.Form.Get("username"), r.Form.Get("password"))) {
		//	//outputHTML(w, r, "static/index.html")
		//	w.WriteHeader(404)
		//	//w.Write()
		//	//w.WriteHeader(http.StatusUnauthorized)
		//	return
		//}
		sStore.Set("LoggedInUserID", formdata.Username)
		err = sStore.Save()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}

		if _, ok := sStore.Get("ReturnUri"); !ok {
			w.Header().Set("Location", "/main")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/auth")
		w.WriteHeader(http.StatusFound)
		return
	})

	log.Printf("Server is running at %d port.\n", portvar)
	log.Printf("Point your OAuth client Auth endpoint to %s:%d%s", "http://localhost", portvar, "/oauth/authorize")
	log.Printf("Point your OAuth client Token endpoint to %s:%d%s", "http://localhost", portvar, "/oauth/token")
	if tlsvar {

		certFile := "/etc/letsencrypt/live/chd.huangzhexi.eu.org/fullchain.pem"
		keyFile := "/etc/letsencrypt/live/chd.huangzhexi.eu.org/privkey.pem"
		log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%d", portvar), certFile, keyFile, nil))
	} else {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", portvar), nil))

	}

}

func dumpRequest(writer io.Writer, header string, r *http.Request) error {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	writer.Write([]byte("\n" + header + ": \n"))
	writer.Write(data)
	return nil
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	if dumpvar {
		_ = dumpRequest(os.Stdout, "userAuthorizeHandler", r) // Ignore the error
	}

	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		return
	}

	uid, ok := store.Get("LoggedInUserID")
	if !ok {
		if r.Form == nil {
			r.ParseForm()
		}

		store.Set("ReturnUri", r.Form)
		store.Save()

		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}
	fmt.Println("here2")
	userID = uid.(string)
	fmt.Println(userID)
	//store.Delete("LoggedInUserID")
	//store.Save()
	return userID, nil
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	if dumpvar {
		_ = dumpRequest(os.Stdout, "userAuthorizeHandler", r) // Ignore the error
	}
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		return
	}

	_, ok := store.Get("LoggedInUserID")
	if !ok {
		if r.Form == nil {
			r.ParseForm()
		}

		store.Set("ReturnUri", r.Form)
		store.Save()

		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}
	outputHTML(w, r, "static/main.html")
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if dumpvar {
		_ = dumpRequest(os.Stdout, "auth", r) // Ignore the error
	}
	w.WriteHeader(404)
	//// session通过cookie，在客户端保存session id，而将用户的其他会话消息保存在服务端的session对象中
	//store, err := session.Start(nil, w, r)
	//if err != nil {
	//	http.Error(w, err.Error(), http.StatusInternalServerError)
	//	return
	//}
	//
	//if _, ok := store.Get("LoggedInUserID"); !ok {
	//	w.Header().Set("Location", "/login")
	//	w.WriteHeader(http.StatusFound)
	//	return
	//}
	//
	//outputHTML(w, r, "static/auth.html")
}

func outputHTML(w http.ResponseWriter, req *http.Request, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	fi, _ := file.Stat()
	http.ServeContent(w, req, file.Name(), fi.ModTime(), file)
}

func validatePassword(u *store.AuthUserStore, username string, password string) bool {
	_, login, err := u.Validates(username, password)
	if err != nil {
		return false
	}
	return login
}

//
//fun validate
