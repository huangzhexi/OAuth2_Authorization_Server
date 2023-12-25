package store

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestAuthUserStore(t *testing.T) {
	_, err := NewDefaultAuthUserStore("user.json")
	if err != nil {
		fmt.Println(err)
	}
	//err = u.Store("testAaaaa", "asfdlkqwheqwoeihr")
	//good, _, err := u.Validates("testAaaaa", "asfdlkqwheqwoeihr")
	//So(err, ShouldBeNil)
	//So(good, ShouldBeTrue)
}

func example() {
	type User struct {
		Name     string `json:"name"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	jsonFile, err := os.Open("11.json")
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var users []User

	err = json.Unmarshal(byteValue, &users)
	if err != nil {
		return
	}

	for i := 0; i < len(users); i++ {
		//err := u.Store(users[i].Username, users[i].Password, users[i].Name)
		if err != nil {
			log.Fatal(err)
			return
		}
		fmt.Println(users[i].Username + "pass:" + users[i].Password + "name:" + users[i].Name)
	}
}
