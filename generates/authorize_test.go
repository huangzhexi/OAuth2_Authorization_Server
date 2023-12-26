package generates_test

import (
	"context"
	"github.com/huangzhexi/oauth2"

	//"github.com/huangzhexi/oauth2/example/server/static"
	"testing"
	"time"

	"github.com/huangzhexi/oauth2/models"

	. "github.com/smartystreets/goconvey/convey"
)

func TestAuthorize(t *testing.T) {
	Convey("Test Authorize Generate", t, func() {
		data := &oauth2.GenerateBasic{
			Client: &models.Client{
				ID:     "123456",
				Secret: "123456",
			},
			UserID:   "000000",
			CreateAt: time.Now(),
		}
		gen := static.NewAuthorizeGenerate()
		code, err := gen.Token(context.Background(), data)
		So(err, ShouldBeNil)
		So(code, ShouldNotBeEmpty)
		Println("\nAuthorize Code:" + code)
	})
}
