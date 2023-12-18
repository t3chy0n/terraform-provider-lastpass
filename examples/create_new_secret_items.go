package examples

import (
	"context"
	"fmt"
	"last-pass-poc/client"
	"last-pass-poc/client/dto"
	"log"
	"os"
)

func mainExample2() {

	email := "YOUR_EMAIL"
	password := "MASTER_PASSWORD"

	logger := log.New(os.Stderr, "LastPass Client", log.LstdFlags)

	ctx := context.Background()

	lastPassClient, err := client.NewClient(
		email,
		password,
		client.WithLogger(logger),
		client.WithTrust(),
	)

	newAcc2 := dto.AccountBuilder("K8sManaged\\RabitMq\\Dev", "TestApp5",
		dto.WithDatabase(dto.AccountDatabaseFields{
			Password: "asd",
		}),
		dto.WithTextFileAttachment("test.txt", "somedataasdasd"),
	)

	newAcc3 := dto.AccountBuilder("K8sManaged\\RabitMq\\Dev", "TestApp5",
		dto.WithSecretNote(dto.AccountSecretNoteFields{
			Notes: "asd",
		}),
		dto.WithTextFileAttachment("test2.txt", "somedataasdasd"),
	)

	newAcc4 := dto.AccountBuilder("K8sManaged\\RabitMq\\Dev", "TestApp6",
		dto.WithSsh(dto.AccountSshFields{
			Passphrase: "asd",
		}),
		dto.WithTextFileAttachment("test.txt", "somedataasdasd"),
	)
	newAcc := dto.Account{
		Name: "TestApp4", Group: "K8sManaged\\RabitMq\\Dev",
		Password: "Testtest",
		NoteType: "Server",
		Url:      "http://your_fancy_url.com",
		//Note:     "NoteType:Custom_3074253946103878272\nLanguage:en-US\ntest:",
		Note: "Some Note",
		//Url:      "https://www.rabbitmq.com/",
		Fields: []*dto.Field{
			{Type: "text", Name: "PG_HOST", Value: "dsaasdasdasd"},
			{Type: "password", Name: "PG_PASS", Value: "asasdcxzxzc asdasd"},
			{Type: "password", Name: "PG_PASS2", Value: "asasdcxzxzc asdasd123121"},
		},
		PwProtect: true,
		Attachments: []*dto.Attachment{
			{FileName: "Test.txt", MimeType: "other:txt", Data: []byte("ContentContentContentContentContentContentContent")},
			{FileName: "Test2.txt", MimeType: "other:txt", Data: []byte("ContentContentContentContentContentContentContent")},
		},
	}
	//newAcc2 := dto.Account{Name: "RedisConfig", Group: "K8sManaged\\RabitMq", Password: "Testtest", Note: "Test notes", Url: "https://www.redis.com/"}
	//app := dto.App{Name: "BrandNewApplicationDev", Account: &newAcc, WinInfo: "asdasdasd", WinTitle: "gfdhgfdhfghgf"}

	//newAcc.Application = &app
	//
	err = lastPassClient.Upsert(ctx, &newAcc)
	err = lastPassClient.Upsert(ctx, &newAcc2)
	err = lastPassClient.Upsert(ctx, &newAcc3)
	err = lastPassClient.Upsert(ctx, &newAcc4)

	if err != nil {
		fmt.Println("Error Creating Last Pass Client:", err)
		return
	}
}
