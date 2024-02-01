package examples

import (
	"context"
	"fmt"
	"last-pass/client"
	"log"
	"os"
)

func mainExample1() {

	email := "YOUR_EMAIL"
	password := "MASTER_PASSWORD"

	ctx := context.Background()
	logger := log.New(os.Stderr, "LastPass Client", log.LstdFlags)

	lastPassClient, err := client.NewClient(
		email,
		password,
		client.WithLogger(logger),
		client.WithTrust(),
	)

	blob, err := lastPassClient.GetBlob(ctx)

	accounts, err := blob.Parse(lastPassClient.Session)
	for _, acc := range accounts {
		if len(acc.Attachments) > 0 {

			plainData, _ := lastPassClient.GetAttachmentData(ctx, acc.Attachments[0], acc.Attachkey)
			println(plainData)

		}
	}

	if err != nil {
		fmt.Println("Error Creating Last Pass Client:", err)
		return
	}
}
