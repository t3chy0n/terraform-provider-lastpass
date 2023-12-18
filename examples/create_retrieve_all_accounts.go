package examples

import (
	"context"
	"fmt"
	"last-pass-poc/client"
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

	accounts, err := lastPassClient.GetBlob(ctx)
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
