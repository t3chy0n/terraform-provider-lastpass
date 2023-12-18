# LastPass Client Library for Go

The LastPass Client Library provides an interface to interact with LastPass accounts programmatically using Go. It allows for operations such as creating new accounts, attaching files, and retrieving account information.

## Getting Started

These instructions will help you get the LastPass Client set up and running on your local machine for development and testing purposes.

### Prerequisites

- Go (version 1.x or later)
- LastPass account credentials (email and master password)

## Usage
Below are some examples of how to use the LastPass Client Library in your Go projects.

### Setting up the Client

To start using the library, you need to set up a LastPass client with your account credentials:

```go
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
if err != nil {
    fmt.Println("Error Creating Last Pass Client:", err)
    return
}
```

### Creating a New Account

You can create new accounts with various details such as passwords, notes, attachments, etc.:

```go
newAcc := dto.Account{
    Name: "TestApp4",
    Group: "K8sManaged\\RabitMq\\Dev",
    Password: "Testtest",
    NoteType: "Server",
    Url: "http://your_fancy_url.com",
    Note: "Some Note",
    Fields: []*dto.Field{
        {Type: "text", Name: "PG_HOST", Value: "dsaasdasdasd"},
        {Type: "password", Name: "PG_PASS", Value: "asasdcxzxzc asdasd"},
    },
    PwProtect: true,
    Attachments: []*dto.Attachment{
        {FileName: "Test.txt", MimeType: "other:txt", Data: []byte("Content...")},
    },
}

err = lastPassClient.Upsert(ctx, &newAcc)
if err != nil {
    fmt.Println("Error Creating Account:", err)
    return
}
```

Alternatively you can use a builder for creating account object, as there are
different kids of secret items. It simplifies object construction:

```go
	newAcc := dto.AccountBuilder("K8sManaged\\RabitMq\\Dev", "TestApp5",
		dto.WithDatabase(dto.AccountDatabaseFields{
			Password: "asd",
		}),
		dto.WithTextFileAttachment("test.txt", "somedataasdasd"),
	)

```

All examples can be found in `./examples` folder.
