package vault

import (
	"context"
	"last-pass/client"
	"last-pass/client/dto"
	"sync"
	"time"
)

var (
	mutex = &sync.Mutex{}
)

const (
	SYNC_AUTO = "SYNC_AUTO"
	SYNC_NOW  = "SYNC_NOW"
)

type LastPassVault struct {
	blobCache  client.Blob
	latestBlob *client.Blob
	client     *client.LastPassClient
	syncType   string
	syncTime   time.Time
	needsSync  bool
}

func NewLastPassVault(client *client.LastPassClient) *LastPassVault {

	var vault = &LastPassVault{
		client:    client,
		syncType:  SYNC_AUTO,
		needsSync: false,
	}

	return vault
}

type AccountPredicate func(c *dto.Account) bool

func (lpassVault *LastPassVault) GetAccount(ctx context.Context, predicates ...AccountPredicate) (*dto.Account, error) {
	var err error

	mutex.Lock()
	defer mutex.Unlock()
	if lpassVault.latestBlob == nil || (lpassVault.syncType == SYNC_AUTO && time.Since(lpassVault.syncTime) >= 15*time.Second) || lpassVault.needsSync == true {
		lpassVault.latestBlob, err = lpassVault.client.GetBlob(ctx)
		if err != nil {
			return nil, err
		}
		lpassVault.syncTime = time.Now()
		lpassVault.needsSync = false
	}

	lpassVault.blobCache = *lpassVault.latestBlob

	accounts, err := lpassVault.blobCache.Parse(lpassVault.client.Session)
	if err != nil {
		return nil, err
	}
	for _, acc := range accounts {
		for _, predicate := range predicates {
			if predicate(acc) {
				return acc, nil
			}
		}

	}
	return nil, nil
}

func (lpassVault *LastPassVault) GetAccountById(ctx context.Context, id string) (*dto.Account, error) {
	return lpassVault.GetAccount(ctx, func(acc *dto.Account) bool {
		return acc.Id == id
	})
}

func (lpassVault *LastPassVault) WriteAccount(ctx context.Context, account *dto.Account) error {
	mutex.Lock()
	defer mutex.Unlock()
	var err = lpassVault.client.Upsert(ctx, account)
	if err == nil {
		lpassVault.needsSync = true
	}
	return err
}
func (lpassVault *LastPassVault) DeleteAccount(ctx context.Context, account *dto.Account) error {
	mutex.Lock()
	defer mutex.Unlock()
	var _, err = lpassVault.client.Delete(ctx, account)
	if err == nil {
		lpassVault.needsSync = true
	}
	return err
}
