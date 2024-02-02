package config

import (
	"last-pass/client/dto"
	"time"
)

type SessionCacheRecord struct {
	Session  *dto.Session
	CachedAt time.Time
}

var (
	sessions = make(map[string]SessionCacheRecord)
)

func GetCachedSession(key string) *dto.Session {
	mutex.Lock()
	defer mutex.Unlock()

	if cached, exists := sessions[key]; exists {
		if time.Since(cached.CachedAt) >= 300*time.Second {
			delete(sessions, key)
			return nil
		}
		return cached.Session
	}
	return nil
}

func CacheSession(key string, session *dto.Session) {
	mutex.Lock()
	defer mutex.Unlock()

	sessions[key] = SessionCacheRecord{
		CachedAt: time.Now(),
		Session:  session,
	}
}
