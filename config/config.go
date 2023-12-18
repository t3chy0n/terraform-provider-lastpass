package config

import "sync"

var (
	configValues = make(map[string]string)
	mutex        = &sync.Mutex{}
)

func ReadString(key string) string {
	mutex.Lock()
	defer mutex.Unlock()

	if value, exists := configValues[key]; exists {
		return value
	}
	return ""
}

func WriteString(key string, value string) {
	mutex.Lock()
	defer mutex.Unlock()

	configValues[key] = value
}
