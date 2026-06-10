package config

import "os"

// GetEnv 協助讀取環境變數，若不存在則回傳預設值
func GetEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
