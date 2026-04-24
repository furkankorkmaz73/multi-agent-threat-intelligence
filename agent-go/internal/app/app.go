package app

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

type App struct {
	MongoClient *mongo.Client
	Database    string
}

func New() *App {
	return &App{}
}

type LogEntry struct {
	Level     string    `json:"level"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

func (a *App) LogJSON(level, source, message string) {
	entry := LogEntry{
		Level:     level,
		Source:    source,
		Message:   message,
		Timestamp: time.Now(),
	}
	output, _ := json.Marshal(entry)
	fmt.Fprintln(os.Stderr, string(output))
}
