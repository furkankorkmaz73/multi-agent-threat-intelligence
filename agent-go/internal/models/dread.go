package models

import "time"

type DreadIntel struct {
	Title     string    `bson:"title"`
	Content   string    `bson:"content"`
	Author    string    `bson:"author"`
	Category  string    `bson:"category"`
	Source    string    `bson:"source"`
	URL       string    `bson:"url"`
	Processed bool      `bson:"processed"`
	CreatedAt time.Time `bson:"created_at"`
}
