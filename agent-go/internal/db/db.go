package db

import (
	"context"
	"os"
	"time"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
	"github.com/furkankorkmaz309/threat-agent/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func InitDB(uri string) (*mongo.Client, error) {
	if uri == "" {
		uri = "mongodb://127.0.0.1:27017"
	}
	clientOptions := options.Client().ApplyURI(uri)
	return mongo.Connect(context.Background(), clientOptions)
}

func Init(appInstance *app.App) {
	uri := os.Getenv("MONGO_URI")
	client, err := InitDB(uri)
	if err != nil {
		return
	}
	appInstance.MongoClient = client
	appInstance.Database = "threat_intel"
}

func SaveDreadPost(appInstance *app.App, post models.DreadIntel) error {
	collection := appInstance.MongoClient.Database(appInstance.Database).Collection("dread_intel")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	post.Processed = false
	opts := options.Update().SetUpsert(true)
	filter := bson.M{"url": post.URL}
	update := bson.M{"$set": post}

	_, err := collection.UpdateOne(ctx, filter, update, opts)
	return err
}

func SaveCVEMany(appInstance *app.App, cves []struct {
	CVE models.CVE "json:\"cve\" bson:\"cve\""
}) error {
	if len(cves) == 0 {
		return nil
	}
	collection := appInstance.MongoClient.Database(appInstance.Database).Collection("cve_intel")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var operations []mongo.WriteModel
	for _, item := range cves {
		item.CVE.Processed = false
		op := mongo.NewReplaceOneModel()
		op.SetFilter(bson.M{"_id": item.CVE.ID})
		op.SetReplacement(item.CVE)
		op.SetUpsert(true)
		operations = append(operations, op)
	}
	_, err := collection.BulkWrite(ctx, operations)
	return err
}

func SaveURLhausMany(appInstance *app.App, urls []models.URLhausResponse) error {
	if len(urls) == 0 {
		return nil
	}
	collection := appInstance.MongoClient.Database(appInstance.Database).Collection("urlhaus_intel")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var operations []mongo.WriteModel
	for _, item := range urls {
		item.Processed = false
		op := mongo.NewUpdateOneModel()
		op.SetFilter(bson.M{"url": item.URL})
		op.SetUpdate(bson.M{"$setOnInsert": item})
		op.SetUpsert(true)
		operations = append(operations, op)
	}
	_, err := collection.BulkWrite(ctx, operations)
	return err
}
