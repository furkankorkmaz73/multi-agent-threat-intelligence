package db

import (
	"context"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
	"github.com/furkankorkmaz309/threat-agent/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var tokenPattern = regexp.MustCompile(`[A-Za-z0-9._:/-]+`)

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
	EnsureIndexes(appInstance)
}

func EnsureIndexes(appInstance *app.App) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	definitions := map[string][]mongo.IndexModel{
		"cve_intel": {
			{Keys: bson.D{{Key: "processed", Value: 1}, {Key: "_id", Value: 1}}},
			{Keys: bson.D{{Key: "normalized_fields.search_text", Value: 1}}},
			{Keys: bson.D{{Key: "metadata.source_ref", Value: 1}}},
		},
		"urlhaus_intel": {
			{Keys: bson.D{{Key: "processed", Value: 1}, {Key: "url", Value: 1}}},
			{Keys: bson.D{{Key: "normalized_fields.search_text", Value: 1}}},
			{Keys: bson.D{{Key: "url", Value: 1}}, Options: options.Index().SetUnique(true)},
		},
		"dread_intel": {
			{Keys: bson.D{{Key: "processed", Value: 1}, {Key: "url", Value: 1}}},
			{Keys: bson.D{{Key: "normalized_fields.search_text", Value: 1}}},
			{Keys: bson.D{{Key: "url", Value: 1}}, Options: options.Index().SetUnique(true)},
		},
	}

	for collectionName, models := range definitions {
		_, err := appInstance.MongoClient.Database(appInstance.Database).Collection(collectionName).Indexes().CreateMany(ctx, models)
		if err != nil {
			appInstance.LogJSON("ERROR", "db", err.Error())
		}
	}
}

func enrichCVE(item *models.CVE) {
	now := time.Now().UTC()
	searchChunks := []string{item.ID}
	var keywords []string
	for _, desc := range item.Descriptions {
		if desc.Value != "" {
			keywords = append(keywords, extractTokens(desc.Value)...)
			searchChunks = append(searchChunks, desc.Value)
		}
	}
	item.Metadata = models.SourceMetadata{Source: "nvd", SourceRef: item.ID, IngestedAt: now, NormalizedAt: now, SchemaVersion: "v3", Collector: "agent-go", SourceConfidence: 0.95}
	item.Normalized = models.NormalizedFields{EntityType: "cve", Aliases: []string{item.ID}, Keywords: uniqueStrings(keywords), SearchText: normalizeSearchText(searchChunks...)}
}

func enrichURLhaus(item *models.URLhausResponse) {
	now := time.Now().UTC()
	references := uniqueStrings([]string{item.URL, item.UrlhausLink})
	keywords := uniqueStrings(append(extractTokens(item.Threat), normalizeMany(item.Tags)...))
	item.Metadata = models.SourceMetadata{Source: "urlhaus", SourceRef: item.ID, SourceURL: item.UrlhausLink, IngestedAt: now, NormalizedAt: now, SchemaVersion: "v3", Collector: "agent-go", SourceConfidence: 0.9}
	item.Normalized = models.NormalizedFields{EntityType: "urlhaus", Aliases: uniqueStrings([]string{item.ID, item.URL}), Keywords: keywords, References: references, SearchText: normalizeSearchText(append([]string{item.ID, item.URL, item.Threat, item.UrlhausLink}, item.Tags...)...)}
}

func enrichDread(post *models.DreadIntel) {
	now := time.Now().UTC()
	keywords := uniqueStrings(append([]string{strings.ToLower(post.Category), strings.ToLower(post.Author)}, extractTokens(post.Title)...))
	post.Metadata = models.SourceMetadata{Source: "dread", SourceRef: post.URL, SourceURL: post.URL, IngestedAt: now, NormalizedAt: now, SchemaVersion: "v3", Collector: "agent-go", SourceConfidence: 0.7}
	post.Normalized = models.NormalizedFields{EntityType: "dread", Aliases: uniqueStrings([]string{post.Title, post.URL}), Keywords: keywords, References: []string{post.URL}, SearchText: normalizeSearchText(post.Title, post.Content, post.Category, post.Author, post.URL)}
}

func normalizeSearchText(parts ...string) string {
	var tokens []string
	for _, part := range parts {
		tokens = append(tokens, extractTokens(part)...)
	}
	return strings.Join(uniqueStrings(tokens), " ")
}

func extractTokens(text string) []string {
	matches := tokenPattern.FindAllString(strings.ToLower(text), -1)
	if len(matches) == 0 {
		return nil
	}
	return matches
}

func normalizeMany(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func SaveDreadPost(appInstance *app.App, post models.DreadIntel) error {
	collection := appInstance.MongoClient.Database(appInstance.Database).Collection("dread_intel")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	post.Processed = false
	enrichDread(&post)
	opts := options.Update().SetUpsert(true)
	filter := bson.M{"url": post.URL}
	update := bson.M{"$set": post}

	_, err := collection.UpdateOne(ctx, filter, update, opts)
	return err
}

func SaveCVEMany(appInstance *app.App, cves []struct {
	CVE models.CVE `json:"cve" bson:"cve"`
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
		enrichCVE(&item.CVE)
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
		enrichURLhaus(&item)
		op := mongo.NewUpdateOneModel()
		op.SetFilter(bson.M{"url": item.URL})
		op.SetUpdate(bson.M{"$set": item})
		op.SetUpsert(true)
		operations = append(operations, op)
	}
	_, err := collection.BulkWrite(ctx, operations)
	return err
}
