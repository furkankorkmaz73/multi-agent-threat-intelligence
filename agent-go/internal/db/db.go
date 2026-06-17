package db

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
	"github.com/furkankorkmaz309/threat-agent/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var tokenPattern = regexp.MustCompile(`[A-Za-z0-9._:/-]+`)

const defaultBulkChunkSize = 500

var pythonOwnedFields = map[string]struct{}{
	"analysis":              {},
	"analysis_history":      {},
	"job_lifecycle":         {},
	"job_lifecycle_history": {},
	"analyzed_at":           {},
	"processed":             {},
}

func InitDB(uri string) (*mongo.Client, error) {
	if uri == "" {
		uri = "mongodb://127.0.0.1:27017"
	}
	clientOptions := options.Client().ApplyURI(uri)
	return mongo.Connect(context.Background(), clientOptions)
}

func Init(appInstance *app.App) error {
	uri := os.Getenv("MONGO_URI")
	client, err := InitDB(uri)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Ping(ctx, nil); err != nil {
		return fmt.Errorf("mongo ping failed: %w", err)
	}

	appInstance.MongoClient = client
	dbName := strings.TrimSpace(os.Getenv("DB_NAME"))
	if dbName == "" {
		dbName = "threat_intel"
	}
	appInstance.Database = dbName
	EnsureIndexes(appInstance)
	return nil
}

func EnsureIndexes(appInstance *app.App) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	definitions := map[string][]mongo.IndexModel{
		"cve_intel": {
			{Keys: bson.D{{Key: "processed", Value: 1}, {Key: "_id", Value: 1}}},
			{Keys: bson.D{{Key: "normalized_fields.search_text", Value: 1}}},
			{Keys: bson.D{{Key: "normalized_fields.keywords", Value: 1}}},
			{Keys: bson.D{{Key: "metadata.source_ref", Value: 1}}},
		},
		"urlhaus_intel": {
			{Keys: bson.D{{Key: "processed", Value: 1}, {Key: "url", Value: 1}}},
			{Keys: bson.D{{Key: "normalized_fields.search_text", Value: 1}}},
			{Keys: bson.D{{Key: "normalized_fields.keywords", Value: 1}}},
			{Keys: bson.D{{Key: "url", Value: 1}}, Options: options.Index().SetUnique(true)},
		},
		"dread_intel": {
			{Keys: bson.D{{Key: "processed", Value: 1}, {Key: "url", Value: 1}}},
			{Keys: bson.D{{Key: "normalized_fields.search_text", Value: 1}}},
			{Keys: bson.D{{Key: "normalized_fields.keywords", Value: 1}}},
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

	enrichDread(&post)
	opts := options.Update().SetUpsert(true)
	filter, update, err := buildDreadUpsert(post)
	if err != nil {
		return err
	}

	_, err = collection.UpdateOne(ctx, filter, update, opts)
	return err
}

func SaveCVEMany(appInstance *app.App, cves []struct {
	CVE models.CVE `json:"cve" bson:"cve"`
}) error {
	if len(cves) == 0 {
		return nil
	}
	collection := appInstance.MongoClient.Database(appInstance.Database).Collection("cve_intel")

	chunkSize := collectorBulkChunkSize()
	operations := make([]mongo.WriteModel, 0, minInt(chunkSize, len(cves)))
	chunkIndex := 1
	for _, item := range cves {
		enrichCVE(&item.CVE)
		filter, update, err := buildCVEUpsert(item.CVE)
		if err != nil {
			return err
		}
		updateOp := mongo.NewUpdateOneModel()
		updateOp.SetFilter(filter)
		updateOp.SetUpdate(update)
		updateOp.SetUpsert(true)
		operations = append(operations, updateOp)
		if len(operations) >= chunkSize {
			if err := writeBulkChunk(appInstance, collection, "cve", chunkIndex, operations, 2*time.Minute); err != nil {
				return err
			}
			chunkIndex++
			operations = operations[:0]
		}
	}
	if len(operations) > 0 {
		return writeBulkChunk(appInstance, collection, "cve", chunkIndex, operations, 2*time.Minute)
	}
	return nil
}

func SaveURLhausMany(appInstance *app.App, urls []models.URLhausResponse) error {
	if len(urls) == 0 {
		return nil
	}
	collection := appInstance.MongoClient.Database(appInstance.Database).Collection("urlhaus_intel")

	chunkSize := collectorBulkChunkSize()
	operations := make([]mongo.WriteModel, 0, minInt(chunkSize, len(urls)))
	chunkIndex := 1
	for _, item := range urls {
		enrichURLhaus(&item)
		filter, update, err := buildURLhausUpsert(item)
		if err != nil {
			return err
		}
		op := mongo.NewUpdateOneModel()
		op.SetFilter(filter)
		op.SetUpdate(update)
		op.SetUpsert(true)
		operations = append(operations, op)
		if len(operations) >= chunkSize {
			if err := writeBulkChunk(appInstance, collection, "urlhaus", chunkIndex, operations, 3*time.Minute); err != nil {
				return err
			}
			chunkIndex++
			operations = operations[:0]
		}
	}
	if len(operations) > 0 {
		return writeBulkChunk(appInstance, collection, "urlhaus", chunkIndex, operations, 3*time.Minute)
	}
	return nil
}

func collectorBulkChunkSize() int {
	raw := strings.TrimSpace(os.Getenv("COLLECTOR_BULK_CHUNK_SIZE"))
	if raw == "" {
		return defaultBulkChunkSize
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return defaultBulkChunkSize
	}
	if parsed > 5000 {
		return 5000
	}
	return parsed
}

func writeBulkChunk(appInstance *app.App, collection *mongo.Collection, source string, chunkIndex int, operations []mongo.WriteModel, timeout time.Duration) error {
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := collection.BulkWrite(ctx, operations, options.BulkWrite().SetOrdered(false))
	elapsed := time.Since(started)
	var matched, modified, upserted int64
	if result != nil {
		matched = result.MatchedCount
		modified = result.ModifiedCount
		upserted = result.UpsertedCount
	}
	appInstance.LogJSON(
		"INFO",
		source,
		fmt.Sprintf(
			"bulk_write_chunk=%d attempted=%d matched=%d modified=%d upserted=%d elapsed=%.3fs records_per_sec=%.1f",
			chunkIndex,
			len(operations),
			matched,
			modified,
			upserted,
			elapsed.Seconds(),
			recordsPerSecond(len(operations), elapsed),
		),
	)
	return err
}

func buildCVEUpsert(item models.CVE) (bson.M, bson.M, error) {
	update, err := collectorUpsertUpdate(item, "_id")
	return bson.M{"_id": item.ID}, update, err
}

func buildURLhausUpsert(item models.URLhausResponse) (bson.M, bson.M, error) {
	update, err := collectorUpsertUpdate(item)
	return bson.M{"url": item.URL}, update, err
}

func buildDreadUpsert(post models.DreadIntel) (bson.M, bson.M, error) {
	update, err := collectorUpsertUpdate(post)
	return bson.M{"url": post.URL}, update, err
}

func collectorUpsertUpdate(document any, omitSetFields ...string) (bson.M, error) {
	payload, err := bson.Marshal(document)
	if err != nil {
		return nil, err
	}

	var set bson.M
	if err := bson.Unmarshal(payload, &set); err != nil {
		return nil, err
	}

	for field := range pythonOwnedFields {
		delete(set, field)
	}
	for _, field := range omitSetFields {
		delete(set, field)
	}

	return bson.M{
		"$set":         set,
		"$setOnInsert": bson.M{"processed": false},
	}, nil
}

func recordsPerSecond(count int, elapsed time.Duration) float64 {
	if count <= 0 || elapsed <= 0 {
		return 0
	}
	return float64(count) / elapsed.Seconds()
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
