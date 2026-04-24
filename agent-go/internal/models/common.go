package models

import "time"

type SourceMetadata struct {
	Source           string    `json:"source,omitempty" bson:"source,omitempty"`
	SourceRef        string    `json:"source_ref,omitempty" bson:"source_ref,omitempty"`
	SourceURL        string    `json:"source_url,omitempty" bson:"source_url,omitempty"`
	IngestedAt       time.Time `json:"ingested_at,omitempty" bson:"ingested_at,omitempty"`
	NormalizedAt     time.Time `json:"normalized_at,omitempty" bson:"normalized_at,omitempty"`
	SchemaVersion    string    `json:"schema_version,omitempty" bson:"schema_version,omitempty"`
	Collector        string    `json:"collector,omitempty" bson:"collector,omitempty"`
	SourceConfidence float64   `json:"source_confidence,omitempty" bson:"source_confidence,omitempty"`
}

type NormalizedFields struct {
	EntityType string   `json:"entity_type,omitempty" bson:"entity_type,omitempty"`
	Aliases    []string `json:"aliases,omitempty" bson:"aliases,omitempty"`
	Keywords   []string `json:"keywords,omitempty" bson:"keywords,omitempty"`
	Products   []string `json:"products,omitempty" bson:"products,omitempty"`
	References []string `json:"references,omitempty" bson:"references,omitempty"`
	SearchText string   `json:"search_text,omitempty" bson:"search_text,omitempty"`
}
