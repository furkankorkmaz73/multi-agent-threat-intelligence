package models

type URLhausResponse struct {
	Metadata    SourceMetadata   `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Normalized  NormalizedFields `json:"normalized_fields,omitempty" bson:"normalized_fields,omitempty"`
	ID          string           `json:"id" bson:"urlhaus_id"`
	DateAdded   string           `json:"date_added" bson:"date_added"`
	URL         string           `json:"url" bson:"url"`
	URLStatus   string           `json:"url_status" bson:"url_status"`
	Threat      string           `json:"threat" bson:"threat"`
	Tags        []string         `json:"tags" bson:"tags"`
	UrlhausLink string           `json:"urlhaus_reference" bson:"urlhaus_link"`
	Reporter    string           `json:"reporter" bson:"reporter"`
	Processed   bool             `json:"-" bson:"processed"`
}
