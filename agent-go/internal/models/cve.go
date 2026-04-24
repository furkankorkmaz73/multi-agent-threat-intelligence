package models

type CVEList struct {
	ResultsPerPage  int `json:"resultsPerPage" bson:"results_per_page"`
	StartIndex      int `json:"startIndex" bson:"start_index"`
	TotalResults    int `json:"totalResults" bson:"total_results"`
	Vulnerabilities []struct {
		CVE CVE `json:"cve" bson:"cve"`
	} `json:"vulnerabilities" bson:"vulnerabilities"`
}

type CVE struct {
	Metadata     SourceMetadata   `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Normalized   NormalizedFields `json:"normalized_fields,omitempty" bson:"normalized_fields,omitempty"`
	ID           string           `json:"id" bson:"_id"`
	Published    string           `json:"published" bson:"published"`
	LastModified string           `json:"lastModified" bson:"last_modified"`
	Descriptions []struct {
		Lang  string `json:"lang" bson:"lang"`
		Value string `json:"value" bson:"value"`
	} `json:"descriptions" bson:"descriptions"`
	Metrics   Metrics `json:"metrics" bson:"metrics"`
	Processed bool    `bson:"processed"`
}

type Metrics struct {
	CvssMetricV40 []CvssDataWrapper `json:"cvssMetricV40" bson:"cvss_metric_v40"`
	CvssMetricV31 []CvssDataWrapper `json:"cvssMetricV31" bson:"cvss_metric_v31"`
	CvssMetricV30 []CvssDataWrapper `json:"cvssMetricV30" bson:"cvss_metric_v30"`
	CvssMetricV2  []CvssDataWrapper `json:"cvssMetricV2" bson:"cvss_metric_v2"`
}

type CvssDataWrapper struct {
	CvssData struct {
		BaseScore    float64 `json:"baseScore" bson:"base_score"`
		BaseSeverity string  `json:"baseSeverity,omitempty" bson:"base_severity,omitempty"`
	} `json:"cvssData" bson:"cvss_data"`
}
