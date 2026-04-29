package model

import "time"

type TaskType string

const (
	TaskSubdomain TaskType = "subdomain"
	TaskReverseIP TaskType = "reverse_ip"
	TaskWebProbe  TaskType = "web_probe"
	TaskPipeline  TaskType = "pipeline"
)

type Record struct {
	Value     string    `json:"value"`
	TaskType  TaskType  `json:"task_type"`
	Query     string    `json:"query"`
	Sources   []string  `json:"sources"`
	FirstSeen time.Time `json:"first_seen"`
}

type ProviderResult struct {
	Provider string
	Values   []string
}

type ProviderStatus struct {
	Name    string
	Running bool
	Error   string
}

type LogEntry struct {
	Time    time.Time
	Level   string
	Message string
}

type WebProbeRecord struct {
	Host         string    `json:"host"`
	URL          string    `json:"url"`
	IP           string    `json:"ip,omitempty"`
	StatusCode   int       `json:"status_code"`
	Title        string    `json:"title,omitempty"`
	Server       string    `json:"server,omitempty"`
	ContentType  string    `json:"content_type,omitempty"`
	Technologies []string  `json:"technologies,omitempty"`
	Source       string    `json:"source,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	Error        string    `json:"error,omitempty"`
}
