package models

import (
	"encoding/json"
	"time"

	"github.com/uptrace/bun"
)

type JobProvider string

const (
	KubernetesJobProvider JobProvider = "kubernetes"
	InternalJobProvider   JobProvider = "internal"
)

func GetJobProviders() []JobProvider {
	return []JobProvider{
		KubernetesJobProvider,
		InternalJobProvider,
	}
}

type JobInfo struct {
	bun.BaseModel `bun:"table:job_info"`
	Id            int64           `bun:"id,pk,autoincrement"`
	JobId         string          `bun:"job_id"` // this is the ID from the provider
	JobName       string          `bun:"job_name"`
	Provider      JobProvider     `bun:"provider"`
	Status        string          `bun:"status"`
	StartTime     time.Time       `bun:"start_time"`
	EndTime       time.Time       `bun:"end_time"`
	UpdatedAt     time.Time       `bun:"updated_at"`
	Duration      int             `bun:"duration"`
	Parameters    json.RawMessage `bun:"parameters,type:jsonb"`
	Retries       int             `bun:"retries"`
	Error         string          `bun:"error"`
}

type VaultAuthProvider interface {
	GetVaultToken() (string, error)
}
