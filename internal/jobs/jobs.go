package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/adalundhe/micron/internal/provider/jobs"
	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
)

const (
	TerraformCloudJobType jobs.JobType = "terraform_cloud"
	DeploymentStatusPoll  jobs.JobType = "deployment_status_poll"
	DnarRevokeJobType     jobs.JobType = "dnar_revoke"
)

func setJobInfoState(ctx context.Context, task *asynq.Task, redisClient *redis.Client, prefix string, jobInfo []byte) error {
	redisKey := fmt.Sprintf("%s:%s:%s", prefix, task.Type(), task.ResultWriter().TaskID())
	return redisClient.Set(ctx, redisKey, jobInfo, time.Hour*24).Err()
}

func getJobInfoState(ctx context.Context, task *asynq.Task, redisClient *redis.Client, prefix string) ([]byte, error) {
	redisKey := fmt.Sprintf("%s:%s:%s", prefix, task.Type(), task.ResultWriter().TaskID())
	result := redisClient.Get(ctx, redisKey)
	if err := result.Err(); err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get job info state with key %s: %w", redisKey, err)
	}
	return result.Bytes()
}
