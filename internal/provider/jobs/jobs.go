package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/adalundhe/micron/internal/models"
	"github.com/adalundhe/micron/internal/stores"
	"github.com/go-redsync/redsync/v4"
	rsredis "github.com/go-redsync/redsync/v4/redis/goredis/v9"
	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

type JobType string

type JobQueueName string

const (
	JobQueueNameDefault = JobQueueName("default")
	TaskStorageDuration = 24 * time.Hour
	DefaultTaskRetries  = 5

	schedulerLockKey     = "asynq:scheduler:lock"
	schedulerLockTTL     = 30 * time.Second
	schedulerRefreshTick = 10 * time.Second
	schedulerRetryDelay  = 5 * time.Second
)

// GetJobQueues returns a list of all known job queues.
//
// The returned list contains the default queue and the test queue.
// this needs to be extended if new job queues are added or removed.
// right now, only the default queue is supported. the test queue should not be used.
// since queues are are only able to be created at startup, we should leave the queues as static values
// otherwise we need to deal with issues such as draining/deleting old queues
func GetJobQueues() []JobQueueName {
	return []JobQueueName{JobQueueNameDefault}
}

// required fields to be able to submit a job
type JobPayloadInfo struct {
	TraceID string `json:"trace_id,omitempty"`
	SpanID  string `json:"span_id,omitempty"`
}

type InternalJobManager interface {
	Close() error
	StartServer() error
	RegisterHandler(provider models.JobProvider, jobType JobType, handler asynq.Handler) error
	ListJobTypes() []JobType
	RegisterScheduledTask(cronSpec string, task *asynq.Task, opts ...asynq.Option) (string, error)
	SubmitTask(ctx context.Context, task *asynq.Task, opts ...asynq.Option) (*asynq.TaskInfo, error)
	WaitForJob(queue JobQueueName, taskId string) error
	IsTaskCompleted(queue JobQueueName, taskId string) (bool, error)
	GetTaskInfo(queue JobQueueName, taskId string) (*asynq.TaskInfo, error)
	ListCompletedTasks(queue JobQueueName) ([]*asynq.TaskInfo, error)
	ListSchedulerEntries() ([]*asynq.SchedulerEntry, error)
	ListSchedulerEnqueueEvents(entryID string) ([]*asynq.SchedulerEnqueueEvent, error)
}

type AsynqLogger struct {
	asynq.Logger
	logger *slog.Logger
}

func (al AsynqLogger) Debug(v ...interface{}) {
	al.logger.Debug("asynq", v...)
}

func (al AsynqLogger) Info(v ...interface{}) {
	al.logger.Info("asynq", v...)
}

func (al AsynqLogger) Error(v ...interface{}) {
	al.logger.Error("asynq", v...)
}

func (al AsynqLogger) Warn(v ...interface{}) {
	al.logger.Warn("asynq", v...)
}

func (al AsynqLogger) Fatal(v ...interface{}) {
	al.logger.Error("asynq", v...)
}

type InternalJobManagerImpl struct {
	client               *asynq.Client
	server               *asynq.Server
	scheduler            *asynq.Scheduler
	inspector            *asynq.Inspector
	mux                  *asynq.ServeMux
	middleware           JobTrackingMiddleware
	jobTypes             []JobType
	started              bool
	schedulerMutex       *redsync.Mutex
	cancelLeaderElection context.CancelFunc
	leaderStatusGauge    metric.Int64ObservableGauge // 0=not leader, 1=leader
	lockLastAttemptGauge metric.Int64ObservableGauge // unix-seconds timestamp
	leaderStatus         int64
	lockLastAttemptUnix  int64
}

type JobTrackingMiddleware interface {
	WrapHandle(w asynq.Handler) asynq.Handler
}

type JobTrackingMiddlewareImpl struct {
	stores.JobStore
}

// WrapHandle wraps a handler with middleware that logs the task type and payload of each processed task.
// If the wrapped handler returns an error, the error is logged with the task type and payload.
// This does not need to be called from Tasks themselves as the SubmitTask method does it for you.
func (m *JobTrackingMiddlewareImpl) WrapHandle(w asynq.Handler) asynq.Handler {
	return asynq.HandlerFunc(func(ctx context.Context, task *asynq.Task) error {
		ctx, span := otel.Tracer(task.Type()).Start(ctx, task.Type())
		defer func() {
			if span != nil {
				span.End()
			}
		}()
		taskID := task.ResultWriter().TaskID()
		payload := task.Payload()
		provider := strings.Split(task.Type(), ":")[0]
		jobName := strings.Split(task.Type(), ":")[1]
		span.SetAttributes(
			attribute.String("task_id", taskID),
			attribute.String("provider", provider),
			attribute.String("job_name", jobName),
			attribute.String("payload", string(payload)),
		)
		var minJobPayloadInfo JobPayloadInfo
		err := json.Unmarshal(payload, &minJobPayloadInfo)
		if err != nil {
			slog.Error("Error unmarshalling payload from task", slog.Any("error", err), slog.Any("task", task.Type()))
			return fmt.Errorf("failed to unmarshal payload: %w", err)
		}

		if minJobPayloadInfo.TraceID != "" {
			traceId, err := trace.TraceIDFromHex(minJobPayloadInfo.TraceID)
			if err != nil {
				slog.Error("Error parsing trace id from task", slog.Any("error", err), slog.Any("task", task.Type()))
			}
			spanId, err := trace.SpanIDFromHex(minJobPayloadInfo.SpanID)
			if err != nil {
				slog.Error("Error parsing span id from task", slog.Any("error", err), slog.Any("task", task.Type()))
			}
			if traceId.IsValid() && spanId.IsValid() {
				slog.Info("Adding trace link to span", slog.Any("trace_id", traceId), slog.Any("span_id", spanId))
				span.AddLink(trace.Link{
					SpanContext: trace.NewSpanContext(trace.SpanContextConfig{
						TraceID: traceId,
						SpanID:  spanId,
					}),
				})
			} else {
				slog.Info("Invalid trace id or span id", slog.Any("trace_id", traceId), slog.Any("span_id", spanId))
			}
		}

		jobInfo := &models.JobInfo{
			JobId:      taskID,
			JobName:    jobName,
			Provider:   models.JobProvider(provider),
			Parameters: payload,
			Status:     "processing",
		}
		err = m.JobStore.UpsertJob(ctx, jobInfo, true)
		if err != nil {
			slog.Error("Failed to upsert job", slog.Any("error", err))
			return fmt.Errorf("failed to upsert job: %w", err)
		}
		jobErr := w.ProcessTask(ctx, task)
		if jobErr != nil {
			jobInfo.Status = "failed"
			jobInfo.Error = jobErr.Error()
			span.RecordError(jobErr)
			span.SetStatus(codes.Error, jobErr.Error())
		} else {
			jobInfo.Status = "completed"
			jobInfo.EndTime = time.Now()
			jobInfo.Duration = int(jobInfo.EndTime.Sub(jobInfo.StartTime).Milliseconds())
		}
		jobInfoNoPayload := *jobInfo
		jobInfoNoPayload.Parameters = nil
		queue, ok := asynq.GetQueueName(ctx)
		if ok {
			span.SetAttributes(attribute.String("queue", queue))
		} else {
			span.SetAttributes(attribute.String("queue", "unknown"))
		}
		slog.Info("Job completed", slog.Any("jobInfo", jobInfoNoPayload), "queue", queue)
		err = m.JobStore.UpsertJob(ctx, jobInfo, false)
		if err != nil {
			return fmt.Errorf("failed to upsert job: %w", err)
		}
		return jobErr
	})
}

// NewAsyncTask creates a new asynq task with the given provider, jobType, and payload.
// The returned task is suitable for submission to an InternalJobManager.
// The task's type is set to provider:jobType and the payload is set to the given payload.
// Any additional options are passed through to the underlying asynq.NewTask call.
// in general this should only be called by Task struct methods or by testing code.
func NewAsyncTask(ctx context.Context, provider models.JobProvider, jobType JobType, payload []byte, opts ...asynq.Option) *asynq.Task {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		var payloadMap map[string]interface{}
		err := json.Unmarshal(payload, &payloadMap)
		if err != nil {
			slog.Error("Error unmarshalling payload when adding trace info", slog.Any("error", err))
		}
		payloadMap["trace_id"] = span.SpanContext().TraceID().String()
		payloadMap["span_id"] = span.SpanContext().SpanID().String()
		payload, err = json.Marshal(payloadMap)
		if err != nil {
			slog.Error("Error marshalling payload with trace info", slog.Any("error", err))
		}
	}
	return asynq.NewTask(string(provider)+":"+string(jobType), payload, opts...)
}

// NewInternalJobManager creates an InternalJobManager that manages the task queue.
//
// The returned InternalJobManager uses the given redisConfig to connect to redis.
// The redisConfig must contain the host, port, username, password, and the database
// to use. The redisConfig can also specify TLS configuration, which is used if
// redisConfig.TLSEnabled is true.
//
// The InternalJobManager is configured to use the following queues:
// - default: 10 concurrent workers
// - test: 10 concurrent workers
//
// The InternalJobManager uses the given auditRepository to store audit events.
// The auditRepository must be a valid AuditRepository.
func NewInternalJobManager(ctx context.Context, redisClient *redis.Client, jobStore stores.JobStore, schedulerOpts ...*asynq.SchedulerOpts) InternalJobManager {

	client := asynq.NewClientFromRedisClient(redisClient)

	queueConfig := map[string]int{}

	for _, queue := range GetJobQueues() {
		queueConfig[string(queue)] = 10
	}

	server := asynq.NewServerFromRedisClient(
		redisClient,
		asynq.Config{
			Concurrency: 100,
			Queues:      queueConfig,
			Logger:      &AsynqLogger{logger: slog.Default()},
		},
	)

	inspector := asynq.NewInspectorFromRedisClient(redisClient)
	middleware := &JobTrackingMiddlewareImpl{jobStore}

	mux := asynq.NewServeMux()

	var schedOpts *asynq.SchedulerOpts
	if len(schedulerOpts) > 0 && schedulerOpts[0] != nil {
		schedOpts = schedulerOpts[0]
	} else {
		schedOpts = &asynq.SchedulerOpts{
			Location: time.UTC,
		}
	}
	scheduler := asynq.NewSchedulerFromRedisClient(redisClient, schedOpts)

	pool := rsredis.NewPool(redisClient)
	rs := redsync.New(pool)
	schedulerMutex := rs.NewMutex(
		schedulerLockKey,
		redsync.WithExpiry(schedulerLockTTL),
		redsync.WithRetryDelay(schedulerRetryDelay),
		redsync.WithTries(1), // try once per attempt loop
	)

	meter := otel.GetMeterProvider().Meter("github.com/adalundhe/micron/internal/jobmanager")

	leaderGauge, err := meter.Int64ObservableGauge(
		"asynq.scheduler.leader_status",
		metric.WithDescription("1 if this instance currently holds the scheduler lock, 0 otherwise"),
		metric.WithUnit("1"),
	)
	if err != nil {
		slog.Error("failed to create leader status gauge", "err", err)
	}
	lockGauge, err := meter.Int64ObservableGauge(
		"asynq.scheduler.lock_last_attempt_time",
		metric.WithDescription("Unix epoch seconds of the last lock attempt/extend."),
		metric.WithUnit("s"),
	)
	if err != nil {
		slog.Error("failed to create lock last attempt gauge", "err", err)
	}

	jm := &InternalJobManagerImpl{client: client,
		server:               server,
		scheduler:            scheduler,
		mux:                  mux,
		inspector:            inspector,
		middleware:           middleware,
		schedulerMutex:       schedulerMutex,
		leaderStatusGauge:    leaderGauge,
		lockLastAttemptGauge: lockGauge,
	}

	_, err = meter.RegisterCallback(
		func(ctx context.Context, o metric.Observer) error {
			o.ObserveInt64(jm.leaderStatusGauge, atomic.LoadInt64(&jm.leaderStatus))
			o.ObserveInt64(jm.lockLastAttemptGauge, atomic.LoadInt64(&jm.lockLastAttemptUnix))
			return nil
		},
		leaderGauge, lockGauge,
	)
	if err != nil {
		slog.Error("failed to register callback for leader status gauge", "err", err)
	}

	return jm
}

// Close shuts down the internal job manager server and client if they are running.
//
// If the server is running, it will be shut down.
// If the client is running, it will be closed.
//
// This is useful for cleaning up resources when the internal job manager is no longer needed.
func (jm *InternalJobManagerImpl) Close() error {
	// release the lock (no‑op if we’re not the leader)
	// stop leader‑election goroutine
	if jm.cancelLeaderElection != nil {
		jm.cancelLeaderElection()
	}

	// best‑effort unlock
	if jm.schedulerMutex != nil {
		_, _ = jm.schedulerMutex.UnlockContext(context.Background())
	}

	if jm.scheduler != nil {
		jm.scheduler.Shutdown()
	}

	if jm.server != nil {
		slog.Info("Shutting down the internal job manager server")
		jm.server.Shutdown()
		jm.started = false
	}

	if jm.client != nil {
		slog.Info("Shutting down the internal job manager client")
		return jm.client.Close()
	}
	return nil
}

// StartServer starts the internal job manager server.
// This does not need to be called from a goroutine as it is not blocking.
// It will start the server and listen for incoming tasks.
// The server will exit when the process recieves a SIGTERM signal or when Close() is called.
func (jm *InternalJobManagerImpl) StartServer() error {
	if err := jm.server.Start(jm.mux); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	jm.cancelLeaderElection = cancel

	go jm.runLeaderElection(ctx)

	slog.Info("Internal job manager server started")
	jm.started = true
	return nil
}

// runLeaderElection starts the leader election process.
func (jm *InternalJobManagerImpl) runLeaderElection(ctx context.Context) {
	for {
		// try to get the lock (single attempt)
		if err := jm.schedulerMutex.LockContext(ctx); err != nil {
			select {
			case <-time.After(5 * time.Second):
				slog.Debug("failed to acquire scheduler lock, retrying", "err", err)
				atomic.StoreInt64(&jm.lockLastAttemptUnix, time.Now().Unix())
				atomic.StoreInt64(&jm.leaderStatus, 0)
				continue // try again
			case <-ctx.Done():
				return // shutting down
			}
		}

		slog.Info("acquired scheduler lock – starting scheduler")
		atomic.StoreInt64(&jm.leaderStatus, 1)
		if err := jm.scheduler.Start(); err != nil {
			slog.Error("scheduler exited with error", "err", err)
		}

		// keep the lock alive until lost or we’re shutting down
		ticker := time.NewTicker(10 * time.Second)
	loop:
		for {
			select {
			case <-ticker.C:
				ok, err := jm.schedulerMutex.ExtendContext(ctx)
				if !ok || err != nil {
					slog.Warn("lost scheduler lock – stopping scheduler")
					jm.scheduler.Shutdown()
					atomic.StoreInt64(&jm.leaderStatus, 0)
					_, _ = jm.schedulerMutex.UnlockContext(context.Background())
					break loop
				} else {
					slog.Debug("scheduler lock extended")
					atomic.StoreInt64(&jm.leaderStatus, 1)
				}

			case <-ctx.Done():
				jm.scheduler.Shutdown()
				_, _ = jm.schedulerMutex.UnlockContext(context.Background())
				return
			}
		}
	}
}

// RegisterHandler registers a handler for a specific job provider and job type.
// The handler will be called whenever a task with the specified job provider and
// job type is received.
func (jm *InternalJobManagerImpl) RegisterHandler(provider models.JobProvider, jobType JobType, handler asynq.Handler) error {
	if jm.started {
		return fmt.Errorf("server already started, cannot register handler")
	}
	jm.jobTypes = append(jm.jobTypes, jobType)
	jobUrn := fmt.Sprintf("%s:%s", provider, jobType)
	jm.mux.Handle(jobUrn, jm.middleware.WrapHandle(handler))
	return nil
}

func (jm *InternalJobManagerImpl) ListJobTypes() []JobType {
	return jm.jobTypes
}

// SubmitTask submits a task to the default queue
// If the provider is not found in the list of known job providers, an error is returned.
// If the job type is not found in the list of known job types, an error is returned.
// payloads must be json serializable
func (jm *InternalJobManagerImpl) SubmitTask(ctx context.Context, task *asynq.Task, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	jobInfo := strings.Split(task.Type(), ":")
	provider := jobInfo[0]
	jobType := jobInfo[1]
	var minJsonData JobPayloadInfo
	err := json.Unmarshal(task.Payload(), &minJsonData)
	if err != nil {
		return nil, fmt.Errorf("payloads must be json serializable: %w", err)
	}

	if !slices.Contains(models.GetJobProviders(), models.JobProvider(provider)) {
		return nil, fmt.Errorf("invalid job provider: %s", provider)
	}
	if !slices.Contains(jm.jobTypes, JobType(jobType)) {
		return nil, fmt.Errorf("invalid job type: %s", jobType)
	}

	asyncOpts := []asynq.Option{}
	asyncOpts = append(asyncOpts, opts...)
	asyncOpts = append(asyncOpts, asynq.Retention(TaskStorageDuration))
	asyncOpts = append(asyncOpts, asynq.Queue(string(JobQueueNameDefault)))

	hasMaxRetries := false
	for _, opt := range asyncOpts {
		if opt.Type() == asynq.MaxRetryOpt {
			hasMaxRetries = true
			break
		}
	}
	if !hasMaxRetries {
		// retires also apply to worker failures. so set the number of retires high enough to handle pod restarts and worker failures
		asyncOpts = append(asyncOpts, asynq.MaxRetry(DefaultTaskRetries))
	}

	slog.Info("submitting task", slog.String("provider", provider), slog.String("job_type", jobType))
	return jm.client.Enqueue(task, asyncOpts...)
}

// RegisterScheduledTask registers a scheduled task with the given cron spec.
func (jm *InternalJobManagerImpl) RegisterScheduledTask(cronSpec string, task *asynq.Task, opts ...asynq.Option) (string, error) {
	if jm.started {
		return "", fmt.Errorf("server already started; register tasks before StartServer")
	}
	if os.Getenv("DISABLE_SCHEDULED_TASKS") == "true" {
		slog.Info("scheduled tasks are disabled", slog.String("cron_spec", cronSpec), slog.String("task_type", fmt.Sprint(task.Type())))
		return "", nil
	}
	slog.Info("registering scheduled task", slog.String("cron_spec", cronSpec), slog.String("task_type", fmt.Sprint(task.Type())))
	return jm.scheduler.Register(cronSpec, task, opts...)
}

// ListCompletedTasks lists all completed tasks in the specified queue that were enqueued (and not scheduled).
func (jm *InternalJobManagerImpl) ListCompletedTasks(queue JobQueueName) ([]*asynq.TaskInfo, error) {
	return jm.inspector.ListCompletedTasks(string(queue), asynq.PageSize(100), asynq.Page(1))
}

// ListScheduledEntries lists all schedules.
func (jm *InternalJobManagerImpl) ListSchedulerEntries() ([]*asynq.SchedulerEntry, error) {
	return jm.inspector.SchedulerEntries()
}

// List all scheduler enqueue events for a specific schedule entry id.
// This returns the enqueued time and the task id for each event.
func (jm *InternalJobManagerImpl) ListSchedulerEnqueueEvents(entryID string) ([]*asynq.SchedulerEnqueueEvent, error) {
	return jm.inspector.ListSchedulerEnqueueEvents(entryID)
}

// WaitForJob waits until a job is completed in the specified queue.
// It will periodically check the status of the job and return an error
// if the job is not completed after a certain amount of time.
// Since this is blocking, it should be called in a goroutine to avoid blocking the main thread.
// The current usage is mostly for testing purposes.
func (jm *InternalJobManagerImpl) WaitForJob(queue JobQueueName, taskId string) error {
	for {
		isCompleted, err := jm.IsTaskCompleted(queue, taskId)
		if err != nil {
			return err
		}
		if isCompleted {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
}

// CancelTask cancels a task. It does not confirm the task has actually been cancelled.
// see https://pkg.go.dev/github.com/hibiken/asynq#Inspector.CancelProcessing
func (jm *InternalJobManagerImpl) CancelTask(taskId string) error {
	return jm.inspector.CancelProcessing(taskId)
}

// ArchiveTask archives a task in the specified queue.
// Archiving a task removes it from the active task list, but does not delete it.
// see https://pkg.go.dev/github.com/hibiken/asynq#Inspector.ArchiveTask
func (jm *InternalJobManagerImpl) ArchiveTask(queue JobQueueName, taskId string) error {
	return jm.inspector.ArchiveTask(string(queue), taskId)
}

// GetTaskInfo retrieves the task info for a task in the specified queue.
// If the task does not exist in the specified queue, an error is returned.
func (jm *InternalJobManagerImpl) GetTaskInfo(queue JobQueueName, taskId string) (*asynq.TaskInfo, error) {
	return jm.inspector.GetTaskInfo(string(queue), taskId)
}

// IsTaskCompleted returns true if the specified task is completed in the specified queue.
// It does not guarantee that the task was completed successfully, just that it is in the completed or archived state.
// An error is returned if the task does not exist in the specified queue.
func (jm *InternalJobManagerImpl) IsTaskCompleted(queue JobQueueName, taskId string) (bool, error) {
	taskInfo, err := jm.inspector.GetTaskInfo(string(queue), taskId)
	if err != nil {
		return false, err
	}
	return slices.Contains([]asynq.TaskState{asynq.TaskStateCompleted, asynq.TaskStateArchived}, taskInfo.State), nil
}
