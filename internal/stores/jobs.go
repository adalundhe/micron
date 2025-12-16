package stores

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/adalundhe/micron/internal/models"
	"github.com/uptrace/bun"
)

type JobStore interface {
	CreateJob(ctx context.Context, job *models.JobInfo) error
	GetJobByID(ctx context.Context, id int64) (*models.JobInfo, error)
	GetJobByJobIdAndProvider(ctx context.Context, jobId string, jobProvider models.JobProvider) (*models.JobInfo, error)
	UpdateJob(ctx context.Context, job *models.JobInfo) error
	UpsertJob(ctx context.Context, job *models.JobInfo, incrementRetry bool) error
	DeleteJob(ctx context.Context, id int64) error
	GetPage(ctx context.Context, jobName string, cursor *Cursor, limit int) ([]*models.JobInfo, *Cursor, error)
}

type JobStoreImpl struct {
	db *bun.DB
}

func NewJobStore(db *bun.DB) *JobStoreImpl {
	return &JobStoreImpl{db: db}
}

// CreateJob creates a new job information in the database
// This should generally not be used directly and instead use UpsertJob
// this is because JobId and Provider are not unique in the database due to the partitioned table
// UpsertJob will check if the job already exists and update it if it does
func (s *JobStoreImpl) CreateJob(ctx context.Context, job *models.JobInfo) error {
	if job.Id != 0 {
		return fmt.Errorf("do not set id when creating job")
	}
	job.StartTime = time.Now()
	job.UpdatedAt = job.StartTime
	_, err := s.db.NewInsert().Model(job).Exec(ctx)
	return err
}

func (s *JobStoreImpl) UpsertJob(ctx context.Context, job *models.JobInfo, incrementRetry bool) error {
	if job.Id == 0 {
		current_job, err := s.GetJobByJobIdAndProvider(ctx, job.JobId, job.Provider)
		if err != nil {
			return s.CreateJob(ctx, job)
		}
		job.Id = current_job.Id
	}
	if incrementRetry {
		job.Retries += 1
	}
	err := s.UpdateJob(ctx, job)
	return err
}

func (s *JobStoreImpl) GetJobByID(ctx context.Context, id int64) (*models.JobInfo, error) {
	job := new(models.JobInfo)
	err := s.db.NewSelect().Model(job).Where("id = ?", id).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return job, nil
}

func (s *JobStoreImpl) GetJobByJobIdAndProvider(ctx context.Context, jobId string, jobProvider models.JobProvider) (*models.JobInfo, error) {
	job := new(models.JobInfo)
	err := s.db.NewSelect().Model(job).Where("job_id = ? AND provider = ?", jobId, string(jobProvider)).Scan(ctx)
	if err != nil || job == nil {
		return nil, fmt.Errorf("job not found: %w", err)
	}
	return job, nil
}

func (s *JobStoreImpl) UpdateJob(ctx context.Context, job *models.JobInfo) error {
	job.UpdatedAt = time.Now()
	_, err := s.db.NewUpdate().Model(job).WherePK().Exec(ctx)
	return err
}

func (s *JobStoreImpl) DeleteJob(ctx context.Context, id int64) error {
	_, err := s.db.NewDelete().Model((*models.JobInfo)(nil)).Where("id = ?", id).Exec(ctx)
	return err
}

func (s *JobStoreImpl) ListJobs(ctx context.Context, limit, offset int) ([]*models.JobInfo, error) {
	var jobs []*models.JobInfo
	err := s.db.NewSelect().Model(&jobs).Limit(limit).Offset(offset).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return jobs, nil
}

func (s *JobStoreImpl) GetPage(ctx context.Context, jobName string, cursor *Cursor, limit int) ([]*models.JobInfo, *Cursor, error) {
	var jobs []*models.JobInfo
	if cursor == nil {
		cursor = &Cursor{}
	}
	query := s.db.NewSelect().Model(&jobs)
	query, err := IdPagination(query, cursor)
	if err != nil {
		return nil, nil, err
	}
	if jobName != "" {
		query = query.Where("job_name = ?", jobName)
	}
	query = query.Limit(limit)
	err = query.Scan(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(jobs) == 0 {
		return jobs, nil, nil
	}
	// could do this in sql, but since the limit should be small it's less complicated to do it in go
	if cursor.PaginationType == PaginationTypePrev {
		slices.Reverse(jobs)
		return jobs, &Cursor{End: jobs[len(jobs)-1].Id, Start: jobs[0].Id}, nil
	}
	return jobs, &Cursor{End: jobs[len(jobs)-1].Id, Start: jobs[0].Id}, nil
}
