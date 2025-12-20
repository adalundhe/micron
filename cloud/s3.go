package cloud

import (
	"context"
	"time"

	"github.com/adalundhe/micron/config"
	micronAWS "github.com/adalundhe/micron/provider/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3Impl struct {
	client *s3.Client
	presign *s3.PresignClient
	config aws.Config
}

type S3Opts struct {
	ConfigOpts []func(*awsconfig.LoadOptions) error
	S3ConfigOpts []func(*s3.Options)
	S3PresignOpts []func(*s3.PresignOptions)
}

type Tag struct {
	Key string
	Value string
}

type Bucket struct {
	Name string
	Opts []func(*s3.Options)
	Tags []Tag
}

type Part struct {
	ContentLength int64
	SHA string

}

type DeleteBucketRequest struct {
	Bucket string
	Version string
}

type DeleteFileRequest struct {
	Bucket string
	Key string
	Version string
}

type DownloadRequest struct {
	Bucket string
	Key string
	PartChunkSizeMB int64
}

type ProvisionMultiPartUploadRequest struct {
	Bucket string
	Key string
	ContentLength int64
	ContentType string
	ChecksumAlgorithm string
	ChecksumType string
	Expires int64
	UploadSHA string
	UploadOps []func(*s3.Options)
	PresignOpts []func(*s3.PresignOptions)
	ServerSideEncryption string
	Parts []Part
	Tags []Tag
}


type ProvisionedMultiPartUpload struct {
	UploadId string
	Parts []*v4.PresignedHTTPRequest
	
}

type CompleteMultiPartUploadReqeust struct {
	Bucket string
	Key string
	UploadID string
	ChecksumAlgorithm string
	ChecksumType string
	UploadSHA string
}

type ListPartsRequest struct {
	Bucket string
	Key string
	UploadID string
	Parts int32

}

type ProvisionDownloadRequest struct {
	Bucket string
	Key string
	ChecksumAlgorithm string
	ChecksumMode string
	Parts int32

}

type ProvisionedMuliPartDownload struct {
	Bucket string
	Key string
	ObjectPresignedRequest *v4.PresignedHTTPRequest
	PartPresignedRequests []*v4.PresignedHTTPRequest
}

type AbortMultipartUploadRequest struct {
	Bucket string
	Key string
	UploadId string
}

type RestoreObjectRequest struct {
	Bucket string
	Key string
	ChecksumAlgorithm string
}

type ListBucketsRequest struct {
	Region string
	ContinuationToken string
	Limit int32
	Prefix string
}

type ListObjectVersionsRequest struct {
	Bucket string
	Limit int32
	Prefix string
}

type ListInProgressMultiPartUploadsRequest struct {
	Bucket string
	Limit int32
	Prefix string
	UploadId string
}

type ListObjectsRequest struct {
	Bucket string
	ContinuationToken string
	Limit int32
	Prefix string
	StartingKey string
}

type UpdateObjectTagsRequest struct {
	Bucket string
	Key string
	Version string
	Tags []Tag
}

type GetObjectTagsRequest struct {
	Bucket string
	Key string
	Version string
}

type DeleteObjectTagsRequest struct {
	Bucket string
	Key string
	Version string
}

type GetBucketTagsRequest struct {
	Bucket string
}

type UpdateBucketTagsRequest struct {
	Bucket string
}

type DeleteBucketTagsRequest struct {
	Bucket string
}

type S3 interface{
	CreateBucket(ctx context.Context, req *Bucket) (*s3.CreateBucketOutput, error)
	DownloadFile(ctx context.Context, req *DownloadRequest) ([]byte, error)
	DeleteFile(ctx context.Context, req *DeleteFileRequest) (*s3.DeleteObjectOutput, error)
	DeleteBucket(ctx context.Context, req *DeleteBucketRequest) (*s3.DeleteBucketOutput, error)
	ProvisionMultiPresignedPartUpload(ctx context.Context, req *ProvisionMultiPartUploadRequest) (*ProvisionedMultiPartUpload, error)
	ProvisionPresignedDownloadWithParts(ctx context.Context, req *ProvisionDownloadRequest) (*ProvisionedMuliPartDownload, error)
	AbortMultipartUpload(ctx context.Context, req *AbortMultipartUploadRequest) (*s3.AbortMultipartUploadOutput, error)
	CompleteMultiPartUpload(ctx context.Context, req *CompleteMultiPartUploadReqeust) (*s3.CompleteMultipartUploadOutput, error)
	ListMultipartUploadParts(ctx context.Context, req *ListPartsRequest) (*s3.ListPartsOutput, error)
	RestoreObject(ctx context.Context, req *RestoreObjectRequest) (*s3.RestoreObjectOutput, error)
	ListAllBuckets(ctx context.Context, req *ListBucketsRequest) (*s3.ListBucketsOutput, error)
	ListAllDirectoryBuckets(ctx context.Context, req *ListBucketsRequest) (*s3.ListDirectoryBucketsOutput, error)
	ListObjectVersions(ctx context.Context, req *ListObjectVersionsRequest) (*s3.ListObjectVersionsOutput, error)
	ListInProgressMultiPartUploads(ctx context.Context, req *ListInProgressMultiPartUploadsRequest) (*s3.ListMultipartUploadsOutput, error)
	ListObjects(ctx context.Context, req *ListObjectsRequest) (*s3.ListObjectsV2Output, error)
	GetObjectTags(ctx context.Context, req *GetObjectTagsRequest) (*s3.GetObjectTaggingOutput, error)
	DeleteObjectTags(ctx context.Context, req *DeleteObjectTagsRequest) (*s3.DeleteObjectTaggingOutput, error)
	UpdateObjectTags(ctx context.Context, req *UpdateObjectTagsRequest) (*s3.PutObjectTaggingOutput, error)
	GetBucketTagging(ctx context.Context, req *GetBucketTagsRequest) (*s3.GetBucketTaggingOutput, error)
	UpdateBucketTagging(ctx context.Context, req *UpdateBucketTagsRequest) (*s3.PutBucketTaggingOutput, error)
	DeleteBucketTagging(ctx context.Context, req *DeleteBucketTagsRequest) (*s3.DeleteBucketTaggingOutput, error)
}


func NewS3(ctx context.Context, cfg *config.Config, opts S3Opts) (S3, error) {

	awsProvider, err := micronAWS.NewAwsProvider(ctx, cfg.Providers.Aws[cfg.Api.Env], opts.ConfigOpts...)
	if err != nil {
		return nil, err
	}

	awsCfg, err := awsProvider.GetConfig(ctx)
	if err != nil {
		return nil, err
	}

	client := s3.NewFromConfig(awsCfg, opts.S3ConfigOpts...)

	presign := s3.NewPresignClient(client, opts.S3PresignOpts...)

	return &S3Impl{
		client: client,
		presign: presign,
		config: awsCfg,
	}, nil
	
}

func (s *S3Impl) CreateBucket(ctx context.Context, req *Bucket) (*s3.CreateBucketOutput, error)  {

	tags := []types.Tag{}
	for _, tag := range req.Tags {
		tags = append(tags, types.Tag{
			Key: &tag.Key,
			Value: &tag.Value,
		})
	}

	return s.client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: &req.Name,
		CreateBucketConfiguration: &types.CreateBucketConfiguration{
			Tags: tags,
		},
	}, req.Opts...)
}


func (s *S3Impl) DownloadFile(ctx context.Context, req *DownloadRequest) ([]byte, error) {
		downloader := manager.NewDownloader(s.client, func(d *manager.Downloader) {
		d.PartSize = req.PartChunkSizeMB * 1024 * 1024
	})
	buffer := manager.NewWriteAtBuffer([]byte{})
	_, err := downloader.Download(ctx, buffer, &s3.GetObjectInput{
		Bucket: aws.String(req.Bucket),
		Key:    aws.String(req.Key),
	})
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), err
}

func (s *S3Impl) DeleteFile(ctx context.Context, req *DeleteFileRequest) (*s3.DeleteObjectOutput, error) {

	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	versionId := &req.Version
	if req.Version == "" {
		versionId = nil
	}

	return s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &req.Bucket,
		Key: &req.Key,
		ExpectedBucketOwner: &creds.AccountID,
		VersionId: versionId,
	})
}

func (s *S3Impl) DeleteBucket(ctx context.Context, req *DeleteBucketRequest) (*s3.DeleteBucketOutput, error) {

	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	return s.client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: &req.Bucket,
		ExpectedBucketOwner: &creds.AccountID,
	})
}


func (s *S3Impl) ProvisionMultiPresignedPartUpload(ctx context.Context, req *ProvisionMultiPartUploadRequest) (*ProvisionedMultiPartUpload, error) {

	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	if req.ChecksumAlgorithm == "" {
		req.ChecksumAlgorithm = string(types.ChecksumAlgorithmSha256)
	}

	if req.ChecksumType == "" {
		req.ChecksumType = string(types.ChecksumModeEnabled)
	}

	if req.ServerSideEncryption == "" {
		req.ServerSideEncryption = string(types.ServerSideEncryptionAes256)
	}

	var expires time.Time
	if req.Expires > 0 {
		expires = time.Unix(req.Expires, 0)
	}

	input := &s3.CreateMultipartUploadInput{
		Bucket: &req.Bucket,
		Key: &req.Key,
		Expires: &expires,
		ChecksumAlgorithm: types.ChecksumAlgorithm(req.ChecksumAlgorithm),
		ChecksumType: types.ChecksumType(req.ChecksumType),
		ExpectedBucketOwner: &creds.AccountID,
		ContentType: &req.ContentType,
		ServerSideEncryption: types.ServerSideEncryption(req.ServerSideEncryption),
	}

	if req.ContentType == "" {
		input.ContentType = nil
	}


	multiPartUpload, err := s.client.CreateMultipartUpload(ctx, input, req.UploadOps...)
	if err != nil {
		return nil, err
	}

	requests := []*v4.PresignedHTTPRequest{}

	for idx, part := range req.Parts {

		chunkId := int32(idx)

		partInput := &s3.UploadPartInput{
			Bucket: multiPartUpload.Bucket,
			Key: multiPartUpload.Key,
			PartNumber:&chunkId,
			ChecksumSHA256: &part.SHA,
			ChecksumAlgorithm: multiPartUpload.ChecksumAlgorithm,
			ContentLength: &part.ContentLength,
			UploadId: multiPartUpload.UploadId,
			ExpectedBucketOwner: &creds.AccountID,
		}


		if part.SHA == "" {
			partInput.ChecksumSHA256 = nil
		}

		if part.ContentLength == 0 {
			partInput.ContentLength = nil
		}

		if multiPartUpload.ChecksumAlgorithm == "" {
			partInput.ChecksumAlgorithm = types.ChecksumAlgorithmSha256
		}

		presigned, err := s.presign.PresignUploadPart(ctx, partInput, req.PresignOpts...)

		if err != nil {
			return nil, err
		}

		requests = append(requests, presigned)
	}

	return &ProvisionedMultiPartUpload{
		UploadId: *multiPartUpload.UploadId,
		Parts: requests,
	}, nil

}

func (s *S3Impl) ProvisionPresignedDownloadWithParts(ctx context.Context, req *ProvisionDownloadRequest) (*ProvisionedMuliPartDownload, error) {
	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	if req.ChecksumMode == "" {
		req.ChecksumMode = string(types.ChecksumModeEnabled)
	}

	object, err := s.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: &req.Bucket,
		Key: &req.Key,
		ChecksumMode: types.ChecksumMode(req.ChecksumMode),
		ExpectedBucketOwner: &creds.AccountID,
	})

	if err != nil {
		return nil, err
	}

	partDownloads := []*v4.PresignedHTTPRequest{}
	for partId := range req.Parts {

		if req.ChecksumMode == "" {
			req.ChecksumMode = string(types.ChecksumModeEnabled)
		}

		part, err := s.presign.PresignGetObject(ctx, &s3.GetObjectInput{
			Bucket: &req.Bucket,
			Key: &req.Key,
			ChecksumMode: types.ChecksumMode(req.ChecksumMode),
			ExpectedBucketOwner: &creds.AccountID,
			PartNumber: &partId,
		})

		if err != nil {
			return nil, err
		}

		partDownloads = append(partDownloads, part)

	}

	return &ProvisionedMuliPartDownload{
		Bucket: req.Bucket,
		Key:  req.Key,
		ObjectPresignedRequest: object,
		PartPresignedRequests: partDownloads,
	}, nil
}

func (s *S3Impl) AbortMultipartUpload(ctx context.Context, req *AbortMultipartUploadRequest) (*s3.AbortMultipartUploadOutput, error) {
	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	return s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket: &req.Bucket,
		Key: &req.Key,
		UploadId: &req.UploadId,
		ExpectedBucketOwner: &creds.AccountID,
	})
}


func (s *S3Impl) CompleteMultiPartUpload(ctx context.Context, req *CompleteMultiPartUploadReqeust) (*s3.CompleteMultipartUploadOutput, error) {

	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	input := &s3.CompleteMultipartUploadInput{
		Bucket: &req.Bucket,
		Key: &req.Key,
		UploadId: &req.UploadID,
		ExpectedBucketOwner: &creds.AccountID,
		ChecksumSHA256: &req.UploadSHA,
		ChecksumType: types.ChecksumType(req.ChecksumType),

	}

	if req.UploadSHA == "" {
		input.ChecksumSHA256 = nil
	}

	return s.client.CompleteMultipartUpload(ctx, input)
}

func (s *S3Impl) ListMultipartUploadParts(ctx context.Context, req *ListPartsRequest) (*s3.ListPartsOutput, error) {

	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	input := &s3.ListPartsInput{
		Bucket: &req.Bucket,
		Key: &req.Key,
		UploadId: &req.UploadID,
		MaxParts: &req.Parts,
		ExpectedBucketOwner: &creds.AccountID,
	}


	if req.Parts == 0 {
		input.MaxParts = nil
	}

	return s.client.ListParts(ctx, input)
}

func (s *S3Impl) RestoreObject(ctx context.Context, req *RestoreObjectRequest) (*s3.RestoreObjectOutput, error) {
	
	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	input := &s3.RestoreObjectInput{
		Bucket: &req.Bucket,
		Key: &req.Key,
		ExpectedBucketOwner: &creds.AccountID,
		ChecksumAlgorithm: types.ChecksumAlgorithm(req.ChecksumAlgorithm),
	}

	if req.ChecksumAlgorithm == "" {
		input.ChecksumAlgorithm = types.ChecksumAlgorithmSha256
	}

	return s.client.RestoreObject(ctx, input)
}

func (s *S3Impl) ListAllBuckets(ctx context.Context, req *ListBucketsRequest) (*s3.ListBucketsOutput, error) {

	input := &s3.ListBucketsInput{
		BucketRegion: &req.Region,
		ContinuationToken: &req.ContinuationToken,
		MaxBuckets: &req.Limit,
		Prefix: &req.Prefix,
	}

	if req.Limit == 0 {
		input.MaxBuckets = aws.Int32(10)
	}
	
	if req.Region == "" {
		input.BucketRegion = &s.config.Region
	}

	if req.ContinuationToken == "" {
		input.ContinuationToken = nil
	}

	if req.Prefix == "" {
		input.Prefix = nil
	}

	return s.client.ListBuckets(ctx, input)
}

func (s *S3Impl) ListAllDirectoryBuckets(ctx context.Context, req *ListBucketsRequest) (*s3.ListDirectoryBucketsOutput, error) {

	continuationToken := &req.ContinuationToken
	if req.ContinuationToken == "" {
		continuationToken = nil
	}

	if req.Limit == 0 {
		req.Limit = 10
	}

	return s.client.ListDirectoryBuckets(ctx, &s3.ListDirectoryBucketsInput{
		ContinuationToken: continuationToken,
		MaxDirectoryBuckets: &req.Limit,
	})
}

func (s *S3Impl) ListObjectVersions(ctx context.Context, req *ListObjectVersionsRequest) (*s3.ListObjectVersionsOutput, error) {
	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	if req.Limit == 0 {
		req.Limit = 10
	}

	prefix := &req.Prefix
	if req.Prefix == "" {
		prefix = nil
	}

	return s.client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket: &req.Bucket,
		MaxKeys: &req.Limit,
		Prefix: prefix,
		ExpectedBucketOwner: &creds.AccountID,
	})
}

func (s *S3Impl) ListInProgressMultiPartUploads(ctx context.Context, req *ListInProgressMultiPartUploadsRequest) (*s3.ListMultipartUploadsOutput, error) {

	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}


	if req.Limit == 0 {
		req.Limit = 10
	}

	prefix := &req.Prefix
	if req.Prefix == "" {
		prefix = nil
	}

	uploadIdMarker := &req.UploadId
	if req.UploadId == "" {
		uploadIdMarker = nil
	}

	return s.client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket: &req.Bucket,
		MaxUploads: &req.Limit,
		Prefix: prefix,
		ExpectedBucketOwner: &creds.AccountID,
		UploadIdMarker: uploadIdMarker,
	})
}

func (s *S3Impl) ListObjects(ctx context.Context, req *ListObjectsRequest) (*s3.ListObjectsV2Output, error) {
	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	
	bucket := &req.Bucket
	if req.Bucket == "" {
		bucket = nil
	}

	continuationToken := &req.ContinuationToken
	if req.ContinuationToken == "" {
		continuationToken = nil
	}

	if req.Limit == 0 {
		req.Limit = 10
	}

	prefix := &req.Prefix
	if req.Prefix == "" {
		prefix = nil
	}

	startingKey := &req.StartingKey
	if req.StartingKey == "" {
		startingKey = nil
	}

	return s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: bucket,
		ContinuationToken: continuationToken,
		MaxKeys: &req.Limit,
		Prefix: prefix,
		StartAfter: startingKey,
		ExpectedBucketOwner: &creds.AccountID,
	})

}

func (s *S3Impl) GetObjectTags(ctx context.Context, req *GetObjectTagsRequest) (*s3.GetObjectTaggingOutput, error) {
	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	
	versionId := &req.Version
	if req.Version == "" {
		versionId = nil
	}


	return s.client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
		Bucket: &req.Bucket,
		Key: &req.Key,
		VersionId: versionId,
		ExpectedBucketOwner: &creds.AccountID,
	})

}

func (s *S3Impl) DeleteObjectTags(ctx context.Context, req *DeleteObjectTagsRequest) (*s3.DeleteObjectTaggingOutput, error) {
	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	
	versionId := &req.Version
	if req.Version == "" {
		versionId = nil
	}


	return s.client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
		Bucket: &req.Bucket,
		Key: &req.Key,
		VersionId: versionId,
		ExpectedBucketOwner: &creds.AccountID,
	})

}

func (s *S3Impl) UpdateObjectTags(ctx context.Context, req *UpdateObjectTagsRequest) (*s3.PutObjectTaggingOutput, error) {
	tags := &types.Tagging{}
	for _, tag := range req.Tags {
		tags.TagSet = append(tags.TagSet, types.Tag{
			Key: &tag.Key,
			Value: &tag.Value,
		})
	}
	
	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	versionId := &req.Version
	if req.Version == "" {
		versionId = nil
	}

	return s.client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
		Bucket: &req.Bucket,
		Key: &req.Key,
		Tagging: tags,
		VersionId: versionId,
		ExpectedBucketOwner: &creds.AccountID,
	})	
}


func (s *S3Impl) GetBucketTagging(ctx context.Context, req *GetBucketTagsRequest) (*s3.GetBucketTaggingOutput, error) {
	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	return s.client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
		Bucket: &req.Bucket,
		ExpectedBucketOwner: &creds.AccountID,
	})
}

func (s *S3Impl) UpdateBucketTagging(ctx context.Context, req *UpdateBucketTagsRequest) (*s3.PutBucketTaggingOutput, error) {
	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	return s.client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
		Bucket: &req.Bucket,
		ExpectedBucketOwner: &creds.AccountID,
	})
}

func (s *S3Impl) DeleteBucketTagging(ctx context.Context, req *DeleteBucketTagsRequest) (*s3.DeleteBucketTaggingOutput, error) {
	creds, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	return s.client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
		Bucket: &req.Bucket,
		ExpectedBucketOwner: &creds.AccountID,
	})
}