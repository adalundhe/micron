package aws

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/adalundhe/micron/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	defaultRegion = "us-west-2"
)

type AWSProvider interface {
	GetCredentialCache() *aws.CredentialsCache
	Retrieve(ctx context.Context) (aws.Credentials, error)
	GetConfig(ctx context.Context) (aws.Config, error)
}

type AWSProviderFactory interface {
	GetProvider(ctx context.Context, name string) (AWSProvider, error)
}

type AWSProviderFactoryImpl struct {
	CachedProviders map[string]AWSProvider
	providerConfigs map[string]*config.AwsConfig
}

type Aws struct {
	credentialCache *aws.CredentialsCache
	region          string
}

func (a *Aws) GetCredentialCache() *aws.CredentialsCache {
	return a.credentialCache
}

func (a *Aws) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return a.credentialCache.Retrieve(ctx)
}

func (a *Aws) GetConfig(ctx context.Context) (aws.Config, error) {
	return awsconfig.LoadDefaultConfig(ctx, func(lo *awsconfig.LoadOptions) error {
		lo.Region = a.region
		lo.Credentials = a.credentialCache
		return nil
	})
}

func NewAwsProviderFactory(ctx context.Context, cfgs map[string]*config.AwsConfig) *AWSProviderFactoryImpl {
	cachedProviders := make(map[string]AWSProvider, len(cfgs))
	return &AWSProviderFactoryImpl{
		CachedProviders: cachedProviders,
		providerConfigs: cfgs,
	}
}

func (p *AWSProviderFactoryImpl) GetProvider(ctx context.Context, name string) (AWSProvider, error) {
	provider, ok := p.CachedProviders[name]
	if !ok {
		var err error
		p.CachedProviders[name], err = NewAwsProvider(ctx, p.providerConfigs[name])
		if err != nil {
			return nil, fmt.Errorf("failed to create AWS provider for %s. Reason: %w", name, err)
		}
		return p.CachedProviders[name], nil
	}

	return provider, nil
}

func NewAwsProvider(ctx context.Context, cfg *config.AwsConfig, awsOptFns ...func(*awsconfig.LoadOptions) error) (*Aws, error) {

	if cfg == nil {
		return nil, fmt.Errorf("AWS config is nil")
	}

	awsRegion := cfg.Region
	if awsRegion == "" {
		awsRegion = defaultRegion
	}

	awsOptFns = append(awsOptFns, func(lo *awsconfig.LoadOptions) error {
		lo.Region = awsRegion
		if cfg.Profile != "" {
			lo.SharedConfigProfile = cfg.Profile
		}
		return nil
	})

	defaultConfig, err := awsconfig.LoadDefaultConfig(ctx, awsOptFns...)
	if err != nil {
		return nil, fmt.Errorf("failed to load default AWS config: %w", err)
	}

	if cfg.RoleArn == "" {
		return &Aws{
			credentialCache: aws.NewCredentialsCache(defaultConfig.Credentials),
		}, nil
	}

	stsClient := sts.NewFromConfig(defaultConfig)
	hostname, err := os.Hostname()
	if err != nil {
		slog.Warn("Failed to get hostname for AWS session", slog.Any("error", err))
		hostname = "unknown"
	}

	stsProvider := stscreds.NewAssumeRoleProvider(stsClient, cfg.RoleArn, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = fmt.Sprintf("micron-%s-%s", cfg.Name, hostname)
	})

	_, err = stsProvider.Retrieve(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}

	return &Aws{
		credentialCache: aws.NewCredentialsCache(stsProvider),
		region:          awsRegion,
	}, nil
}

func AwsString(s string) *string {
	return &s
}

func AwsInt32(i int32) *int32 {
	return &i
}
func AwsInt16to32(i int16) *int32 {
	v := int32(i)
	return &v
}
