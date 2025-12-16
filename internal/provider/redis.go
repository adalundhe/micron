package provider

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/adalundhe/micron/internal/config"
	awsprovider "github.com/adalundhe/micron/internal/provider/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/redis/go-redis/v9"
)

type Redis struct {
	client *redis.Client
}

const (
	ElasticacheReplicationGroupExtractPattern = `^(?:master|replica)\.([^.]+)\..*\.cache\.amazonaws\.com$`
	defaultAwsRegion                          = "us-west-2"
)

type RedisConfigOpt struct {
	AWSProviderFactory awsprovider.AWSProviderFactory
}

type RedisConfigOpts func(*RedisConfigOpt)

var ErrRedisPingFailed = errors.New("redis ping failed")

/*
taken from a mixture of https://github.com/aws/aws-sdk-go-v2/blob/249090ec218d0e6ab266a47a759baab368bb6b1f/feature/rds/auth/connect.go#L47-L102 and https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/auth-iam.html
*/
func NewRedisAwsCredentialsProvider(credCache *aws.CredentialsCache, cfg *config.RedisConfig) (func(ctx context.Context) (string, string, error), error) {
	replicationGroupID := cfg.ReplicationGroupID
	if replicationGroupID == "" {
		host_parts := regexp.MustCompile(ElasticacheReplicationGroupExtractPattern).FindStringSubmatch(cfg.Host)
		if len(host_parts) < 2 {
			return nil, errors.New("unable to determine replication group id from host and replication group id not provided")
		}
		replicationGroupID = host_parts[1]
	}

	if cfg.Username == "" {
		return nil, errors.New("username not provided")
	}

	return func(ctx context.Context) (string, string, error) {
		creds, err := credCache.Retrieve(ctx)
		if err != nil {
			return "", "", err
		}
		signer := v4.NewSigner()
		u, err := url.Parse(fmt.Sprintf("http://%s/", replicationGroupID))
		if err != nil {
			return "", "", err
		}
		query := u.Query()
		query.Add("Action", "connect")
		query.Add("User", cfg.Username)
		query.Add("X-Amz-Expires", "900") // 15 minute expiry
		u.RawQuery = query.Encode()
		req, err := http.NewRequestWithContext(ctx, "GET", u.String(), strings.NewReader(""))
		if err != nil {
			return "", "", err
		}
		region := defaultAwsRegion
		if cfg.AwsRegion != "" {
			region = cfg.AwsRegion
		}
		// the hash is a sha256 hash of the empty string
		signedUri, _, err := signer.PresignHTTP(ctx, creds, req, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "elasticache", region, time.Now())
		if err != nil {
			return "", "", err
		}
		return cfg.Username, strings.Replace(signedUri, "http://", "", 1), nil
	}, nil
}

func NewRedisStaticCredentialsProvider(cfg *config.RedisConfig) (func(ctx context.Context) (string, string, error), error) {
	return func(ctx context.Context) (string, string, error) {
		return cfg.Username, cfg.Password, nil
	}, nil
}

func NewRedisClient(cfg *config.RedisConfig, cfgOpts ...RedisConfigOpts) (*redis.Client, error) {
	if cfg == nil {
		return nil, errors.New("missing redis config")
	}

	if cfg.Host == "" {
		return nil, errors.New("missing redis host")
	}

	if cfg.Port == 0 {
		return nil, errors.New("missing redis port")
	}

	options := &redis.Options{
		Addr: fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		DB:   cfg.DB,
	}

	if cfg.TLSEnabled {
		options.TLSConfig = &tls.Config{
			InsecureSkipVerify: cfg.SkipTLSVerify,
		}
	}

	redisOptions := &RedisConfigOpt{}

	for _, opt := range cfgOpts {
		opt(redisOptions)
	}

	slog.Info("connecting to redis at %s:%d", slog.String("host", cfg.Host), slog.Int("port", cfg.Port))
	slog.Info("using auth type %s", slog.String("auth_type", string(cfg.AuthType)))

	switch cfg.AuthType {
	case config.RedisAuthAws:
		if redisOptions.AWSProviderFactory == nil {
			return nil, errors.New("missing aws provider factory")
		}
		slog.Info("using aws credentials provider for redis")
		credCache, err := redisOptions.AWSProviderFactory.GetProvider(context.Background(), cfg.AwsConfigName)
		if err != nil {
			return nil, err
		}
		provider, err := NewRedisAwsCredentialsProvider(credCache.GetCredentialCache(), cfg)
		if err != nil {
			return nil, err
		}
		options.CredentialsProviderContext = provider
	case config.RedisAuthPassword:
		slog.Info("using static credentials provider for redis")
		provider, err := NewRedisStaticCredentialsProvider(cfg)
		if err != nil {
			return nil, err
		}
		options.CredentialsProviderContext = provider
	}

	client := redis.NewClient(options)
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to redis at %s:%d: %w", cfg.Host, cfg.Port, err)
	}
	return client, nil
}

// NewRedisUniversalOptions creates redis.UniversalOptions from RedisConfig with credential provider support
func NewRedisUniversalOptions(cfg *config.RedisConfig, cfgOpts ...RedisConfigOpts) (*redis.UniversalOptions, error) {
	if cfg == nil {
		return nil, errors.New("missing redis config")
	}

	if cfg.Host == "" {
		return nil, errors.New("missing redis host")
	}

	if cfg.Port == 0 {
		return nil, errors.New("missing redis port")
	}

	options := &redis.UniversalOptions{
		Addrs: []string{fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)},
		DB:    cfg.DB,
	}

	if cfg.TLSEnabled {
		options.TLSConfig = &tls.Config{
			InsecureSkipVerify: cfg.SkipTLSVerify,
		}
	}

	redisOptions := &RedisConfigOpt{}
	for _, opt := range cfgOpts {
		opt(redisOptions)
	}

	slog.Info("creating redis universal options for %s:%d", slog.String("host", cfg.Host), slog.Int("port", cfg.Port))
	slog.Info("using auth type %s", slog.String("auth_type", string(cfg.AuthType)))

	switch cfg.AuthType {
	case config.RedisAuthAws:
		if redisOptions.AWSProviderFactory == nil {
			return nil, errors.New("missing aws provider factory")
		}
		slog.Info("using aws credentials provider for redis universal options")
		credCache, err := redisOptions.AWSProviderFactory.GetProvider(context.Background(), cfg.AwsConfigName)
		if err != nil {
			return nil, err
		}
		provider, err := NewRedisAwsCredentialsProvider(credCache.GetCredentialCache(), cfg)
		if err != nil {
			return nil, err
		}
		// Convert context-based provider to simple provider for UniversalOptions
		options.CredentialsProvider = func() (string, string) {
			username, password, err := provider(context.Background())
			if err != nil {
				slog.Error("Failed to get Redis credentials from AWS provider", slog.Any("error", err))
				return "", ""
			}
			return username, password
		}
	case config.RedisAuthPassword:
		slog.Info("using static credentials provider for redis universal options")
		options.CredentialsProvider = func() (string, string) {
			return cfg.Username, cfg.Password
		}
	case config.RedisAuthNone:
		slog.Info("using no authentication for redis universal options")
		// No credentials needed
	default:
		slog.Info("using no authentication for redis universal options (default)")
	}

	return options, nil
}

func NewRedisProvider(client *redis.Client) (*Redis, error) {
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		return nil, ErrRedisPingFailed
	}

	return &Redis{client}, nil
}

func (r *Redis) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

func (r *Redis) Set(ctx context.Context, key string, value interface{}) error {
	return r.client.Set(ctx, key, value, 0).Err()
}

// TODO: remove this method once go-redis supports FT.SEARCH.
// Temporary method while waiting for this feature in next go-redis release
func (r *Redis) FTSearch(ctx context.Context, indexName, query string) (*FTSearchResult, error) {
	// Execute the FT.SEARCH command
	result, err := r.client.Do(ctx, "FT.SEARCH", indexName, query).Result()
	if err != nil {
		return nil, err
	}

	return parseFTSearch(result.([]interface{}), false, false, false, false)
}

// TODO: remove this once go-redis supports FT.SEARCH
type FTSearchResult struct {
	Total int
	Docs  []Document
}

// TODO: remove this once go-redis supports FT.SEARCH
type Document struct {
	ID      string
	Score   *float64
	Payload *string
	SortKey *string
	Fields  map[string]string
}

// TODO: remove this once go-redis supports FT.SEARCH
func parseFTSearch(data []interface{}, noContent, withScores, withPayloads, withSortKeys bool) (*FTSearchResult, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("unexpected search result format")
	}

	total, ok := data[0].(int64)
	if !ok {
		return nil, fmt.Errorf("invalid total results format")
	}

	var results []Document
	for i := 1; i < len(data); {
		docID, ok := data[i].(string)
		if !ok {
			return nil, fmt.Errorf("invalid document ID format")
		}

		doc := Document{
			ID:     docID,
			Fields: make(map[string]string),
		}
		i++

		if noContent {
			results = append(results, doc)
			continue
		}

		if withScores && i < len(data) {
			if scoreStr, ok := data[i].(string); ok {
				score, err := strconv.ParseFloat(scoreStr, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid score format")
				}
				doc.Score = &score
				i++
			}
		}

		if withPayloads && i < len(data) {
			if payload, ok := data[i].(string); ok {
				doc.Payload = &payload
				i++
			}
		}

		if withSortKeys && i < len(data) {
			if sortKey, ok := data[i].(string); ok {
				doc.SortKey = &sortKey
				i++
			}
		}

		if i < len(data) {
			fields, ok := data[i].([]interface{})
			if !ok {
				return nil, fmt.Errorf("invalid document fields format")
			}

			for j := 0; j < len(fields); j += 2 {
				key, ok := fields[j].(string)
				if !ok {
					return nil, fmt.Errorf("invalid field key format")
				}
				value, ok := fields[j+1].(string)
				if !ok {
					return nil, fmt.Errorf("invalid field value format")
				}
				doc.Fields[key] = value
			}
			i++
		}

		results = append(results, doc)
	}
	return &FTSearchResult{
		Total: int(total),
		Docs:  results,
	}, nil
}
