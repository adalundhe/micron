package stores

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/adalundhe/micron/config"
	"github.com/adalundhe/micron/provider"
	"github.com/redis/go-redis/v9"
)

var (
	ErrCacheKeyNotFound = errors.New("key not found")
	//ErrRedisPingFailed  = errors.New("redis ping failed")
	ErrUnknownCacheType = errors.New("unknown cache type")
)

type Cache interface {
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Get(ctx context.Context, key string) (interface{}, error)
	GetRedisClient() *redis.Client
}

type InMemCache struct {
	cache map[string]item
	mu    sync.RWMutex // Protects the cache map
}

type item struct {
	value      interface{}
	expiration int64 // Time when the item expires, stored as Unix timestamp
}

type RedisCache struct {
	client *redis.Client
}

// Set stores a value in the in-memory cache with a given TTL.
func (i *InMemCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	expiration := time.Now().Add(ttl).Unix()
	i.cache[key] = item{
		value:      value,
		expiration: expiration,
	}
	return nil
}

// Get retrieves a value from the in-memory cache.
func (i *InMemCache) Get(ctx context.Context, key string) (interface{}, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	it, found := i.cache[key]
	if !found || time.Now().Unix() > it.expiration {
		return nil, ErrCacheKeyNotFound
	}
	return it.value, nil
}

func (i *InMemCache) GetRedisClient() *redis.Client {
	return nil
}

func (r *RedisCache) GetRedisClient() *redis.Client {
	return r.client
}

// Set stores a value in the Redis cache with a given TTL.
func (r *RedisCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl).Err()
}

// Get retrieves a value from the Redis cache.
func (r *RedisCache) Get(ctx context.Context, key string) (interface{}, error) {
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrCacheKeyNotFound
		}
		return nil, err
	}
	return val, nil
}

func NewCache(ctx context.Context, ccfg config.CacheConfig, redisOpts ...provider.RedisConfigOpts) (Cache, error) {
	switch ccfg.Type {
	case config.InMem:
		slog.Warn("WARNING: in-memory cache is not suitable for use outside of testing")
		return &InMemCache{
			cache: make(map[string]item),
		}, nil
	case config.Redis:
		client, err := provider.NewRedisClient(ccfg.RedisConfig, redisOpts...)
		if err != nil {
			return nil, err
		}
		return &RedisCache{
			client: client,
		}, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrUnknownCacheType, ccfg.Type)
}

// MustNewCache is a helper function that wraps NewCache and panics on error.
// It is intended for use in tests and initialization code.
func MustNewCache(ctx context.Context, ccfg config.CacheConfig) Cache {
	c, err := NewCache(ctx, ccfg)
	if err != nil {
		panic(err)
	}
	return c
}
