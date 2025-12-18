package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/caarlos0/env/v11"
	"github.com/creasty/defaults"
)

var Conf *Config

type CacheType string
type DbType string
type RedisAuthType string
type KubeTokenProvider string

const (
	InMem                    CacheType         = "memory"
	Redis                    CacheType         = "redis"
	Postgres                 DbType            = "postgres"
	Sqlite                   DbType            = "sqlite"
	RedisAuthPassword        RedisAuthType     = "password"
	RedisAuthAws             RedisAuthType     = "aws"
	RedisAuthNone            RedisAuthType     = "none"
	KubeTokenProviderAws     KubeTokenProvider = "aws"
	KubeTokenProviderCommand KubeTokenProvider = "command"
)

// Use custom error type internally to append multiple errors
// this allows us to return all errors at once
type ConfigError struct {
	Errs []error
}

func (e *ConfigError) Append(err ...error) {
	e.Errs = append(e.Errs, err...)
}

func (e ConfigError) Error() string {
	var errStr string
	for _, err := range e.Errs {
		errStr += err.Error() + "\n"
	}
	return errStr
}

func ConfigErrorFromError(err error) ConfigError {
	if err == nil {
		return ConfigError{}
	}
	if configError, ok := err.(ConfigError); ok {
		return configError
	}
	return ConfigError{Errs: []error{err}}
}

/*
  NOTE: using default: and env: will lead to env: not being used
  if you need a default value and want to also load from env, use envDefault: instead
*/

type Config struct {
	Name        string                        `yaml:"name" default:"Micron API"`
	Description string                        `yaml:"description" default:"A might Micron API!"`
	Version     string                        `yaml:"version" default:"v1"`
	Api         *ApiConfig                    `yaml:"api" default:"{}"`
	
	Database    *DatabaseConfig               `yaml:"database" default:"{}"`
	Cache       *CacheConfig                  `yaml:"cache" default:"{}"`
	Providers   *Providers                    `yaml:"providers" default:"{}"`
	DeployEnvs  map[string]*EnvironmentConfig `yaml:"deploy_envs" default:"{}"`
}

type ApiConfig struct {
	Env        string         `yaml:"env" env:"MICRON_API_ENV"`
	EnableCors bool           `yaml:"enable_cors"`
	Url        string         `yaml:"url" env:"MICRON_API_URL" default:"http://localhost:8081/api"`
	Auth       *ApiAuthConfig `yaml:"auth" default:"{}"`
	CertPath   string         `yaml:"cert_path" env:"MICRON_TLS_CERT_PATH"`
	KeyPath    string         `yaml:"key_path" env:"MICRON_TLS_KEY_PATH"`
}

type CasbinConfig struct {
	ValidEmailDomains []string `yaml:"valid_email_domains" default:"[]"`
}

type ApiAuthConfig struct {
	AllowedIssuers    []string `yaml:"allowed_issuers" default:"[]"`
	AllowedClients    []string `yaml:"allowed_clients" default:"[]"`
	AllowedActors     []string `yaml:"allowed_actors" default:"[]"`
	AllowedGithubOrgs []string `yaml:"allowed_github_orgs"`
	AllowedAudiences  []string `yaml:"allowed_audiences" default:"[]"`
}

type Providers struct {
	Aws               map[string]*AwsConfig `yaml:"aws" default:"{}"`
	SSO               *SSOConfig            `yaml:"sso" default:"{}"`
	Casbin      	  *CasbinConfig         `yaml:"casbin" default:"{}"`
	EnabledProviders  []string              `yaml:"enabled_providers" default:"[]"`
}


func (p *Providers) IsEnabled(name string) bool {
	for _, enabled := range p.EnabledProviders {
		if strings.EqualFold(enabled, name) {
			return true
		}
	}

	return false
}

type DatabaseConfig struct {
	Type     DbType `yaml:"type" env:"DATABASE_TYPE" default:"sqlite"`
	DSN      string `yaml:"dsn" env:"DATABASE_DSN" default:"file::memory:data.db"`
	Username string `yaml:"username" env:"DATABASE_USERNAME"`
	Password string `yaml:"password" env:"DATABASE_PASSWORD"`
}

type CacheConfig struct {
	Type        CacheType    `yaml:"type" env:"CACHE_TYPE" default:"memory"`
	RedisConfig *RedisConfig `yaml:"redis_config" env:"REDIS_CONFIG"`
}

type AwsConfig struct {
	Name    string `yaml:"name"`
	Region  string `yaml:"region"`
	RoleArn string `yaml:"role_arn"`
	Profile string `yaml:"profile"` // mainly useful for testing
}

type SSOConfig struct {
	SSOUrlPath     string `yaml:"sso_url_path" default:"/v1/saml"`
	SSORedirectUrl string `yaml:"sso_redirect_url" env:"SSO_REDIRECT_URL"`
	EntityId       string `yaml:"sso_entity_id" env:"SSO_ENTITY_ID"`
	BaseUrl        string `yaml:"sso_base_url" env:"SSO_BASE_URL"`
	X509PublicKey  string `yaml:"sso_public_x509_key" env:"SSO_PUBLIC_X509_KEY"`
	X509PrivateKey string `yaml:"sso_private_x509_key" env:"SSO_PRIVATE_X509_KEY"`
}

type RedisConfig struct {
	Name               string        `yaml:"name"`
	Host               string        `yaml:"host"`
	Port               int           `yaml:"port" default:"6379"`
	Username           string        `yaml:"username"`
	Password           string        `yaml:"password"`
	DB                 int           `yaml:"db" default:"0"`
	TLSEnabled         bool          `yaml:"tls_enabled" default:"false"`
	AuthType           RedisAuthType `yaml:"auth_type" default:"none"`
	AwsConfigName      string        `yaml:"aws_config_name"`
	ReplicationGroupID string        `yaml:"replication_group_id"`
	AwsRegion          string        `yaml:"aws_region"`
	SkipTLSVerify      bool          `yaml:"skip_tls_verify"`
}

type EnvironmentConfig struct {
	WellKnownUrls        map[string]string `yaml:"well_known_urls" default:"{}"`
	Aliases              []string          `yaml:"aliases" default:"[]"`
	Jwks                 []string          `yaml:"jwks" default:"[]"`
	RequiredEnvironments []string          `yaml:"required_environments" default:"[]"`
	Validations          map[string]bool   `yaml:"validations" default:"{}"`
	GithubOrg            string            `yaml:"github_org" default:""`
	GithubRepo           string            `yaml:"github_repo" default:""`
	ValidateOnly         bool              `yaml:"validate_only" default:"false"`
}

func (c Config) Validate() error {
	configErrors := ConfigError{}

	if err := c.Providers.Casbin.validateCasbinConfig(
		c.Providers.IsEnabled("auth"),
	); err != nil {
		configErrors.Append(ConfigErrorFromError(err).Errs...)
	}

	if err := c.validateDeploymentEnvs(); err != nil {
		configErrors.Append(ConfigErrorFromError(err).Errs...)
	}

	if err := c.Providers.SSO.validateSSOConfig(
		c.Providers.IsEnabled("sso"),
	); err != nil {
		configErrors.Append(ConfigErrorFromError(err).Errs...)
	}

	if configErrors.Errs != nil {
		return configErrors
	}
	return nil
}

func (c *CasbinConfig) validateCasbinConfig(enabled bool) error {

	if !enabled {
		return nil
	}

	configErrors := ConfigError{}

	if len(c.ValidEmailDomains) == 0 {
		configErrors.Append(
			errors.New("no valid email domains specified under Casbin config"),
		)
	}

	if len(configErrors.Errs) > 0 {
		return configErrors
	}
	return nil

}

func (c *Config) validateDeploymentEnvs() error {
	configErrors := ConfigError{}
	if len(c.DeployEnvs) == 0 {
		return nil
	}
	aliasNames := []string{}

	for name, env := range c.DeployEnvs {
		currentAliases := append(env.Aliases, name)
		if slices.ContainsFunc(currentAliases, func(alias string) bool { return slices.Contains(aliasNames, alias) }) {
			configErrors.Append(fmt.Errorf("duplicate alias name in env %s, aliases: %v", name, currentAliases))
		}
		aliasNames = append(aliasNames, currentAliases...)
	}
	if len(configErrors.Errs) > 0 {
		return configErrors
	}
	return nil
}

// NOTE: this is not a deep copy for each env. map keys can share the same pointer still
// This should be ran after config validation to ensure no duplicate aliases
func (c *Config) ExpandDeploymentEnvs(httpClient *http.Client) (map[string]*EnvironmentConfig, error) {
	expandedEnvs := map[string]*EnvironmentConfig{}
	for name, env := range c.DeployEnvs {
		// resolve the pointer so we can modify without affecting the original
		env := *env
		jwks := []string{}
		for _, jwk := range env.Jwks {
			if url, err := url.Parse(jwk); err == nil {
				content, err := getUrlContent(url, httpClient)
				if err != nil {
					return nil, err
				}
				jwks = append(jwks, content)
			} else {
				jwks = append(jwks, jwk)
			}
		}
		env.Jwks = jwks
		allAliases := append(env.Aliases, name)
		slices.Sort(allAliases)
		env.Aliases = slices.Compact(allAliases)
		expandedEnvs[name] = &env
		for _, alias := range env.Aliases {
			expandedEnvs[alias] = &env
		}
	}
	return expandedEnvs, nil
}

func getUrlContent(url *url.URL, httpClient *http.Client) (string, error) {
	switch url.Scheme {
	case "http", "https":
		r, err := httpClient.Get(url.String())
		if err != nil {
			return "", err
		}
		if r.StatusCode != http.StatusOK {
			return "", fmt.Errorf("failed to fetch jwk %s, status code: %d", url.String(), r.StatusCode)
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return "", err
		}
		return string(b), nil
	case "file":
		b, err := os.ReadFile(url.Path)
		if err != nil {
			return "", err
		}
		return string(b), nil
	default:
		return "", fmt.Errorf("unsupported url scheme: %s", url.Scheme)
	}
}

func (sso *SSOConfig) validateSSOConfig(enabled bool) error {
	configErrors := ConfigError{}

	if !enabled {
		return nil
	}

	if sso.SSORedirectUrl == "" {
		configErrors.Append(errors.New("sso_redirect_url for SSOConfig cannot be empty"))
	}

	if sso.BaseUrl == "" {
		configErrors.Append(errors.New("sso_base_url for SSOConfig cannot be empty"))
	}

	if sso.X509PublicKey == "" {
		configErrors.Append(errors.New("sso_public_x509_key for SSOConfig cannot be empty"))
	}

	if sso.X509PrivateKey == "" {
		configErrors.Append(errors.New("sso_private_x509_key for SSOConfig cannot be empty"))
	}

	if configErrors.Errs != nil {
		return configErrors
	}

	return nil
}

// Validate the nas config block.
// Call this from the umbrella Config.Validate() (similar to your DNAR validation).

func (c Config) GetAwsProviderConfigs() []*AwsConfig {
	var awsConfigs []*AwsConfig
	for name, aws := range c.Providers.Aws {
		aws.Name = name
		awsConfigs = append(awsConfigs, aws)
	}
	return awsConfigs
}

func LoadConfig(reader io.Reader) (*Config, error) {
	config := &Config{}
	if err := defaults.Set(config); err != nil {
		slog.Error("error setting defaults", slog.Any("error", err))
		return nil, fmt.Errorf("error setting defaults: %w", err)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		slog.Error("error reading config data: %w", slog.Any("error", err))
		return nil, fmt.Errorf("error reading config data: %w", err)
	}

	if err = yaml.Unmarshal(data, &config); err != nil {
		slog.Error("error unmarshalling config data", slog.Any("error", err))
		return nil, fmt.Errorf("error unmarshalling config data: %w", err)
	}
	envOpts := env.Options{
		FuncMap: map[reflect.Type]env.ParserFunc{
			/*
			  since RedisConfig is a struct, we need to define a custom parser function
			  yaml is a superset of json, we can use yaml to unmarshal a json string
			  this is easier than writing a custom parser using a custom format
			*/
			reflect.TypeOf(RedisConfig{}): func(v string) (interface{}, error) {
				var rc RedisConfig
				if err := yaml.Unmarshal([]byte(v), &rc); err != nil {
					return nil, err
				}
				return rc, nil
			},
		},
	}

	// pull any environment variables with stuct tags defined
	if err = env.ParseWithOptions(config, envOpts); err != nil {
		slog.Error("error parsing env", slog.Any("error", err))
		return nil, err
	}

	Conf = config

	return config, nil
}

func LoadConfigFromPath(configPath string) (
	*Config,
	error,
) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found at path %s", configPath)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	config, err := LoadConfig(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	return config, nil
}

// ParseInXDuration parses a string in the format "in <number> <unit>" and returns a time.Duration.
// Built in time parsing only supports up to hours.
func ParseInXDuration(input string) (time.Duration, error) {
	parts := strings.Fields(strings.TrimSpace(input))
	// Expecting exactly: ["in", "<number>", "<unit>"] (unit may be plural)
	if len(parts) != 3 || strings.ToLower(parts[0]) != "in" {
		return 0, errors.New("format must be: 'in <number> <unit>'")
	}

	// Parse the numeric part
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("invalid number: %w", err)
	}

	// Normalize unit (drop trailing "s" if present)
	unit := strings.TrimSuffix(strings.ToLower(parts[2]), "s")

	var d time.Duration
	switch unit {
	case "second", "sec":
		d = time.Duration(n) * time.Second
	case "minute", "min":
		d = time.Duration(n) * time.Minute
	case "hour", "hr":
		d = time.Duration(n) * time.Hour
	case "day":
		d = time.Duration(n) * 24 * time.Hour
	case "week":
		d = time.Duration(n) * 7 * 24 * time.Hour
	case "month":
		// “Month” is ambiguous (28–31 days), but often approximated as 30 days:
		d = time.Duration(n) * 30 * 24 * time.Hour
	case "year":
		// Approximate as 365 days (ignore leap days):
		d = time.Duration(n) * 365 * 24 * time.Hour
	default:
		return 0, fmt.Errorf("unsupported unit: %s", parts[2])
	}

	return d, nil
}
