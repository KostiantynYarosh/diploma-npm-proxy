package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type Config struct {
	Proxy     ProxyConfig     `koanf:"proxy"`
	Registry  RegistryConfig  `koanf:"registry"`
	Cache     CacheConfig     `koanf:"cache"`
	Extractor ExtractorConfig `koanf:"extractor"`
	Layer1    Layer1Config    `koanf:"layer1"`
	Layer2    Layer2Config    `koanf:"layer2"`
	Layer3    Layer3Config    `koanf:"layer3"`
	Policy    PolicyConfig    `koanf:"policy"`
	Recheck   RecheckConfig   `koanf:"recheck"`
	SIEM      SIEMConfig      `koanf:"siem"`
}

type ProxyConfig struct {
	ListenAddr        string        `koanf:"listen_addr"`
	UpstreamURL       string        `koanf:"upstream_url"`
	MaxTarballBytes   int64         `koanf:"max_tarball_bytes"`
	AnalysisTimeout   time.Duration `koanf:"-"`
	AnalysisTimeoutSec int          `koanf:"analysis_timeout_sec"`
}

type RegistryConfig struct {
	ConnectTimeoutSec int `koanf:"connect_timeout_sec"`
	TotalTimeoutSec   int `koanf:"total_timeout_sec"`
	MaxRetries        int `koanf:"max_retries"`
}

type CacheConfig struct {
	RedisAddr       string `koanf:"redis_addr"`
	RedisPassword   string `koanf:"redis_password"`
	RedisDB         int    `koanf:"redis_db"`
	VerdictTTLHours int    `koanf:"verdict_ttl_hours"`
	OSVTTLHours     int    `koanf:"osv_ttl_hours"`
}

type ExtractorConfig struct {
	MaxFiles      int   `koanf:"max_files"`
	MaxFileBytes  int64 `koanf:"max_file_bytes"`
	MaxTotalBytes int64 `koanf:"max_total_bytes"`
}

type Layer1Config struct {
	OSVAPIUrl                string  `koanf:"osv_api_url"`
	OSVTimeoutSec            int     `koanf:"osv_timeout_sec"`
	MetadataNetTimeoutSec    int     `koanf:"metadata_net_timeout_sec"`
	Top10kPath               string  `koanf:"top10k_path"`
	TyposquatCloseDistance        int     `koanf:"typosquat_close_distance"`
	TyposquatCloseScore           float64 `koanf:"typosquat_close_score"`
	TyposquatWarnDistance         int     `koanf:"typosquat_warn_distance"`
	TyposquatWarnScore            float64 `koanf:"typosquat_warn_score"`
	TyposquatASCIIHomoglyphScore  float64 `koanf:"typosquat_ascii_homoglyph_score"`
	MetadataNewPackageDays       int     `koanf:"metadata_new_package_days"`
	MetadataNewPackageScore      float64 `koanf:"metadata_new_package_score"`
	MetadataYoungMaintainerDays  int     `koanf:"metadata_young_maintainer_days"`
	MetadataYoungMaintainerScore float64 `koanf:"metadata_young_maintainer_score"`
	MetadataLowDownloadsThreshold int64  `koanf:"metadata_low_downloads_threshold"`
	MetadataLowDownloadsScore     float64 `koanf:"metadata_low_downloads_score"`
	MetadataPopularThreshold      int64  `koanf:"metadata_popular_threshold"`
	MetadataPopularStaleDays      int    `koanf:"metadata_popular_stale_days"`
	MetadataPopularStaleScore     float64 `koanf:"metadata_popular_stale_score"`
	AnomalyMaxVersionsPerDay int     `koanf:"anomaly_max_versions_per_day"`
	AnomalyVersionSpikeScore float64 `koanf:"anomaly_version_spike_score"`
	AnomalyMaintainerChangeScore float64 `koanf:"anomaly_maintainer_change_score"`
	AnomalyUnusualHoursScore     float64 `koanf:"anomaly_unusual_hours_score"`
	AnomalySizeDeviationScore    float64 `koanf:"anomaly_size_deviation_score"`
	LicensePatchChangeScore  float64 `koanf:"license_patch_change_score"`
	LicenseMissingPopScore   float64 `koanf:"license_missing_popular_score"`
	LicensePopularDownloads  int     `koanf:"license_popular_downloads"`
}

type Layer2Config struct {
	InstallScriptPresentScore        float64 `koanf:"install_script_present_score"`
	InstallScriptBase64Score         float64 `koanf:"install_script_base64_score"`
	InstallScriptChildProcessScore   float64 `koanf:"install_script_child_process_score"`
	InstallScriptEvalScore           float64 `koanf:"install_script_eval_score"`
	InstallScriptNodeEvalScore       float64 `koanf:"install_script_node_eval_score"`
	InstallScriptDynamicRequireScore float64 `koanf:"install_script_dynamic_require_score"`
	InstallScriptExternalURLScore    float64 `koanf:"install_script_external_url_score"`
}

type Layer3Config struct {
	EntropyThreshold              float64 `koanf:"entropy_threshold"`
	EntropyRatioThreshold         float64 `koanf:"entropy_ratio_threshold"`
	EntropyMinStringLen           int     `koanf:"entropy_min_string_len"`
	EntropyHexMinLen              int     `koanf:"entropy_hex_min_len"`
	CapabilityNetScore            float64 `koanf:"capability_net_score"`
	CapabilityExecScore           float64 `koanf:"capability_exec_score"`
	CapabilityFSSensScore         float64 `koanf:"capability_fs_sensitive_score"`
	CapabilityDynEvalScore        float64 `koanf:"capability_dynamic_eval_score"`
	CapabilityEnvReadScore        float64 `koanf:"capability_env_read_score"`
	VersionDiffScriptAddedScore   float64 `koanf:"version_diff_script_added_score"`
	VersionDiffScriptChangedScore float64 `koanf:"version_diff_script_changed_score"`
	VersionDiffCapExecScore       float64 `koanf:"version_diff_cap_exec_score"`
	VersionDiffCapNetScore        float64 `koanf:"version_diff_cap_net_score"`
	VersionDiffNewDepScore        float64 `koanf:"version_diff_new_dep_score"`
	VersionDiffNewDepCap          float64 `koanf:"version_diff_new_dep_cap"`
	SinkAloneScore                float64 `koanf:"sink_alone_score"`
}

// Recheck controls the background post-factum rechecker.
type RecheckConfig struct {
	Enabled       bool `koanf:"enabled"`
	IntervalHours int  `koanf:"interval_hours"`
	BatchSize     int  `koanf:"batch_size"`
	WarnOnly      bool `koanf:"warn_only"`
}

type PolicyConfig struct {
	AllowThreshold float64 `koanf:"allow_threshold"`
	BlockThreshold float64 `koanf:"block_threshold"`
}

type SIEMConfig struct {
	Mode          string `koanf:"mode"`
	SyslogAddr    string `koanf:"syslog_addr"`
	SyslogNetwork string `koanf:"syslog_network"`
	WebhookURL    string `koanf:"webhook_url"`
	WebhookSecret string `koanf:"webhook_hmac_secret"`
	BufferSize    int    `koanf:"buffer_size"`
}

func Load(path string) (*Config, error) {
	k := koanf.New(".")

	if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("load config file: %w", err)
	}

	// Override with env vars: PROXY_CACHE_REDIS_ADDR → cache.redis_addr
	_ = k.Load(env.Provider("PROXY_", ".", func(s string) string {
		return strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(s, "PROXY_")), "_", ".")
	}), nil)

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	cfg.Proxy.AnalysisTimeout = time.Duration(cfg.Proxy.AnalysisTimeoutSec) * time.Second

	return &cfg, nil
}
