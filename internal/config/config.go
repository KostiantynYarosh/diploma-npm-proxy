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
	Proxy     ProxyConfig     `koanf:"proxy" yaml:"proxy"`
	Registry  RegistryConfig  `koanf:"registry" yaml:"registry"`
	Cache     CacheConfig     `koanf:"cache" yaml:"cache"`
	Extractor ExtractorConfig `koanf:"extractor" yaml:"extractor"`
	Layer1    Layer1Config    `koanf:"layer1" yaml:"layer1"`
	Layer2    Layer2Config    `koanf:"layer2" yaml:"layer2"`
	Layer3    Layer3Config    `koanf:"layer3" yaml:"layer3"`
	Combo     ComboConfig     `koanf:"combo" yaml:"combo"`
	Policy    PolicyConfig    `koanf:"policy" yaml:"policy"`
	Recheck   RecheckConfig   `koanf:"recheck" yaml:"recheck"`
	SIEM      SIEMConfig      `koanf:"siem" yaml:"siem"`
}

type ProxyConfig struct {
	ListenAddr         string        `koanf:"listen_addr" yaml:"listen_addr"`
	UpstreamURL        string        `koanf:"upstream_url" yaml:"upstream_url"`
	MaxTarballBytes    int64         `koanf:"max_tarball_bytes" yaml:"max_tarball_bytes"`
	AnalysisTimeout    time.Duration `koanf:"-" yaml:"-"`
	AnalysisTimeoutSec int           `koanf:"analysis_timeout_sec" yaml:"analysis_timeout_sec"`
}

type RegistryConfig struct {
	ConnectTimeoutSec int `koanf:"connect_timeout_sec" yaml:"connect_timeout_sec"`
	TotalTimeoutSec   int `koanf:"total_timeout_sec" yaml:"total_timeout_sec"`
	MaxRetries        int `koanf:"max_retries" yaml:"max_retries"`
}

type CacheConfig struct {
	RedisAddr       string `koanf:"redis_addr" yaml:"redis_addr"`
	RedisPassword   string `koanf:"redis_password" yaml:"redis_password"`
	RedisDB         int    `koanf:"redis_db" yaml:"redis_db"`
	VerdictTTLHours int    `koanf:"verdict_ttl_hours" yaml:"verdict_ttl_hours"`
	OSVTTLHours     int    `koanf:"osv_ttl_hours" yaml:"osv_ttl_hours"`
}

type ExtractorConfig struct {
	MaxFiles      int   `koanf:"max_files" yaml:"max_files"`
	MaxFileBytes  int64 `koanf:"max_file_bytes" yaml:"max_file_bytes"`
	MaxTotalBytes int64 `koanf:"max_total_bytes" yaml:"max_total_bytes"`
}

type Layer1Config struct {
	OSVAPIUrl                     string  `koanf:"osv_api_url" yaml:"osv_api_url"`
	OSVTimeoutSec                 int     `koanf:"osv_timeout_sec" yaml:"osv_timeout_sec"`
	MetadataNetTimeoutSec         int     `koanf:"metadata_net_timeout_sec" yaml:"metadata_net_timeout_sec"`
	Top10kPath                    string  `koanf:"top10k_path" yaml:"top10k_path"`
	TyposquatCloseDistance        int     `koanf:"typosquat_close_distance" yaml:"typosquat_close_distance"`
	TyposquatCloseScore           float64 `koanf:"typosquat_close_score" yaml:"typosquat_close_score"`
	TyposquatWarnDistance         int     `koanf:"typosquat_warn_distance" yaml:"typosquat_warn_distance"`
	TyposquatWarnScore            float64 `koanf:"typosquat_warn_score" yaml:"typosquat_warn_score"`
	TyposquatASCIIHomoglyphScore  float64 `koanf:"typosquat_ascii_homoglyph_score" yaml:"typosquat_ascii_homoglyph_score"`
	MetadataNewPackageDays        int     `koanf:"metadata_new_package_days" yaml:"metadata_new_package_days"`
	MetadataNewPackageScore       float64 `koanf:"metadata_new_package_score" yaml:"metadata_new_package_score"`
	MetadataYoungMaintainerDays   int     `koanf:"metadata_young_maintainer_days" yaml:"metadata_young_maintainer_days"`
	MetadataYoungMaintainerScore  float64 `koanf:"metadata_young_maintainer_score" yaml:"metadata_young_maintainer_score"`
	MetadataLowDownloadsThreshold int64   `koanf:"metadata_low_downloads_threshold" yaml:"metadata_low_downloads_threshold"`
	MetadataLowDownloadsScore     float64 `koanf:"metadata_low_downloads_score" yaml:"metadata_low_downloads_score"`
	MetadataPopularThreshold      int64   `koanf:"metadata_popular_threshold" yaml:"metadata_popular_threshold"`
	MetadataPopularStaleDays      int     `koanf:"metadata_popular_stale_days" yaml:"metadata_popular_stale_days"`
	MetadataPopularStaleScore     float64 `koanf:"metadata_popular_stale_score" yaml:"metadata_popular_stale_score"`
	AnomalyMaxVersionsPerDay      int     `koanf:"anomaly_max_versions_per_day" yaml:"anomaly_max_versions_per_day"`
	AnomalyVersionSpikeScore      float64 `koanf:"anomaly_version_spike_score" yaml:"anomaly_version_spike_score"`
	AnomalyMaintainerChangeScore  float64 `koanf:"anomaly_maintainer_change_score" yaml:"anomaly_maintainer_change_score"`
	AnomalyUnusualHoursScore      float64 `koanf:"anomaly_unusual_hours_score" yaml:"anomaly_unusual_hours_score"`
	AnomalySizeDeviationScore     float64 `koanf:"anomaly_size_deviation_score" yaml:"anomaly_size_deviation_score"`
	LicensePatchChangeScore       float64 `koanf:"license_patch_change_score" yaml:"license_patch_change_score"`
	LicenseMissingPopScore        float64 `koanf:"license_missing_popular_score" yaml:"license_missing_popular_score"`
	LicensePopularDownloads       int     `koanf:"license_popular_downloads" yaml:"license_popular_downloads"`
}

type Layer2Config struct {
	InstallScriptPresentScore        float64 `koanf:"install_script_present_score" yaml:"install_script_present_score"`
	InstallScriptBase64Score         float64 `koanf:"install_script_base64_score" yaml:"install_script_base64_score"`
	InstallScriptChildProcessScore   float64 `koanf:"install_script_child_process_score" yaml:"install_script_child_process_score"`
	InstallScriptEvalScore           float64 `koanf:"install_script_eval_score" yaml:"install_script_eval_score"`
	InstallScriptNodeEvalScore       float64 `koanf:"install_script_node_eval_score" yaml:"install_script_node_eval_score"`
	InstallScriptDynamicRequireScore float64 `koanf:"install_script_dynamic_require_score" yaml:"install_script_dynamic_require_score"`
	InstallScriptExternalURLScore    float64 `koanf:"install_script_external_url_score" yaml:"install_script_external_url_score"`
}

type Layer3Config struct {
	EntropyThreshold              float64 `koanf:"entropy_threshold" yaml:"entropy_threshold"`
	EntropyRatioThreshold         float64 `koanf:"entropy_ratio_threshold" yaml:"entropy_ratio_threshold"`
	EntropyMinStringLen           int     `koanf:"entropy_min_string_len" yaml:"entropy_min_string_len"`
	EntropyHexMinLen              int     `koanf:"entropy_hex_min_len" yaml:"entropy_hex_min_len"`
	CapabilityNetScore            float64 `koanf:"capability_net_score" yaml:"capability_net_score"`
	CapabilityExecScore           float64 `koanf:"capability_exec_score" yaml:"capability_exec_score"`
	CapabilityFSSensScore         float64 `koanf:"capability_fs_sensitive_score" yaml:"capability_fs_sensitive_score"`
	CapabilityDynEvalScore        float64 `koanf:"capability_dynamic_eval_score" yaml:"capability_dynamic_eval_score"`
	CapabilityEnvReadScore        float64 `koanf:"capability_env_read_score" yaml:"capability_env_read_score"`
	VersionDiffScriptAddedScore   float64 `koanf:"version_diff_script_added_score" yaml:"version_diff_script_added_score"`
	VersionDiffScriptChangedScore float64 `koanf:"version_diff_script_changed_score" yaml:"version_diff_script_changed_score"`
	VersionDiffCapExecScore       float64 `koanf:"version_diff_cap_exec_score" yaml:"version_diff_cap_exec_score"`
	VersionDiffCapNetScore        float64 `koanf:"version_diff_cap_net_score" yaml:"version_diff_cap_net_score"`
	VersionDiffNewDepScore        float64 `koanf:"version_diff_new_dep_score" yaml:"version_diff_new_dep_score"`
	VersionDiffNewDepCap          float64 `koanf:"version_diff_new_dep_cap" yaml:"version_diff_new_dep_cap"`
	SinkAloneScore                float64 `koanf:"sink_alone_score" yaml:"sink_alone_score"`
	SinkObfuscationScore          float64 `koanf:"sink_obfuscation_score" yaml:"sink_obfuscation_score"`
}

type ComboConfig struct {
	TyposquatWithInstallScriptScore   float64 `koanf:"typosquat_with_install_script_score" yaml:"typosquat_with_install_script_score"`
	InstallScriptWithExecScore        float64 `koanf:"install_script_with_exec_score" yaml:"install_script_with_exec_score"`
	InstallScriptWithNetworkScore     float64 `koanf:"install_script_with_network_score" yaml:"install_script_with_network_score"`
	InstallScriptWithObfuscationScore float64 `koanf:"install_script_with_obfuscation_score" yaml:"install_script_with_obfuscation_score"`
}

// Recheck controls the background post-factum rechecker.
type RecheckConfig struct {
	Enabled       bool `koanf:"enabled" yaml:"enabled"`
	IntervalHours int  `koanf:"interval_hours" yaml:"interval_hours"`
	BatchSize     int  `koanf:"batch_size" yaml:"batch_size"`
	WarnOnly      bool `koanf:"warn_only" yaml:"warn_only"`
}

type PolicyConfig struct {
	AllowThreshold float64 `koanf:"allow_threshold" yaml:"allow_threshold"`
	BlockThreshold float64 `koanf:"block_threshold" yaml:"block_threshold"`
	MinCategories  int     `koanf:"min_categories" yaml:"min_categories"`
}

type SIEMConfig struct {
	Mode          string `koanf:"mode" yaml:"mode"`
	SyslogAddr    string `koanf:"syslog_addr" yaml:"syslog_addr"`
	SyslogNetwork string `koanf:"syslog_network" yaml:"syslog_network"`
	WebhookURL    string `koanf:"webhook_url" yaml:"webhook_url"`
	WebhookSecret string `koanf:"webhook_hmac_secret" yaml:"webhook_hmac_secret"`
	BufferSize    int    `koanf:"buffer_size" yaml:"buffer_size"`
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
