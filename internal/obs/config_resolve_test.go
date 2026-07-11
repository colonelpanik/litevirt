package obs

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

// A bogus operator-exported LITEVIRT_TRACES_SAMPLE_RATE must not silently
// discard a valid configured sample_rate. obs rejects the env value, then
// falls back to the config rate (already range-checked by normalizeTelemetry)
// rather than the library default (1.0) — otherwise a stale/malformed override
// flips sampling back to 100% while the operator believes it is capped.
func TestSetup_InvalidSampleRateEnv_FallsBackToConfigRate(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("LITEVIRT_TRACES_SAMPLE_RATE", "abc")
	setup(t, Config{ServiceName: "s", OTLPEndpoint: "http://127.0.0.1:4318", SampleRate: f64p(0.1)})

	if got := os.Getenv("PROVIDE_SAMPLING_TRACES_RATE"); got != "0.1" {
		t.Errorf("PROVIDE_SAMPLING_TRACES_RATE = %q; a bogus env override must fall back to the configured 0.1, not the library default (100%%)", got)
	}
}

// With no endpoint, an operator who sets the log format only via env
// (LITEVIRT_LOG_FORMAT=json, cfg.LogFormat empty) must still get the stdlib
// JSON handler — the resolved format lives in PROVIDE_LOG_FORMAT, not the cfg
// field, so building the handler from cfg alone silently drops it.
func TestSetup_NoEndpointEnvJSONFormat_InstallsStdlibJSONHandler(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("LITEVIRT_LOG_FORMAT", "json")
	setup(t, Config{ServiceName: "s"})

	if _, ok := slog.Default().Handler().(*slog.JSONHandler); !ok {
		t.Errorf("slog.Default().Handler() = %T; want *slog.JSONHandler for env-set LITEVIRT_LOG_FORMAT=json with no endpoint", slog.Default().Handler())
	}
}

// With no endpoint, an operator who sets the log level only via env
// (LITEVIRT_LOG_LEVEL=DEBUG, cfg.LogLevel empty) must get a stdlib handler that
// actually emits DEBUG. Building the handler from the empty cfg field drops to
// INFO and swallows exactly the diagnostics the operator turned on.
func TestSetup_NoEndpointEnvLogLevel_StdlibHandlerHonorsLevel(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("LITEVIRT_LOG_LEVEL", "DEBUG")
	setup(t, Config{ServiceName: "s"})

	if !slog.Default().Handler().Enabled(context.Background(), slog.LevelDebug) {
		t.Error("stdlib handler does not honor env-set LITEVIRT_LOG_LEVEL=DEBUG; debug records would be dropped")
	}
}
