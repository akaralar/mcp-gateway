//! Prometheus metrics recorder installation and text-format rendering.
//!
//! Only active when compiled with the `metrics` feature (opt-in, enabled by
//! default).  Call [`install`] once at server startup; the `/metrics` handler
//! then calls [`render`] on every scrape.

#[cfg(feature = "metrics")]
use std::sync::OnceLock;

#[cfg(feature = "metrics")]
use metrics_exporter_prometheus::PrometheusHandle;

#[cfg(feature = "metrics")]
static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the global Prometheus metrics recorder.
///
/// Idempotent: subsequent calls are silently ignored so that test helpers
/// and server startup can both call this without panicking.
#[cfg(feature = "metrics")]
pub fn install() {
    match metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder() {
        Ok(handle) => {
            let _ = HANDLE.set(handle);
            tracing::info!("Prometheus metrics recorder installed; scrape at /metrics");
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Failed to install Prometheus recorder; /metrics will return empty output"
            );
        }
    }
}

/// Render the current metrics snapshot in Prometheus text exposition format.
///
/// Returns an empty string when the recorder was not installed.
#[cfg(feature = "metrics")]
pub fn render() -> String {
    HANDLE
        .get()
        .map(PrometheusHandle::render)
        .unwrap_or_default()
}
