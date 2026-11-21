use std::{sync::OnceLock, time::Duration};

use chrono::{DateTime, Utc};
use reqwest::{Client, Url};
use serde::Deserialize;
use serde_json::Value;

const MAX_SAMPLES: usize = 80;
const MAX_GAP_SECONDS: i64 = 60;
const MAX_TRACE_REQUESTS: usize = 4;
const MIN_CONFIDENCE: f64 = 0.5;

struct GpsSample {
    lat: f64,
    lon: f64,
    timestamp: i64,
    accuracy: f64,
}

#[derive(Deserialize)]
struct MatchResponse {
    code: String,
    #[serde(default)]
    matchings: Vec<Matching>,
}

#[derive(Deserialize)]
struct Matching {
    confidence: f64,
    geometry: Geometry,
}

#[derive(Deserialize)]
struct Geometry {
    coordinates: Vec<[f64; 2]>,
}

fn client() -> Option<&'static Client> {
    static CLIENT: OnceLock<Option<Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            Client::builder()
                .timeout(Duration::from_secs(3))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .ok()
        })
        .as_ref()
}

/// Returns Leaflet-ordered coordinates. None means matching is unavailable.
pub async fn match_guard_history(points: &[Value]) -> Option<Vec<Vec<[f64; 2]>>> {
    let endpoint = Url::parse(&std::env::var("ROAD_MATCHER_URL").ok()?).ok()?;
    let host = endpoint.host_str()?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || !(host.ends_with(".railway.internal")
            || matches!(host, "localhost" | "127.0.0.1" | "[::1]"))
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
    {
        return None;
    }

    let mut requests = tokio::task::JoinSet::new();
    for trace in continuous_traces(points)
        .into_iter()
        .rev()
        .take(MAX_TRACE_REQUESTS)
    {
        requests.spawn(match_trace(endpoint.clone(), trace));
    }

    let mut segments = Vec::new();
    while let Some(result) = requests.join_next().await {
        segments.extend(result.ok()??);
    }
    Some(segments)
}

fn continuous_traces(points: &[Value]) -> Vec<Vec<GpsSample>> {
    let mut traces = Vec::new();
    let mut trace: Vec<GpsSample> = Vec::new();
    for point in &points[points.len().saturating_sub(MAX_SAMPLES)..] {
        let Some(sample) = gps_sample(point) else {
            continue;
        };
        if let Some(previous) = trace.last() {
            let gap = sample.timestamp - previous.timestamp;
            if gap <= 0 {
                continue;
            }
            if gap > MAX_GAP_SECONDS {
                if trace.len() >= 3 {
                    traces.push(std::mem::take(&mut trace));
                } else {
                    trace.clear();
                }
            }
        }
        trace.push(sample);
    }
    if trace.len() >= 3 {
        traces.push(trace);
    }
    traces
}

async fn match_trace(mut endpoint: Url, trace: Vec<GpsSample>) -> Option<Vec<Vec<[f64; 2]>>> {
    let coordinates: Vec<_> = trace
        .iter()
        .map(|sample| format!("{:.6},{:.6}", sample.lon, sample.lat))
        .collect();
    let timestamps: Vec<_> = trace
        .iter()
        .map(|sample| sample.timestamp.to_string())
        .collect();
    let radiuses: Vec<_> = trace
        .iter()
        .map(|sample| sample.accuracy.to_string())
        .collect();
    endpoint.set_path(&format!("/match/v1/driving/{}", coordinates.join(";")));
    endpoint.set_query(None);
    endpoint
        .query_pairs_mut()
        .append_pair("timestamps", &timestamps.join(";"))
        .append_pair("radiuses", &radiuses.join(";"))
        .append_pair("gaps", "split")
        .append_pair("geometries", "geojson")
        .append_pair("overview", "full");

    // OSRM returns NoMatch as a structured response with an HTTP 400 status.
    // Avoid logging errors that could contain the request URL and GPS samples.
    let response = client()?
        .get(endpoint)
        .send()
        .await
        .ok()?
        .json::<MatchResponse>()
        .await
        .ok()?;
    match response.code.as_str() {
        "NoMatch" | "NoSegment" => Some(Vec::new()),
        "Ok" => Some(
            response
                .matchings
                .into_iter()
                .filter(|matched| {
                    matched.confidence >= MIN_CONFIDENCE && matched.geometry.coordinates.len() >= 2
                })
                .map(|matched| {
                    matched
                        .geometry
                        .coordinates
                        .into_iter()
                        .map(|[lon, lat]| [lat, lon])
                        .collect()
                })
                .collect(),
        ),
        _ => None,
    }
}

fn gps_sample(point: &Value) -> Option<GpsSample> {
    let status = point["status"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if matches!(
        status.as_str(),
        "presentation_checkpoint" | "approximate" | "network"
    ) {
        return None;
    }
    let lat = point["latitude"].as_f64()?;
    let lon = point["longitude"].as_f64()?;
    let accuracy = point["accuracyMeters"].as_f64()?;
    if !(-90.0..=90.0).contains(&lat)
        || !(-180.0..=180.0).contains(&lon)
        || !(0.0..=40.0).contains(&accuracy)
    {
        return None;
    }
    let timestamp =
        DateTime::<Utc>::from(DateTime::parse_from_rfc3339(point["recordedAt"].as_str()?).ok()?)
            .timestamp();
    Some(GpsSample {
        lat,
        lon,
        timestamp,
        accuracy: accuracy.max(5.0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn splits_long_gaps_and_excludes_approximate_and_duplicate_readings() {
        let point = |seconds, status| {
            json!({
                "latitude": 7.448,
                "longitude": 125.808,
                "accuracyMeters": 12,
                "recordedAt": DateTime::<Utc>::from_timestamp(seconds, 0).unwrap().to_rfc3339(),
                "status": status,
            })
        };
        let points = [
            point(100, "gps"),
            point(120, "gps"),
            point(120, "gps"),
            point(140, "gps"),
            point(180, "approximate"),
            point(220, "gps"),
            point(240, "gps"),
            point(260, "gps"),
        ];
        let traces = continuous_traces(&points);
        assert_eq!(traces.len(), 2);
        assert_eq!(traces[0].len(), 3);
        assert_eq!(traces[1].len(), 3);
        assert_eq!(traces[1][0].timestamp, 220);
    }
}
