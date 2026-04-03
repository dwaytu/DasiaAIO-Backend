use reqwest;

const DEFAULT_GROQ_API_BASE: &str = "https://api.groq.com/openai/v1";
const DEFAULT_GROQ_MODEL: &str = "llama-3.1-8b-instant";
const DEFAULT_OPENAI_API_BASE: &str = "https://api.openai.com/v1";
const DEFAULT_OPENAI_MODEL: &str = "gpt-4o-mini";

/// Result from the incident classifier — carries the severity, confidence,
/// and how many keyword signals were matched (for non-LLM fallback).
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub severity: String,
    /// 0.0 – 1.0
    pub confidence: f64,
    /// "llm" | "keyword"
    pub source: String,
}

const AI_CLASSIFY_PROMPT: &str =
    "You are a security incident classifier for a professional security operations center. \
     Given an incident report, classify its severity as one of: CRITICAL, HIGH, MEDIUM, or LOW.\n\
     \n\
     CRITICAL: armed threats, weapons, active violence, hostage situations, major breaches.\n\
     HIGH: intruders, suspicious armed persons, serious threats, break-ins in progress.\n\
     MEDIUM: trespassing, unauthorised access, suspicious activity without immediate threat.\n\
     LOW: lost items, minor disturbances, noise complaints.\n\
     \n\
     Respond with ONLY the severity word (CRITICAL, HIGH, MEDIUM, or LOW). No explanation.";

/// Primary entry point. Attempts LLM classification first, falls back to keyword matching.
pub async fn classify_incident_smart(description: &str) -> ClassificationResult {
    match call_llm_classifier(description).await {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!(error = %e, "LLM classifier unavailable — falling back to keyword heuristic");
            classify_incident_keywords(description)
        }
    }
}

/// Keyword-only classification (sync, used as fallback and in unit tests).
pub fn classify_incident(description: &str) -> String {
    classify_incident_keywords(description).severity
}

struct LlmConfig {
    api_key: String,
    api_base: String,
    model: String,
    provider: String,
}

fn resolve_llm_config() -> Result<LlmConfig, Box<dyn std::error::Error + Send + Sync>> {
    let provider = std::env::var("AI_PROVIDER")
        .unwrap_or_else(|_| "groq".to_string())
        .trim()
        .to_lowercase();

    let ai_key = std::env::var("AI_API_KEY").unwrap_or_default();
    let groq_key = std::env::var("GROQ_API_KEY").unwrap_or_default();
    let openai_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();

    let api_key = if !ai_key.trim().is_empty() {
        ai_key
    } else if provider == "groq" && !groq_key.trim().is_empty() {
        groq_key
    } else if provider == "openai" && !openai_key.trim().is_empty() {
        openai_key
    } else if !groq_key.trim().is_empty() {
        groq_key
    } else if !openai_key.trim().is_empty() {
        openai_key
    } else {
        return Err(
            "No AI API key configured. Set AI_API_KEY or GROQ_API_KEY (recommended) or OPENAI_API_KEY"
                .into(),
        );
    };

    let api_base = std::env::var("AI_API_BASE_URL").unwrap_or_else(|_| {
        if provider == "openai" {
            DEFAULT_OPENAI_API_BASE.to_string()
        } else {
            DEFAULT_GROQ_API_BASE.to_string()
        }
    });

    let model = std::env::var("AI_MODEL").unwrap_or_else(|_| {
        if provider == "openai" {
            DEFAULT_OPENAI_MODEL.to_string()
        } else {
            DEFAULT_GROQ_MODEL.to_string()
        }
    });

    Ok(LlmConfig {
        api_key,
        api_base,
        model,
        provider,
    })
}

fn llm_confidence_from_output(raw_output: &str, severity: &str) -> f64 {
    let normalized = raw_output.trim().to_uppercase();
    let exact = normalized == severity;
    let contains_only_expected = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        .iter()
        .any(|label| normalized == *label || normalized == format!("{}.", label));

    if exact || contains_only_expected {
        return 0.90;
    }

    if normalized.contains(severity) {
        return 0.82;
    }

    0.74
}

async fn call_llm_classifier(
    description: &str,
) -> Result<ClassificationResult, Box<dyn std::error::Error + Send + Sync>> {
    let config = resolve_llm_config()?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .build()?;

    let body = serde_json::json!({
        "model": config.model,
        "messages": [
            { "role": "system", "content": AI_CLASSIFY_PROMPT },
            { "role": "user", "content": description }
        ],
        "temperature": 0.1,
        "max_tokens": 10
    });

    let response = client
        .post(format!("{}/chat/completions", config.api_base))
        .bearer_auth(&config.api_key)
        .json(&body)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("LLM API returned {}: {}", status, text).into());
    }

    let json: serde_json::Value = response.json().await?;
    let raw = json["choices"][0]["message"]["content"]
        .as_str()
        .ok_or("No content field in LLM response")?
        .trim()
        .to_uppercase();

    // Validate — accept exact match or substring
    let severity = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        .iter()
        .find(|&&s| raw == s || raw.contains(s))
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            tracing::warn!(raw_response = %raw, "Unexpected LLM output, defaulting to keyword fallback");
            classify_incident_keywords(description).severity
        });

    let confidence = llm_confidence_from_output(&raw, &severity);

    Ok(ClassificationResult {
        severity,
        confidence,
        source: format!("llm:{}", config.provider),
    })
}

fn classify_incident_keywords(description: &str) -> ClassificationResult {
    let text = description.to_lowercase();

    let critical_keywords = ["weapon", "armed", "shooting", "bomb", "hostage", "stabbing"];
    let high_keywords = [
        "intruder",
        "suspicious",
        "break-in",
        "breaking in",
        "threat",
        "assault",
    ];
    let medium_keywords = [
        "trespassing",
        "trespass",
        "unauthorised",
        "unauthorized",
        "loitering",
        "tampering",
    ];
    let low_keywords = [
        "lost item",
        "noise",
        "complaint",
        "minor",
        "slip",
        "fall",
    ];

    let critical_hits = critical_keywords.iter().filter(|&&k| text.contains(k)).count();
    let high_hits = high_keywords.iter().filter(|&&k| text.contains(k)).count();
    let medium_hits = medium_keywords.iter().filter(|&&k| text.contains(k)).count();
    let low_hits = low_keywords.iter().filter(|&&k| text.contains(k)).count();

    let (severity, hits, tier_size) = if critical_hits > 0 {
        ("CRITICAL", critical_hits, critical_keywords.len())
    } else if high_hits > 0 {
        ("HIGH", high_hits, high_keywords.len())
    } else if medium_hits > 0 {
        ("MEDIUM", medium_hits, medium_keywords.len())
    } else if low_hits > 0 {
        ("LOW", low_hits, low_keywords.len())
    } else {
        ("LOW", 0usize, 1usize)
    };

    // Confidence = base + proportion of tier keywords matched (never below 0.55)
    let base = match severity {
        "CRITICAL" => 0.75_f64,
        "HIGH" => 0.70,
        "MEDIUM" => 0.65,
        _ => 0.55,
    };
    let bonus = if hits > 0 {
        (hits as f64 / tier_size as f64) * 0.20
    } else {
        0.0
    };

    ClassificationResult {
        severity: severity.to_string(),
        confidence: (base + bonus).min(0.95),
        source: "keyword".to_string(),
    }
}
