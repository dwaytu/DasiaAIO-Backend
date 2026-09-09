#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub severity: String,
    pub confidence: f64,
    pub source: String,
}

pub fn classify_incident_severity(description: &str) -> ClassificationResult {
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
        source: "keyword rules".to_string(),
    }
}
