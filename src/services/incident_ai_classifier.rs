pub fn classify_incident(description: &str) -> String {
    let text = description.to_lowercase();

    let mut critical_score = 0;
    let mut high_score = 0;
    let mut medium_score = 0;
    let mut low_score = 0;

    // Deterministic keyword scoring rules.
    for keyword in ["weapon", "armed"] {
        if text.contains(keyword) {
            critical_score += 1;
        }
    }

    for keyword in ["suspicious", "intruder"] {
        if text.contains(keyword) {
            high_score += 1;
        }
    }

    if text.contains("trespassing") {
        medium_score += 1;
    }

    if text.contains("lost item") {
        low_score += 1;
    }

    if critical_score > 0 {
        "CRITICAL".to_string()
    } else if high_score > 0 {
        "HIGH".to_string()
    } else if medium_score > 0 {
        "MEDIUM".to_string()
    } else if low_score > 0 {
        "LOW".to_string()
    } else {
        // Default to LOW when no risk keywords are present.
        "LOW".to_string()
    }
}
