use std::collections::HashMap;

const STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "had", "has", "have", "he",
    "her", "his", "in", "is", "it", "its", "of", "on", "or", "she", "that", "the", "their",
    "there", "they", "to", "was", "were", "with", "near", "into", "this", "while", "but", "after",
    "before",
];

fn normalize_sentence(text: &str) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut chars = trimmed.chars();
    let first = chars
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_default();
    let rest: String = chars.collect();
    let mut sentence = format!("{}{}", first, rest);
    if !sentence.ends_with('.') && !sentence.ends_with('!') && !sentence.ends_with('?') {
        sentence.push('.');
    }
    sentence
}

pub fn extract_key_phrases(description: &str) -> Vec<String> {
    let mut freq: HashMap<String, usize> = HashMap::new();

    for token in description
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
    {
        let word = token.to_lowercase();
        if word.len() < 4 || STOPWORDS.contains(&word.as_str()) {
            continue;
        }
        *freq.entry(word).or_insert(0) += 1;
    }

    let mut words = freq.into_iter().collect::<Vec<_>>();
    words.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    words.into_iter().take(4).map(|(word, _)| word).collect()
}

pub fn summarize_incident(description: &str) -> String {
    let cleaned = description.trim();
    if cleaned.is_empty() {
        return "No incident details were provided for summarization.".to_string();
    }

    let primary_sentence_raw = cleaned
        .split_terminator(['.', '!', '?'])
        .next()
        .unwrap_or(cleaned)
        .trim();
    let primary_sentence = normalize_sentence(primary_sentence_raw);

    let key_phrases = extract_key_phrases(cleaned);
    if key_phrases.is_empty() {
        return primary_sentence;
    }

    let secondary = if key_phrases.len() == 1 {
        format!("Key factor identified: {}.", key_phrases[0])
    } else {
        format!("Key factors identified: {}.", key_phrases.join(", "))
    };

    format!("{} {}", primary_sentence, secondary)
}
