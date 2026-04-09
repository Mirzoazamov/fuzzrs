use bytes::Bytes;
use regex::bytes::Regex;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub hash: u64,
}

/// Zero-allocation compiled regex matching dynamic boundaries purely on native u8 byte structures.
fn get_dynamic_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?x)
            \b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b | # UUIDs
            \b\d+\b | # Numeric IDs and Unix Timestamps
            \b[a-zA-Z0-9_\-\+/\=]{32,}\b | # High entropy tokens (CSRF, Session tracking hashes)
            \b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b # ISO8601 Formatting
        ",
        )
        .unwrap()
    })
}

/// Generates a unified 64-bit SimHash.
/// Strictly utilizes O(1) Iterators avoiding ANY String cloning or heap allocations locally natively.
pub fn compute_fingerprint(body: &Bytes) -> Fingerprint {
    let mut descriptor_weights = [0i32; 64];
    let re = get_dynamic_regex();

    // 1. SPLIT natively by Regex Match Boundaries. The iterator simply jumps pointers across valid &[u8] chunks avoiding ANY `.replace()` allocations.
    for chunk in re.split(body) {
        // 2. Tokenize by ascii spacing bounds
        for word in chunk.split(|b| b.is_ascii_whitespace()) {
            if word.is_empty() {
                continue;
            }

            let mut hasher = DefaultHasher::new();
            hasher.write(word);
            let token_hash = hasher.finish();

            // 3. Incrementally balance the 64-dimensional text projection
            for i in 0..64 {
                if (token_hash >> i) & 1 == 1 {
                    descriptor_weights[i] += 1;
                } else {
                    descriptor_weights[i] -= 1;
                }
            }
        }
    }

    let mut hash: u64 = 0;
    for (i, weight) in descriptor_weights.iter().enumerate() {
        if *weight > 0 {
            hash |= 1 << i;
        }
    }

    Fingerprint { hash }
}

/// Yields exact similarity natively mapped out of 100%. (Expected 95%+)
pub fn similarity(a: &Fingerprint, b: &Fingerprint) -> f32 {
    let hamming_distance = (a.hash ^ b.hash).count_ones() as f32;
    let similarity = 1.0 - (hamming_distance / 64.0);
    similarity * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_pages() {
        let body1 = Bytes::from("<html><body><h1>Welcome to our secure fuzzer</h1></body></html>");
        let body2 = Bytes::from("<html><body><h1>Welcome to our secure fuzzer</h1></body></html>");

        let hash1 = compute_fingerprint(&body1);
        let hash2 = compute_fingerprint(&body2);

        assert_eq!(hash1.hash, hash2.hash);
        assert_eq!(similarity(&hash1, &hash2), 100.0);
    }

    #[test]
    fn test_slightly_different_pages() {
        let body1 = Bytes::from("<html><body><p>This is a standard page with generic output bounds.</p></body></html>");
        let body2 = Bytes::from("<html><body><p>This is a standard page with generic output bounds.</p><div>footer changed visually</div></body></html>");

        let hash1 = compute_fingerprint(&body1);
        let hash2 = compute_fingerprint(&body2);

        let sim = similarity(&hash1, &hash2);
        assert!(sim >= 80.0 && sim < 100.0, "Similarity should be highly correlated, was {}", sim);
    }

    #[test]
    fn test_completely_different_pages() {
        let auth_page = Bytes::from("<html><form action='/login'><input name='username'></form></html>");
        let error_page = Bytes::from("nginx 502 bad gateway generic server offline backend missing");

        let hash1 = compute_fingerprint(&auth_page);
        let hash2 = compute_fingerprint(&error_page);

        let sim = similarity(&hash1, &hash2);
        assert!(sim < 60.0, "Similarity should decouple totally, was {}", sim);
    }

    #[test]
    fn test_dynamic_content_removed_correctly() {
        let base_response = "<html><body>Welcome Admin!</body></html>";
        
        let response_a = format!("{}<timestamp>1699999999</timestamp><csrf>a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0uz</csrf>", base_response);
        let response_b = format!("{}<timestamp>1700000000</timestamp><csrf>x9y8z7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0f</csrf>", base_response);
        let response_c = format!("{}<uuid>123e4567-e89b-12d3-a456-426614174000</uuid><id>948573</id>", base_response);

        let hash_base = compute_fingerprint(&Bytes::from(base_response.clone()));
        let hash_a = compute_fingerprint(&Bytes::from(response_a));
        let hash_b = compute_fingerprint(&Bytes::from(response_b));
        let hash_c = compute_fingerprint(&Bytes::from(response_c));

        // The exact match verifies our dynamic stripper totally bypassed regex tokens natively bypassing allocations identically.
        assert_eq!(hash_a.hash, hash_b.hash);
        assert_eq!(hash_b.hash, hash_c.hash);
        
        // Minor boundary drift from the actual surrounding static tags (`<timestamp></timestamp>`) affects small features, 
        // but similarity to physical text MUST be cleanly matched.
        assert!(similarity(&hash_a, &hash_base) >= 95.0);
        assert!(similarity(&hash_c, &hash_base) >= 95.0);
    }
}
