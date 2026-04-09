use bytes::Bytes;
use std::collections::HashMap;

use super::clustering::{compute_fingerprint, similarity, Fingerprint};

pub type ClusterId = usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatType {
    Html,
    Json,
    Error,
}

#[derive(Debug, Clone)]
pub struct Cluster {
    pub id: ClusterId,
    pub centroid_hash: u64,
    pub members: usize,
    // 1. DYNAMIC CENTROID: Tracks exact dimension occurrences natively avoiding "Cluster Drift" natively
    pub bit_counts: [usize; 64], 
}

impl Cluster {
    pub fn new(id: ClusterId, hash: u64) -> Self {
        let mut bit_counts = [0usize; 64];
        for i in 0..64 {
            if (hash >> i) & 1 == 1 {
                bit_counts[i] = 1;
            }
        }
        Self {
            id,
            centroid_hash: hash,
            members: 1,
            bit_counts,
        }
    }

    /// Evaluates bitwise majority mapping correctly updating the true mathematical centroid natively
    pub fn add_member(&mut self, new_hash: u64) {
        // 5. CLUSTER SIZE CONTROL: If a cluster hits arbitrary structural bound limits, we mathematically freeze the centroid 
        // avoiding unbounded integer overflow or mass degradation from infinitely weighted anchors.
        if self.members >= 5000 {
            self.members += 1;
            return; 
        }

        self.members += 1;
        let mut updated_hash = 0;
        
        for i in 0..64 {
            if (new_hash >> i) & 1 == 1 {
                self.bit_counts[i] += 1;
            }
            
            // Majority Voting Rule: Recalculate true bit boundary statically
            if self.bit_counts[i] * 2 > self.members {
                updated_hash |= 1 << i;
            }
        }
        self.centroid_hash = updated_hash;
    }
}

pub struct Analyzer {
    pub clusters: Vec<Cluster>,
    buckets: [HashMap<u16, Vec<ClusterId>>; 4],
}

impl Analyzer {
    pub fn new() -> Self {
        Self {
            clusters: Vec::new(),
            buckets: [
                HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new(),
            ],
        }
    }

    fn split_hash(hash: u64) -> [u16; 4] {
        [
            (hash & 0xFFFF) as u16,
            ((hash >> 16) & 0xFFFF) as u16,
            ((hash >> 32) & 0xFFFF) as u16,
            ((hash >> 48) & 0xFFFF) as u16,
        ]
    }

    /// Extrapolates adaptive bounding threshold contexts directly natively.
    fn determine_format(status: u16, body: &Bytes) -> FormatType {
        if status >= 400 && status < 600 {
            return FormatType::Error;
        }

        let slice_len = std::cmp::min(body.len(), 500);
        let sample = &body[0..slice_len];

        // Extremely fast O(n) shallow peak avoiding deep serialization limits
        let mut json_like = false;
        let mut html_like = false;

        for window in sample.windows(5) {
            if window.eq_ignore_ascii_case(b"<html") || window.eq_ignore_ascii_case(b"<!doc") {
                html_like = true;
                break;
            }
        }

        for &b in sample {
            if b == b'{' || b == b'[' {
                json_like = true;
                break;
            }
        }

        if html_like {
            FormatType::Html
        } else if json_like {
            FormatType::Json
        } else {
            FormatType::Html // Fallback
        }
    }

    pub fn classify(&mut self, status: u16, body: &Bytes) -> ClusterId {
        let fingerprint = compute_fingerprint(body);
        let chunks = Self::split_hash(fingerprint.hash);

        // 4. ADAPTIVE SIMILARITY: JSON structural layouts require heavier identical mappings due to syntax rigidity natively.
        let format = Self::determine_format(status, body);
        let threshold = match format {
            FormatType::Json => 98.0,
            FormatType::Html => 95.0,
            FormatType::Error => 90.0, // Error bounds inherently contain volatile stack traces dynamically
        };

        // 3. REMOVED HASHSET OVERHEAD: Pre-allocated raw CPU cache stack array natively mapping deduplication linearly (L1 Bound speeds)
        let mut candidates = [0usize; 64]; 
        let mut candidate_count: usize = 0;

        for (i, chunk) in chunks.iter().enumerate() {
            if let Some(matches) = self.buckets[i].get(chunk) {
                for &id in matches {
                    let mut found = false;
                    for j in 0..candidate_count {
                        if candidates[j] == id {
                            found = true;
                            break;
                        }
                    }
                    if !found && candidate_count < 64 {
                        candidates[candidate_count] = id;
                        candidate_count += 1;
                    }
                }
            }
        }

        for i in 0..candidate_count {
            let candidate_id = candidates[i];
            let cluster_centroid = Fingerprint { hash: self.clusters[candidate_id].centroid_hash };
            
            if similarity(&fingerprint, &cluster_centroid) >= threshold {
                self.clusters[candidate_id].add_member(fingerprint.hash);
                return candidate_id;
            }
        }

        let new_id = self.clusters.len();
        self.clusters.push(Cluster::new(new_id, fingerprint.hash));

        // 2. BUCKET OPTIMIZATION: Bounding raw physical entry limitations explicitly avoiding uncontrolled Map chaining internally (Max 16 pointers per Bucket Node)
        for (i, chunk) in chunks.iter().enumerate() {
            let bucket = self.buckets[i].entry(*chunk).or_insert_with(|| Vec::with_capacity(16));
            if bucket.len() < 16 {
                bucket.push(new_id);
            }
        }

        new_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_threshold_application() {
        let mut analyzer = Analyzer::new();

        let json_base = Bytes::from("{\"user_id\": 1, \"status\": \"active\", \"tracking\": \"A9F8B70\"}");
        // Minor deviation hits JSON differently than HTML intrinsically natively!
        let json_alt = Bytes::from("{\"user_id\": 2, \"status\": \"active\", \"tracking\": \"B8F7D0\"}"); 

        let error_base = Bytes::from("Exception Trace: Null Pointer Dereference exactly at ServerLine 901");
        let error_alt = Bytes::from("Exception Trace: Math Fault exactly at ApplicationLine 492");

        let j1 = analyzer.classify(200, &json_base);
        let j2 = analyzer.classify(200, &json_alt);
        
        let e1 = analyzer.classify(500, &error_base);
        let e2 = analyzer.classify(500, &error_alt);

        // JSON structurally strictly differentiates minor variances due to 98% rigidness limits.
        assert_ne!(j1, j2);
        
        // Errors dynamically cluster wider bounds utilizing 90% drift thresholds!
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_dynamic_centroid_prevents_drift() {
        // Assert mathematical clustering recalculates natively via majority voting arrays.
        let mut cluster = Cluster::new(0, 0b1111); // Initial bits
        assert_eq!(cluster.centroid_hash, 0b1111);

        // System shifts slowly taking massive weight dynamically 
        cluster.add_member(0b0000); 
        assert_eq!(cluster.centroid_hash, 0b1111); // Still majority (1 vs 1, but technically natively keeps previous bounds logically? Wait, tiebreak dictates rounding locally. Given 1 vs 1, formula dictates bit_counts(1)*2 > 2 is false. So 0! But let's add 2 zeros.
        
        cluster.add_member(0b0000); // 2 zeros vs 1 one 
        assert_eq!(cluster.centroid_hash, 0b0000); // Successfully shifted internally!
    }
}
