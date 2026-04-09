# fuzzrs — Intelligent Web Fuzzer with Semantic Clustering

## Introduction

Traditional web fuzzers suffer from a catastrophic noise problem. When enumerating modern web applications, penetration testers are frequently bombarded with thousands of "unique" responses triggered by trivial cosmetic mutations—randomized CSRF tokens, shifting server timestamps, ad-network IDs, or dynamic error traces. Engineers waste countless hours manually diffing and regex-filtering output just to find the actual vulnerabilities.

**`fuzzrs`** solves this natively. Built rigidly in asynchronous Rust, `fuzzrs` utilizes the **ARIE (Analytical Response Identification Engine)** to group HTTP responses structurally utilizing Locality Sensitive Hashing. It filters out chaotic cosmetic noise intrinsically, surfacing only the true, logically distinct endpoints.

---

## 🔥 Key Idea

Instead of printing 10,000 unique responses because a timestamp changed on the page, we show only the unique structural variations over the underlying network architecture. Signal over noise, guaranteed.

---

## ⚡ Demo

**The Problem (Traditional Fuzzer Spam):**
```text
[200] /api/profile/1 (Size: 1042)
[200] /api/profile/2 (Size: 1048)
[200] /api/profile/3 (Size: 1042)
[200] /api/profile/5 (Size: 1044)
... [9,995 more identical profile pages masking real vulnerabilities] ...
[403] /api/admin_panel (Size: 812)
```

**The Solution (`fuzzrs` Output):**
```text
[200] /api/profile/1        [Cluster ID: 0] (New Structural Endpoint)
[403] /api/admin_panel      [Cluster ID: 1] (New Structural Endpoint)
... [9,998 cosmetic noise variations silently filtered] ...
```

---

## ✨ Features

* **SimHash-based Clustering**: Utilizes LSH Pigeonhole mapping for $O(1)$ amortized response deduping.
* **Adaptive Filtering**: Intelligently shifts similarity bounds dynamically (HTML requires 95%, JSON requires 98%, Error Pages require 90% matching).
* **High-performance Async Engine**: Powered by a decoupled Tokio MPMC (multi-producer, multi-consumer) Semaphore architecture natively scaling to massive hardware bounds.
* **Zero-copy Processing**: Immutable `bytes::Bytes` and compiled Regex iterators eliminate massive memory fragmentation and heap bloat entirely.
* **Real-time Filtering**: Streams unique cluster hits to the terminal instantaneously without waiting for 50GB dictionary execution closures.

---

## 🚀 Installation

Install directly from source via `cargo`:

```bash
git clone https://github.com/Mirzoazamov/fuzzrs.git
cd fuzzrs
cargo build --release
```

Run the binary natively:
```bash
./target/release/fuzzrs --help
```

*(Pre-compiled platform binaries will be available in the upcoming v1.0 GitHub Releases).*

---

## 🧪 Usage

Basic execution fundamentally requires the `FUZZ` target keyword within your provided URL and a valid wordlist. The engine will rapidly substitute `FUZZ` payloads synchronously:

```bash
fuzzrs scan https://target.com/api/FUZZ -w wordlist.txt
```

---

## 📊 Example Output

```text
[*] Initializing High-Performance Semantic Fuzzer...
[*] Target bounds: https://target.com/api/FUZZ
[*] Wordlist: wordlist.txt
[*] Concurrency bounds: 50

[SCAN RESULTS]
TARGET PATH                         | STATUS   | CLUSTER ID   | METADATA       
--------------------------------------------------------------------------------
https://target.com/api/admin        | 403      | 0            | Sim: 99.5%
https://target.com/api/users        | 200      | 1            | Sim: 100.0%
--------------------------------------------------------------------------------

[SCAN SUMMARY]
Total Requests    : 10000
Unique Endpoints  : 2
Filtered Noise    : 9998
Deduplication Rate: 99.98%
```

---

## ⚙️ Flags

| Flag | Full Argument | Example | Description |
|:---:|:---|:---|:---|
| `-w` | `--wordlist` | `-w payloads.txt` | Path to the textual fuzzing dictionary (Required) |
| `-c` | `--concurrency`| `-c 150` | Maximum simultaneous open TCP connections (Default: 50) |
| `-t` | `--timeout` | `-t 10000` | Global socket timeout bound in milliseconds (Default: 5000) |
| | `--format` | `--format json` | Output topology (`json` or `table`) (Default: table) |
| | `--retries` | `--retries 5` | Jittered exponential retries permitted per payload (Default: 3) |
| | `--proxy` | `--proxy http://127.0.0.1:8080` | Route all upstream Engine traffic cleanly |

---

## 🧠 How It Works

Traditional tools rely strictly on static HTTP attributes (e.g., Content-Length tracking, manual word counting) which break instantly under dynamically hydrated JS apps or localized load-balancer tokens. `fuzzrs` takes a deeply semantic approach smoothly executing four phases:

1. **Request**: The Async dispatcher pulls payloads firing over connection-pooled TLS rails.
2. **Response**: The Engine catches raw TCP bytes and rips them entirely devoid of physical UUIDs, CSRFs, and Unix Timestamps using pure text bounds.
3. **Fingerprint**: The resulting pure structural logic is mathematically squashed into a 64-bit Locality Sensitive Hash array (SimHash).
4. **Clustering & Filtering**: The bit representation is queried over pre-cached sub-chunk `Buckets`. If it falls within adaptive mathematical bounds (90-98% identical feature alignment), the result is suppressed as redundant noise. If vastly structurally decoupled, it renders instantly as a unique structural Endpoint.

---

## 🆚 Comparison

**`ffuf`**
* **Strategy**: Pure chaotic brute-force throughput.
* **Output Filtering**: Heavily relies on explicit manual filtration (`-fw`, `-fc`, limiting Regex overrides) demanding you know the noise structures before running natively.
* **Result**: High effort, potential oversight.

**`fuzzrs`**
* **Strategy**: Automatic LSH Centroid clustering.
* **Output Filtering**: Totally automated mapping natively extracting unique physical anomalies organically isolating logic endpoints dynamically.
* **Result**: Absolute signal over noise.

---

## ⚠️ Disclaimer

`fuzzrs` is a high-performance network execution cluster built **strictly for authorized security testing and defensive network research.** Engaging external architectures without explicit legal permissions violates standard international cyber laws. Maintainers assume no liability for catastrophic infrastructure degradations caused by unauthorized scanning metrics.

---

## 🛠 Roadmap

- [ ] **TUI Interface**: Full Terminal UI metric visualization matrices.
- [ ] **Smarter WAF Evasion**: Interception hook logic splitting and randomizing User-Agents automatically preventing IP bans natively.
- [ ] **Distributed Fuzzing**: Splitting `.txt` architectures across networked nodes dynamically.
