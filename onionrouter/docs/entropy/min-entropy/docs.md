### **Standards for Min-Entropy & What "Good Entropy" Means**
**Goal**: Ensure randomness is **unpredictable enough** to resist brute-force/statistical attacks.  

---

### **1. Key Standards**
#### **A. NIST SP 800-90B (Hardware RNGs)**  
- **Minimum Requirement**:  
  - **Full entropy**: ≥1 bit of min-entropy per output bit.  
  - Example: A 256-bit key must have **at least 256 bits of min-entropy** (no bias).  
- **Testing**:  
  - Health tests (e.g., repetition counts, adaptive proportion tests).  

#### **B. Password Policies (NIST SP 800-63B)**  
- **Min-Entropy ≥ 10 bits**:  
  - At least **1,024 possible combinations** to resist online guessing.  
- **Example**:  
  - A 4-digit PIN (\(10^4\) combinations) has **~13.3 bits** of min-entropy *if uniformly random*.  
  - But if users pick "1234" (30% of cases), actual min-entropy drops to **~1.7 bits** (very weak).  

#### **C. Cryptography (AES, RSA Keys)**  
- **256-bit keys**: Must be derived from **256 bits of min-entropy**.  
  - Weakness: If entropy source has only 100 bits, the key is **theoretically breakable** in \(2^{100}\) tries.  

---

### **2. What "Good Entropy" Looks Like**
| Scenario             | Min-Entropy (H) | Attacker’s Effort   | Security Level         |
| -------------------- | --------------- | ------------------- | ---------------------- |
| Fair coin flip       | 1 bit           | 2 guesses (avg.)    | Useless for crypto     |
| 6-digit PIN (random) | ~19.9 bits      | 1 million guesses   | Weak (offline attacks) |
| Bitcoin private key  | 256 bits        | \(2^{256}\) guesses | Unbreakable            |
| Biased RNG (90% '0') | ~0.15 bits      | 1–2 guesses         | Catastrophic failure   |

---

### **3. Why Min-Entropy (Not Just Shannon Entropy)?**  
- **Shannon entropy**: Measures *average* unpredictability.  
  - Example: A distribution with 99% '0' and 1% '1' has low Shannon entropy (~0.08 bits), but min-entropy is **~0.015 bits** (even worse!).  
- **Min-entropy**: Measures *worst-case* predictability—critical for security.  

---

### **4. How to Achieve "Good Entropy"**  
1. **Hardware RNGs**: Use RDSEED/RDRAND (Intel) or jitter entropy (Linux’s `getrandom`).  
2. **Post-Processing**: Hash raw entropy with SHA-3 to remove bias.  
3. **Testing**:  
   - **NIST STS**: Statistical tests for randomness.  
   - **Dieharder**: Detect subtle biases.  

---

### **5. Red Flags (Bad Entropy)**  
- **Low min-entropy**: Attacker guesses secrets quickly.  
  - Example: Cloudflare’s 2018 bug ([LavaRand](https://blog.cloudflare.com/randomness-101-lavarand-in-production/)) where some servers had weak entropy.  
- **No mixing**: Using raw hardware RNG output without whitening.  

---

### **🚀 Rule of Thumb**  
- **For crypto**: Aim for **min-entropy ≥ security parameter** (e.g., 128-bit key → 128-bit min-entropy).  
- **For passwords**: Min-entropy ≥ 30 bits (requires **1 billion guesses**).  

**Example**:  
- **Good**: Linux’s `/dev/random` (mixes CPU jitter, interrupts, hardware RNG).  
- **Bad**: PHP’s `rand()` (predictable linear congruential generator).  

--- 

### **Final Answer**  
**Standard**: NIST SP 800-90B’s **full entropy (1 bit/bit)**.  
**Goal**: Make secrets **hardest to guess** in the worst case.  
**Good entropy**: Min-entropy so high that attackers need **infeasible time** (e.g., \(2^{128}\) guesses).