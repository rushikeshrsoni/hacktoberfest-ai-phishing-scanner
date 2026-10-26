import urllib.parse
import re
import math

def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def scan_url_live(url: str) -> dict:
    try:
        if not isinstance(url, str): url = str(url)
        if not url.startswith(("http://", "https://")): url = "https://" + url
            
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        full_url_lower = url.lower()
        
        is_https = parsed.scheme == "https"
        is_ip_host = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))
        
        found_risks = []
        shorteners = ["go.link", "bit.ly", "tinyurl", "cutt.ly", "t.co", "rb.gy", "shorturl"]
        if any(short in domain for short in shorteners):
            found_risks.append("url-shortener-used")

        clean_domain = domain.replace("www.", "")
        if clean_domain.count('.') > 2 and not clean_domain.endswith((".co.in", ".com.au", ".co.uk")):
            found_risks.append("excessive-subdomains")
            
        if calculate_entropy(clean_domain) > 3.8:
            found_risks.append("high-randomness-entropy")

        if "xn--" in domain:
            found_risks.append("punycode-fake-letters")
            
        if len(url) > 150:
            found_risks.append("suspiciously-long-path")
            
        suspicious_words = [
            "free-prize", "lottery-winner", "secure-update", "verify-account", 
            "wallet-connect", "claim-gift", "account-recovery", "urgent-kyc",
            "bank-update", "refund-process", "unblock-account"
        ]
        for word in suspicious_words:
            if word in full_url_lower:
                found_risks.append(f"risk-word:{word}")
                
        famous_brands = ["paypal", "netflix", "apple", "microsoft", "google", "amazon", "sbi", "hdfc"]
        for brand in famous_brands:
            if brand in full_url_lower and f"{brand}.com" not in domain and f"{brand}.in" not in domain:
                found_risks.append(f"brand-spoofing:{brand}")
                
        sketchy_tlds = [".xyz", ".top", ".club", ".buzz", ".tk", ".ml", ".cf", ".gq", ".cc", ".biz"]
        if any(domain.endswith(tld) for tld in sketchy_tlds):
            found_risks.append("sketchy-tld")
            
        has_suspicious_keywords = len(found_risks) > 0
        
        return {
            "scanned_url": url,
            "is_https": is_https,
            "is_ip_host": is_ip_host,
            "found_suspicious_keywords": found_risks,
            "has_suspicious_keywords": has_suspicious_keywords
        }
    except Exception:
        return {"scanned_url": url, "is_https": False, "is_ip_host": False, "found_suspicious_keywords": ["fatal-scan-error"], "has_suspicious_keywords": True}

def calculate_scam_score(is_https: bool, has_suspicious_keywords: bool, is_ip_host: bool) -> dict:
    score = 0
    if is_ip_host: score += 75  
    if has_suspicious_keywords: score += 65  
    if not is_https: score += 40  
        
    score = min(score, 99) 
    
    if score >= 60: risk_level = "CRITICAL - HIGH RISK"
    elif score >= 40: risk_level = "SUSPICIOUS - Proceed with Caution"
    else:
        score = 0 
        risk_level = "SAFE - Looks Legitimate"
        
    return {"scam_probability_score": f"{score}%", "risk_level": risk_level}