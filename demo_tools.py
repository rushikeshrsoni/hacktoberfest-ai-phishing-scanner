"""Direct unit validation for Cybersecurity tools."""
from tools import scan_url_live, calculate_scam_score

# 1. Test a fake lottery scam link (IP + Keywords)
r1 = scan_url_live("http://192.168.1.1/free-lottery-winner")
assert r1["is_https"] is False
assert r1["has_suspicious_keywords"] is True
assert r1["is_ip_host"] is True

# 2. Test Scam Score for the above link
r2 = calculate_scam_score(r1["is_https"], r1["has_suspicious_keywords"], r1["is_ip_host"])
assert r2["scam_probability_score"] == "100%"
assert r2["risk_level"] == "CRITICAL RISK - DO NOT CLICK"

# 3. Test a safe link
r3 = scan_url_live("https://github.com/rushikesh")
assert r3["is_https"] is True
assert r3["has_suspicious_keywords"] is False
assert r3["is_ip_host"] is False

print("✅ Cybersecurity Tools passed successfully! Ready to hunt hackers.")