import logging
import ollama
from flask import Flask, request, jsonify
from flask_cors import CORS
from tools import scan_url_live, calculate_scam_score

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

MODEL_NAME = "gemma"

def run_agent_bypass(url: str) -> dict:
    try:
        scan_data = scan_url_live(url)
        score_data = calculate_scam_score(
            scan_data["is_https"], 
            scan_data["has_suspicious_keywords"], 
            scan_data["is_ip_host"]
        )
        
        prompt = f"""You are an elite Cybersecurity Detective AI. 
        I have analyzed a URL. Here are the results:
        URL: {url}
        Scan Results: {scan_data}
        Risk Score: {score_data}
        
        Write a short, sharp, warning-style detective report explaining the risks (or safety) of this link. 
        Keep it concise and in a hacker-terminal style. Do not make up any extra data."""

        try:
            client = ollama.Client(host="http://localhost:11434", timeout=60.0)
            response = client.chat(
                model=MODEL_NAME,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.3},
            )
            report_text = response.message.content.strip()
        except Exception as ai_error:
            # FALLBACK: Agar Ollama crash hua toh yeh default report jayegi
            report_text = f"**SYSTEM OVERRIDE**\nAI Model unreachable. Offline analysis confirms:\nRisk Level: {score_data['risk_level']}\nSecure Connection: {scan_data['is_https']}\nKeywords Found: {scan_data['has_suspicious_keywords']}\n\nProceed based on manual indicators."
        
        return {
            "report": report_text, 
            "scan_data": scan_data, 
            "score_data": score_data
        }
        
    except Exception as exc:
        # Ultimate fallback
        return {"error": "false", "report": "CRITICAL SYSTEM FAILURE. ASSUME LINK IS HOSTILE.", "score_data": {"scam_probability_score": "99%", "risk_level": "CRITICAL"}, "scan_data": {"is_https": False, "is_ip_host": True, "has_suspicious_keywords": True}}

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.json
    if not data or not data.get("url"):
        return jsonify({"error": "URL is required"}), 400
    return jsonify(run_agent_bypass(data.get("url")))

if __name__ == "__main__":
    print(f"\n🚀 BULLETPROOF Cyber-Detective API is running on {MODEL_NAME}!")
    app.run(port=5000, debug=True)