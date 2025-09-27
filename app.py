from flask import Flask, render_template, request
import re
from urllib.parse import urlparse
import joblib
import pandas as pd
import socket
import whois
from datetime import datetime

# Load the trained model
model = joblib.load("phishing_train_model.joblib")
print("Model loaded successfully!")

def extract_features_from_url(url: str) -> dict:
    features = {}
    
    # --- Pre-processing and Hostname Correction ---
    if not re.match(r'^https?://', url):
        url_with_scheme = 'http://' + url
    else:
        url_with_scheme = url
    
    try:
        parsed = urlparse(url_with_scheme)
        hostname = parsed.netloc
    except Exception:
        # If parsing fails, it's a malformed URL. Return all features as suspicious.
        feature_names = ['having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State', 'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL', 'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page', 'Statistical_report']
        return {name: 1 for name in feature_names}

    # CRITICAL FIX 1: Find the REAL hostname when '@' is present
    if '@' in hostname:
        hostname = hostname.split('@')[-1]
    if ':' in hostname:
        hostname = hostname.split(':')[0]

    # --- Feature Extraction ---

    # 1. having_IP_Address
    try:
        socket.inet_aton(hostname)
        features["having_IP_Address"] = 1
    except socket.error:
        features["having_IP_Address"] = -1

    # 2. URL_Length (Corrected Logic: Long URLs are suspicious)
    features["URL_Length"] = 1 if len(url) >= 54 else -1

    # 3. Shortining_Service
    shortening_services = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]
    features["Shortining_Service"] = 1 if any(s in url for s in shortening_services) else -1

    # 4. having_At_Symbol
    features["having_At_Symbol"] = 1 if "@" in url else -1

    # 5. double_slash_redirecting
    features["double_slash_redirecting"] = 1 if url.find("//", 8) != -1 else -1

    # 6. Prefix_Suffix
    features["Prefix_Suffix"] = 1 if "-" in hostname else -1

    # 7. having_Sub_Domain
    features["having_Sub_Domain"] = 1 if hostname.count('.') > 2 else -1
    
    # 9. & 24. Domain Age and Registration
    # CRITICAL FIX 2: Treat ALL errors as SUSPICIOUS (1)
    try:
        domain_info = whois.whois(hostname)
        if domain_info.creation_date:
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            age_days = (datetime.now() - creation_date).days
            features["age_of_domain"] = 1 if age_days < 180 else -1
        else:
            features["age_of_domain"] = 1

        if domain_info.expiration_date and domain_info.creation_date:
            expiration_date = domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date
            creation_date_for_reg = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            reg_len_days = (expiration_date - creation_date_for_reg).days
            features["Domain_registeration_length"] = 1 if reg_len_days < 365 else -1
        else:
            features["Domain_registeration_length"] = 1
    except Exception:
        features["age_of_domain"] = 1
        features["Domain_registeration_length"] = 1
        
    # 25. DNSRecord
    try:
        socket.gethostbyname(hostname)
        features["DNSRecord"] = -1
    except socket.gaierror:
        features["DNSRecord"] = 1
        
    # --- Fill in placeholder features ---
    placeholder_features = ['SSLfinal_State', 'Favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL', 'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page', 'Statistical_report']
    for name in placeholder_features:
        if name not in features:
            features[name] = -1

    return features

# --- Flask Application ---
app = Flask(__name__)

@app.route('/')
def homepage():
    return render_template('index.html')

@app.route('/check', methods=['GET', 'POST'])
def Checking_page():
    if request.method == 'GET':
        return render_template("check.html")

    url_to_check = request.form.get('URL', '').strip()
    if not url_to_check:
        return render_template("check.html", error="Please enter a URL.")

    features_dict = extract_features_from_url(url_to_check)
    
    feature_order = ['having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State', 'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL', 'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page', 'Statistical_report']
    
    ordered_features_list = [features_dict.get(f, -1) for f in feature_order]
    X_new = pd.DataFrame([ordered_features_list], columns=feature_order)
    
    prediction = model.predict(X_new)[0]
    result = "Phishing" if prediction == 1 else "Safe"

    return render_template("check.html", url=url_to_check, prediction=result)

if __name__ == '__main__':
    app.run(debug=True)