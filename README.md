# Phishing Link Scanner (updated)

Reads the text of a link and lists red flags. It never opens or contacts the link. Runs fully offline.

## Run
    python3 -m venv venv
    source venv/bin/activate          # Windows: venv\Scripts\activate
    pip install --upgrade pip
    pip install --only-binary=:all: -r requirements.txt
    streamlit run app.py --server.address localhost

## What changed from the first version
- Catches brand names hidden in subdomains (microsoft.com.account-verify.xyz), swapped-character spellings, `@` tricks, shorteners and look-alike (punycode) names.
- Real registered domain is found properly, including endings like .com.pk.
- Hyphens are no longer penalised on their own; several hyphens are.
- Result wording is "No red flags found" instead of "Likely Safe".
- Link anatomy view highlights the real website; example buttons; advice per result; dark theme.
