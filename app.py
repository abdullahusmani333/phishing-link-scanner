"""Phishing Link Scanner (updated). Analyses the TEXT of a link only: it never opens or contacts the link."""
import html
import random
import re
from urllib.parse import urlparse

import streamlit as st

st.set_page_config(page_title="Phishing Link Scanner", page_icon="🎣", layout="centered")

BRANDS = ["google", "microsoft", "amazon", "apple", "facebook", "instagram",
          "whatsapp", "netflix", "github", "paypal", "wikipedia", "twitter"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly"}
RISKY_TLDS = {"xyz", "top", "click", "zip", "work", "tk", "ml", "gq", "cf", "icu", "buzz", "monster"}
KEYWORDS = ["login", "signin", "verify", "secure", "security", "update", "account",
            "password", "prize", "free", "bonus", "confirm", "claim", "wallet"]
SECOND_LEVEL = {"com", "co", "org", "net", "edu", "gov", "ac"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})
FAKE = ["https://microsoft.com.account-verify.xyz/signin", "http://g00gle-security-check.com/login",
        "https://www.amazon.com@free-gifts.top/claim", "https://bit.ly/prize-claim-now",
        "http://192.168.4.12/secure/update", "https://whatsapp-web.verify-chat.click/"]
REAL = ["https://accounts.google.com", "https://www.wikipedia.org", "https://github.com/login", "https://docs.python.org/3/"]


def split_url(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    netloc = parsed.netloc.lower()
    userinfo, _, hostport = netloc.rpartition("@")
    host = hostport.split(":")[0]
    return parsed, userinfo, host


def registered(host):
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:]), labels[-3]
    if len(labels) >= 2:
        return ".".join(labels[-2:]), labels[-2]
    return host, host


def scan(url):
    """Return (risk_label, reasons, score). A clean result means 'no red flags', never 'safe'."""
    url = url.strip()
    parsed, userinfo, host = split_url(url)
    if not host or " " in url:
        return "Can't read this link", ["This doesn't look like a web address"], 0
    path = (parsed.path + "?" + parsed.query).lower()
    score, reasons = 0, []

    def flag(points, text):
        nonlocal score
        score += points
        reasons.append(text)

    if "://" in url and parsed.scheme != "https":
        flag(1, "Not using HTTPS, so the connection is not encrypted")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        flag(3, "Uses a raw IP address instead of a website name")
    if "@" in parsed.netloc:
        flag(3, "Contains '@': everything before it is ignored, and the real site is after it")
    if len(url) > 75:
        flag(1, "Very long link, often used to hide the real destination")
    if host in SHORTENERS:
        flag(2, "Link shortener: you can't see where it really leads")
    if "xn--" in host:
        flag(3, "Uses look-alike characters (punycode) to imitate a real name")

    reg, name = registered(host)
    if host.count(".") >= 4:
        flag(1, "Unusually many subdomains")
    for brand in BRANDS:
        if name == brand:
            continue
        if brand in host:
            flag(3, f"Mentions '{brand}' but the real site is {reg}")
            break
        if brand in host.translate(LEET) and "xn--" not in host:
            flag(3, f"Looks like a fake spelling of '{brand}' (swapped characters)")
            break
    tld = host.split(".")[-1]
    if tld in RISKY_TLDS:
        flag(1, f"Ends in .{tld}, an ending often used by scam sites")
    if host.count("-") >= 2:
        flag(1, "Several hyphens in the site name")
    hits = {k for k in KEYWORDS if k in host or k in path}
    if len(hits) >= 2:
        flag(1, "Pressure words in the link: " + ", ".join(sorted(hits)))

    risk = "High risk" if score >= 4 else "Suspicious" if score >= 2 else "Minor flag only" if score == 1 else "No red flags found"
    return risk, reasons, score


def anatomy(url):
    """Show the link with the real website highlighted."""
    parsed, userinfo, host = split_url(url.strip())
    e = html.escape
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        sub, real = "", host
    else:
        reg, _ = registered(host)
        sub, real = host[: len(host) - len(reg)], reg
    scheme = (parsed.scheme + "://") if "://" in url else ""
    rest = url.strip().split(parsed.netloc, 1)[-1] if parsed.netloc in url.lower() else ""
    port = parsed.netloc.rsplit("@", 1)[-1][len(host):]
    out = f'<span class="dim">{e(scheme)}</span>'
    if userinfo:
        out += f'<span class="ignored">{e(userinfo)}@</span>'
    out += f'<span class="dim">{e(sub)}</span><span class="real">{e(real)}</span><span class="dim">{e(port)}{e(rest)}</span>'
    return out


st.markdown("""
<style>
#MainMenu, footer, header {visibility:hidden;}
.stApp {background-color:#0E1621;
  background-image: linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px);
  background-size:44px 44px;}
.block-container {max-width:760px; padding-top:1.4rem;}
.mono {font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; letter-spacing:.09em; text-transform:uppercase; font-size:.78rem; color:#8FA3B8;}
.topbar {display:flex; justify-content:space-between; border-bottom:1px solid #26384A; padding-bottom:.5rem; margin-bottom:1rem;}
.panel {background:#16222F; border:1px solid #26384A; border-radius:10px; padding:1rem 1.2rem; margin:.6rem 0; line-height:1.55;}
.url {background:#0A111A; border:1px solid #2F4358; border-radius:8px; padding:.9rem 1.1rem; font-family: ui-monospace, Menlo, Consolas, monospace; font-size:1.15rem; word-break:break-all;}
.dim {color:#8FA3B8;} .real {color:#F2B134; font-weight:800; border-bottom:3px solid #F2B134;} .ignored {color:#E4572E; text-decoration:line-through;}
.meter-track {height:14px; background:#0A111A; border:1px solid #26384A; border-radius:7px; overflow:hidden; position:relative; margin:.4rem 0 .8rem;}
.meter-fill {height:100%;}
.meter-track::after {content:""; position:absolute; inset:0; background:repeating-linear-gradient(90deg, transparent 0 18px, #0A111A 18px 20px);}
.verdict {font-size:2.2rem; font-weight:800; line-height:1.1;}
.reason {margin:.3rem 0;}
div.stButton > button {width:100%; padding:.7rem 1rem; font-weight:600; border-radius:8px; background:#16222F; color:#E6EDF3; border:1px solid #2F4358;}
div.stButton > button:hover {border-color:#F2B134; color:#F2B134;}
div.stButton > button p {color:inherit;}
</style>
""", unsafe_allow_html=True)

S = st.session_state


def example(kind):
    S.url = random.choice(FAKE if kind == "fake" else REAL)


st.markdown('<div class="topbar"><span class="mono">Cyber Defense Unit // Link Lab</span></div>', unsafe_allow_html=True)
st.markdown("# Phishing Link Scanner")
st.markdown('<div class="panel">Paste a link to check it for red flags. This tool only reads the <b>text</b> of the link. '
            'It never opens it, so it is safe to paste suspicious links here.</div>', unsafe_allow_html=True)
st.text_input("Link to check", key="url", placeholder="https://example.com")
c1, c2 = st.columns(2)
c1.button("Try a fake link", on_click=example, args=("fake",))
c2.button("Try a real link", on_click=example, args=("real",))

url = (S.get("url") or "").strip()
if url:
    risk, reasons, score = scan(url)
    color = "#E4572E" if risk == "High risk" else "#F2B134" if risk == "Suspicious" else "#3DD6B5" if risk == "No red flags found" else "#8FA3B8"
    st.markdown(f'<div class="verdict" style="color:{color}">{html.escape(risk)}</div>'
                f'<div class="meter-track"><div class="meter-fill" style="width:{min(score, 6) / 6 * 100:.0f}%;background:{color}"></div></div>',
                unsafe_allow_html=True)
    if risk != "Can't read this link":
        st.markdown('<div class="mono" style="margin-bottom:.3rem">Link anatomy: the amber part is the real website</div>'
                    f'<div class="url">{anatomy(url)}</div>', unsafe_allow_html=True)
    st.markdown('<div class="mono" style="margin-top:1rem">Why</div>', unsafe_allow_html=True)
    for r in reasons or ["Nothing suspicious in the text of the link."]:
        st.markdown(f'<div class="reason">&#9656; {html.escape(r)}</div>', unsafe_allow_html=True)
    advice = {"High risk": "Don't open it. Delete the message and report it. If you must visit the company, type its address yourself.",
              "Suspicious": "Don't enter any information. Open the official site by typing its address yourself.",
              "Minor flag only": "Probably fine, but check who sent it and don't enter passwords through links in messages.",
              "No red flags found": "This only checks the link's text. Still check who sent it, and don't enter passwords through links in messages."}
    if risk in advice:
        st.markdown(f'<div class="panel"><b>What to do:</b> {advice[risk]}</div>', unsafe_allow_html=True)
st.caption("A rule-based teaching tool, not a guarantee. 'No red flags found' never means a link is safe.")
