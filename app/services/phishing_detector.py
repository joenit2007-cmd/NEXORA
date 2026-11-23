"""Hybrid Machine Learning + Transparent Rule-Based Phishing Email Analyzer.

SECURITY GUARANTEE: This module performs strictly static lexical, structural,
and ML text analysis. It NEVER connects to, resolves, fetches, or executes any
submitted URL or attachment.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

URL_EXTRACT_RE = re.compile(r"https?://[^\s<>\"'()]+", re.IGNORECASE)
IPV4_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
EMAIL_EXTRACT_RE = re.compile(r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})")

URGENCY_PHRASES = [
    "act immediately",
    "urgent action required",
    "account suspended",
    "account will be closed",
    "within 24 hours",
    "within 48 hours",
    "final notice",
    "immediate verification",
    "unauthorized login",
    "unusual sign-in",
    "expire today",
    "suspended immediately",
    "limited time",
    "failure to comply",
    "respond immediately",
]

CREDENTIAL_AND_LURE_PHRASES = [
    "verify your account",
    "confirm your identity",
    "verify your password",
    "reset your password",
    "update your billing",
    "update payment",
    "confirm your bank",
    "social security",
    "wire transfer",
    "gift card",
    "click the link below",
    "log in below",
    "login credentials",
    "validate your mailbox",
    "mailbox quota exceeded",
    "claim your prize",
    "inheritance",
    "tax refund",
]

SUSPICIOUS_ATTACHMENT_TERMS = [
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".ps1",
    ".iso",
    ".xlsm",
    ".docm",
    ".zip",
    ".rar",
    "enable macros",
    "enable content",
    "password-protected",
    "password is",
    "open the attached invoice",
    "download the attached form",
]

IMPERSONATED_BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com"],
    "office 365": ["microsoft.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "google": ["google.com", "gmail.com"],
    "netflix": ["netflix.com"],
    "bank of america": ["bankofamerica.com"],
    "chase": ["chase.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "irs": ["irs.gov"],
    "it helpdesk": [],
    "hr department": [],
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rb.gy",
    "cutt.ly",
    "rebrand.ly",
}

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".zip",
    ".mov",
    ".click",
    ".work",
    ".support",
    ".security",
    ".ru",
}

FREE_WEBMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "aol.com",
    "protonmail.com",
    "mail.com",
    "yandex.com",
}


class PhishingClassifierEngine:
    """Reproducible TF-IDF + Logistic Regression phishing classifier with transparent fallback."""

    def __init__(self, dataset_path: Path | None = None):
        self.dataset_path = dataset_path or (
            Path(__file__).resolve().parent.parent.parent / "sample_data" / "phishing_dataset.csv"
        )
        self.pipeline: Pipeline | None = None
        self.model_ready: bool = False
        self.metrics: dict[str, Any] = {}
        self._train_if_available()

    def _train_if_available(self) -> None:
        if not self.dataset_path.is_file():
            self.model_ready = False
            self.metrics = {
                "available": False,
                "reason": "Training dataset not found; operating in transparent rule-based mode.",
            }
            return

        try:
            df = pd.read_csv(self.dataset_path)
            if "text" not in df.columns or "label" not in df.columns or len(df) < 40:
                self.model_ready = False
                self.metrics = {
                    "available": False,
                    "reason": "Insufficient labeled records (<40); operating in transparent rule-based mode.",
                }
                return

            df = df.dropna(subset=["text", "label"]).copy()
            X = df["text"].astype(str)
            y = df["label"].astype(int)

            if y.nunique() < 2:
                self.model_ready = False
                self.metrics = {
                    "available": False,
                    "reason": "Dataset must contain both phishing and legitimate classes.",
                }
                return

            X_train, X_test, y_train, y_test = train_test_split(
                X,
                y,
                test_size=0.25,
                random_state=42,
                stratify=y,
            )

            pipeline = Pipeline(
                [
                    (
                        "tfidf",
                        TfidfVectorizer(
                            lowercase=True,
                            stop_words="english",
                            ngram_range=(1, 2),
                            max_features=3000,
                            sublinear_tf=True,
                        ),
                    ),
                    (
                        "clf",
                        LogisticRegression(
                            C=1.5,
                            max_iter=1000,
                            random_state=42,
                            class_weight="balanced",
                        ),
                    ),
                ]
            )
            pipeline.fit(X_train, y_train)
            y_pred = pipeline.predict(X_test)
            cm = confusion_matrix(y_test, y_pred, labels=[0, 1])

            self.pipeline = pipeline
            self.model_ready = True
            self.metrics = {
                "available": True,
                "algorithm": "TF-IDF (unigrams + bigrams) + Logistic Regression",
                "dataset_file": self.dataset_path.name,
                "total_samples": int(len(df)),
                "phishing_samples": int((y == 1).sum()),
                "legitimate_samples": int((y == 0).sum()),
                "train_size": int(len(X_train)),
                "test_size": int(len(X_test)),
                "random_state": 42,
                "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
                "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
                "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
                "f1_score": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
                "confusion_matrix": {
                    "tn": int(cm[0][0]),
                    "fp": int(cm[0][1]),
                    "fn": int(cm[1][0]),
                    "tp": int(cm[1][1]),
                },
            }
        except Exception as exc:
            self.pipeline = None
            self.model_ready = False
            self.metrics = {
                "available": False,
                "reason": f"ML model training skipped ({exc}); using rule-based mode.",
            }

    def predict_text(self, combined_text: str) -> tuple[float | None, list[str]]:
        """Return (phishing_probability, top_contributing_terms)."""
        if not self.model_ready or self.pipeline is None:
            return None, []

        prob = float(self.pipeline.predict_proba([combined_text])[0][1])

        # Explain top positively contributing TF-IDF features present in this email
        vectorizer: TfidfVectorizer = self.pipeline.named_steps["tfidf"]
        clf: LogisticRegression = self.pipeline.named_steps["clf"]
        vec = vectorizer.transform([combined_text])
        feature_names = vectorizer.get_feature_names_out()
        coefs = clf.coef_[0]

        contributions: list[tuple[float, str]] = []
        coo = vec.tocoo()
        for idx, val in zip(coo.col, coo.data):
            score = float(val * coefs[idx])
            if score > 0.04:
                contributions.append((score, str(feature_names[idx])))
        contributions.sort(reverse=True)
        top_terms = [term for _, term in contributions[:6]]
        return round(prob, 4), top_terms


_ENGINE_INSTANCE: PhishingClassifierEngine | None = None


def get_phishing_engine() -> PhishingClassifierEngine:
    global _ENGINE_INSTANCE
    if _ENGINE_INSTANCE is None:
        _ENGINE_INSTANCE = PhishingClassifierEngine()
    return _ENGINE_INSTANCE


def reset_phishing_engine(dataset_path: Path | None = None) -> PhishingClassifierEngine:
    """Re-initialize engine (useful for testing fallback or updated dataset)."""
    global _ENGINE_INSTANCE
    _ENGINE_INSTANCE = PhishingClassifierEngine(dataset_path=dataset_path)
    return _ENGINE_INSTANCE


def _analyze_urls(urls: list[str]) -> tuple[float, list[dict[str, Any]]]:
    score = 0.0
    indicators: list[dict[str, Any]] = []
    seen: set[str] = set()

    for raw_url in urls:
        url = raw_url.strip()
        if not url or url in seen:
            continue
        seen.add(url)

        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "").lower()
        path_query = f"{parsed.path or ''}?{parsed.query or ''}".lower()

        if not host:
            continue

        # 1. Raw IP address in URL
        if IPV4_HOST_RE.match(host):
            score += 24
            indicators.append(
                {
                    "category": "Suspicious URL Pattern",
                    "severity": "High",
                    "detail": f"URL uses a raw IP address instead of a domain name: '{host}'.",
                }
            )

        # 2. '@' symbol obfuscation in URL
        if "@" in url:
            score += 22
            indicators.append(
                {
                    "category": "URL Obfuscation",
                    "severity": "High",
                    "detail": "URL contains an '@' symbol, a known technique to disguise the true destination host.",
                }
            )

        # 3. Punycode / IDN homograph indicator
        if "xn--" in host:
            score += 20
            indicators.append(
                {
                    "category": "URL Obfuscation",
                    "severity": "High",
                    "detail": f"Punycode (internationalized domain) detected in '{host}', often used in homograph spoofing.",
                }
            )

        # 4. URL shortener
        if host in URL_SHORTENERS:
            score += 14
            indicators.append(
                {
                    "category": "URL Obfuscation",
                    "severity": "Medium",
                    "detail": f"URL shortener domain '{host}' hides the true target destination.",
                }
            )

        # 5. Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                score += 14
                indicators.append(
                    {
                        "category": "Suspicious Domain TLD",
                        "severity": "Medium",
                        "detail": f"URL host '{host}' uses high-abuse top-level domain '{tld}'.",
                    }
                )
                break

        # 6. Excessive subdomains or hyphenated brand lure
        if host.count(".") >= 3 and not IPV4_HOST_RE.match(host):
            score += 10
            indicators.append(
                {
                    "category": "URL Obfuscation",
                    "severity": "Medium",
                    "detail": f"URL host '{host}' contains excessive subdomain nesting.",
                }
            )

        # 7. Plaintext HTTP with credential keywords
        if scheme == "http" and any(k in path_query or k in host for k in ("login", "verify", "secure", "account", "bank", "signin", "update")):
            score += 14
            indicators.append(
                {
                    "category": "Insecure Credential Link",
                    "severity": "High",
                    "detail": f"Unencrypted HTTP link references login/verification keywords: '{host}'.",
                }
            )

        # 8. Brand impersonation inside non-official URL host
        for brand, official_domains in IMPERSONATED_BRANDS.items():
            brand_token = brand.replace(" ", "")
            if official_domains and brand_token in host:
                if not any(host == d or host.endswith(f".{d}") for d in official_domains):
                    score += 22
                    indicators.append(
                        {
                            "category": "Brand Impersonation URL",
                            "severity": "High",
                            "detail": f"URL host '{host}' contains brand keyword '{brand}' but does not match official domain(s) ({', '.join(official_domains)}).",
                        }
                    )
                    break

        # 9. Percent-encoding obfuscation
        if len(re.findall(r"%[0-9a-fA-F]{2}", url)) >= 4:
            score += 10
            indicators.append(
                {
                    "category": "URL Obfuscation",
                    "severity": "Medium",
                    "detail": f"Heavy percent-encoding detected in URL targeting '{host}'.",
                }
            )

    return min(score, 65.0), indicators


def analyze_phishing_email(
    *,
    content: str,
    sender: str = "",
    subject: str = "",
    extra_urls: str = "",
    engine: PhishingClassifierEngine | None = None,
) -> dict[str, Any]:
    """Perform static rule-based + ML phishing assessment without visiting any URLs."""
    clean_content = (content or "").strip()
    clean_sender = (sender or "").strip()
    clean_subject = (subject or "").strip()
    clean_extra_urls = (extra_urls or "").strip()

    if not clean_content and not clean_extra_urls and not clean_subject:
        return {
            "success": False,
            "error": "Please provide email content, a subject line, or at least one URL to analyze.",
        }

    # Extract URLs from content and explicit URL field
    extracted_urls = URL_EXTRACT_RE.findall(clean_content)
    if clean_extra_urls:
        for token in re.split(r"[\s,;]+", clean_extra_urls):
            if token and ("." in token or "://" in token):
                extracted_urls.append(token.strip())
    # Deduplicate while preserving order
    unique_urls = list(dict.fromkeys(extracted_urls))

    combined_text = f"Subject: {clean_subject}\nSender: {clean_sender}\n{clean_content}".strip()
    lower_text = combined_text.lower()

    rule_score = 0.0
    indicators: list[dict[str, Any]] = []

    # 1. Urgency & coercive social engineering
    matched_urgency = [p for p in URGENCY_PHRASES if p in lower_text]
    if matched_urgency:
        pts = min(24.0, 10.0 + (len(matched_urgency) - 1) * 6.0)
        rule_score += pts
        indicators.append(
            {
                "category": "Urgent / Coercive Language",
                "severity": "High" if len(matched_urgency) >= 2 else "Medium",
                "detail": f"Detected urgency phrase(s): {', '.join(matched_urgency[:5])}.",
            }
        )

    # 2. Credential harvesting & social engineering lures
    matched_lures = [p for p in CREDENTIAL_AND_LURE_PHRASES if p in lower_text]
    if matched_lures:
        pts = min(26.0, 12.0 + (len(matched_lures) - 1) * 6.0)
        rule_score += pts
        indicators.append(
            {
                "category": "Credential / Financial Lure",
                "severity": "High" if len(matched_lures) >= 2 else "Medium",
                "detail": f"Detected suspicious request keyword(s): {', '.join(matched_lures[:5])}.",
            }
        )

    # 3. Suspicious attachment / macro lures
    matched_attach = [p for p in SUSPICIOUS_ATTACHMENT_TERMS if p in lower_text]
    if matched_attach:
        pts = min(22.0, 12.0 + (len(matched_attach) - 1) * 5.0)
        rule_score += pts
        indicators.append(
            {
                "category": "Suspicious Attachment Reference",
                "severity": "High",
                "detail": f"References potentially hazardous attachment/macro indicator(s): {', '.join(matched_attach[:5])}.",
            }
        )

    # 4. Sender analysis & brand impersonation mismatch
    sender_domain = ""
    if clean_sender:
        em = EMAIL_EXTRACT_RE.search(clean_sender)
        if em:
            sender_addr = em.group(1).lower()
            sender_domain = sender_addr.split("@", 1)[1]
            local_part = sender_addr.split("@", 1)[0]

            # Suspicious TLD on sender
            for tld in SUSPICIOUS_TLDS:
                if sender_domain.endswith(tld):
                    rule_score += 18.0
                    indicators.append(
                        {
                            "category": "Suspicious Sender Domain",
                            "severity": "High",
                            "detail": f"Sender domain '{sender_domain}' uses high-abuse TLD '{tld}'.",
                        }
                    )
                    break

            # Digits-heavy / hyphen-stuffed spoofing domain
            if sender_domain.count("-") >= 2 or re.search(r"\d{3,}", local_part):
                rule_score += 10.0
                indicators.append(
                    {
                        "category": "Suspicious Sender Pattern",
                        "severity": "Medium",
                        "detail": f"Sender address '{sender_addr}' shows automated or lookalike naming patterns.",
                    }
                )
        else:
            rule_score += 8.0
            indicators.append(
                {
                    "category": "Malformed Sender Address",
                    "severity": "Low",
                    "detail": f"Sender field '{clean_sender[:80]}' does not contain a standard email address.",
                }
            )

    # Brand impersonation check (mentions brand in subject/body/display name while sender domain mismatches)
    for brand, official_domains in IMPERSONATED_BRANDS.items():
        if brand in lower_text:
            if sender_domain and official_domains:
                if not any(sender_domain == d or sender_domain.endswith(f".{d}") for d in official_domains):
                    rule_score += 22.0
                    indicators.append(
                        {
                            "category": "Brand Impersonation",
                            "severity": "High",
                            "detail": (
                                f"Message references '{brand.title()}' but originates from non-official domain "
                                f"'{sender_domain}' (expected {', '.join(official_domains)})."
                            ),
                        }
                    )
                    break
            elif sender_domain in FREE_WEBMAIL_DOMAINS and brand in {"it helpdesk", "hr department"}:
                rule_score += 16.0
                indicators.append(
                    {
                        "category": "Internal Authority Spoofing",
                        "severity": "High",
                        "detail": f"Message purports to be from '{brand.title()}' using public webmail domain '{sender_domain}'.",
                    }
                )
                break

    # 5. URL static lexical analysis
    url_score, url_indicators = _analyze_urls(unique_urls)
    rule_score += url_score
    indicators.extend(url_indicators)

    # Cap rule score at 100
    rule_score = round(min(100.0, rule_score), 2)

    # 6. Machine Learning prediction (if model ready)
    active_engine = engine or get_phishing_engine()
    ml_prob, ml_terms = active_engine.predict_text(combined_text)

    if ml_prob is not None:
        ml_score = ml_prob * 100.0
        # Blend transparently: 60% rule-based indicators + 40% ML probability,
        # ensuring strong concrete rule signals (like IP URL + brand spoofing) aren't diluted.
        if rule_score >= 60:
            final_score = max(rule_score, round(0.65 * rule_score + 0.35 * ml_score, 2))
        elif rule_score == 0 and ml_score < 55:
            final_score = round(0.35 * ml_score, 2)
        else:
            final_score = round(0.60 * rule_score + 0.40 * ml_score, 2)
        detection_method = "Hybrid ML + Rule-Based"
        if ml_terms and ml_prob >= 0.55:
            indicators.append(
                {
                    "category": "ML Lexical Classification",
                    "severity": "High" if ml_prob >= 0.78 else "Medium",
                    "detail": (
                        f"TF-IDF + Logistic Regression classifier estimated {ml_prob * 100:.1f}% phishing likelihood. "
                        f"Key weighted terms: {', '.join(ml_terms)}."
                    ),
                }
            )
    else:
        final_score = rule_score
        detection_method = "Rule-Based Scoring"

    final_score = round(min(100.0, max(0.0, final_score)), 2)

    if final_score >= 65.0:
        risk_level = "High Risk"
        recommended_action = (
            "Do NOT click links, reply, or open attachments. Quarantine the email, block the sender domain, "
            "and notify affected users if credentials may have been exposed."
        )
    elif final_score >= 35.0:
        risk_level = "Suspicious"
        recommended_action = (
            "Treat with caution. Independently verify the sender via a trusted out-of-band channel before acting, "
            "and inspect email headers (SPF/DKIM/DMARC)."
        )
    else:
        risk_level = "Low Risk"
        recommended_action = (
            "No major phishing indicators detected by static analysis. Maintain normal email hygiene and verify "
            "unexpected requests independently."
        )

    if indicators:
        explanation = (
            f"Classified as {risk_level} (score {final_score:.1f}/100 via {detection_method}) based on "
            f"{len(indicators)} observed indicator(s): "
            + "; ".join(ind["category"] for ind in indicators[:5])
            + "."
        )
    else:
        explanation = (
            f"Classified as {risk_level} (score {final_score:.1f}/100 via {detection_method}). "
            "No suspicious urgency, impersonation, obfuscated URLs, or hazardous attachment cues were detected."
        )

    return {
        "success": True,
        "sender": clean_sender or "Not provided",
        "subject": clean_subject or "(No subject)",
        "urls": unique_urls,
        "content_preview": clean_content[:1200] if clean_content else "(URL-only analysis)",
        "risk_level": risk_level,
        "risk_score": final_score,
        "rule_score": rule_score,
        "ml_probability": ml_prob,
        "ml_terms": ml_terms,
        "detection_method": detection_method,
        "indicators": indicators,
        "explanation": explanation,
        "recommended_action": recommended_action,
    }
