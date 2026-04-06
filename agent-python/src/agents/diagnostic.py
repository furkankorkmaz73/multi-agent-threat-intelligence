from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import re

from agents.llm_helper import extract_cve_info, classify_dread, generate_explanation


class DiagnosticAgent:
    STOPWORDS = {
        "the", "and", "for", "with", "that", "this", "from", "into", "have", "has",
        "allow", "allows", "could", "would", "there", "their", "them", "been",
        "being", "after", "before", "about", "through", "remote", "local", "attack",
        "attacker", "attackers", "vulnerability", "vulnerabilities", "product",
        "products", "component", "components", "affected", "impact", "issue",
        "causes", "using", "used", "when", "where", "which", "via",
        "unauthenticated", "authenticated", "arbitrary", "code", "execution",
        "privilege", "escalation", "denial", "service", "overflow", "buffer",
        "improper", "input", "validation", "application", "software", "version",
        "versions", "may", "can", "also",
    }

    HIGH_SIGNAL_TERMS = {
        "rce", "exploit", "0day", "zero-day", "zeroday", "leak", "breach",
        "malware", "botnet", "cobaltstrike", "ransomware", "phishing",
        "credential", "access", "shell", "loader", "dropper", "backdoor",
    }

    DREAD_CLASSIFIERS = {
        "exploit_sale": ["exploit", "0day", "zero-day", "zeroday", "rce", "weaponized"],
        "data_leak": ["leak", "database", "dump", "breach", "records"],
        "access_sale": ["access", "vpn", "rdp", "foothold", "initial access"],
        "malware_activity": ["malware", "stealer", "ransomware", "botnet", "loader"],
    }

    def analyze(
        self,
        source: str,
        data: Dict[str, Any],
        db: Optional[Any] = None,
    ) -> Optional[Dict[str, Any]]:
        if source == "cve":
            return self._analyze_cve(data, db)
        if source == "urlhaus":
            return self._analyze_urlhaus(data, db)
        if source == "dread":
            return self._analyze_dread(data, db)
        return None

    def _analyze_cve(
        self,
        data: Dict[str, Any],
        db: Optional[Any],
    ) -> Dict[str, Any]:
        cve_id = data.get("_id", "unknown-cve")
        description = self._get_primary_description(data)
        cvss_score, cvss_version = self._extract_cvss_score(data.get("metrics", {}))
        keywords = self._extract_keywords(description, cve_id)

        llm_info = extract_cve_info(description) if description else {}

        age_days = self._calculate_age_days(data.get("published"))
        recentness_bonus = self._calculate_recentness_bonus(age_days)
        age_penalty = self._calculate_age_penalty(age_days)

        urlhaus_matches = db.find_related_urlhaus(keywords, limit=10) if db else []
        dread_matches = db.find_related_dread(keywords, limit=10) if db else []

        urlhaus_score, urlhaus_explanations = self._score_urlhaus_matches(urlhaus_matches)
        dread_score, dread_explanations, dread_categories = self._score_dread_matches(dread_matches)
        llm_bonus, llm_explanations = self._score_llm_cve_info(llm_info)

        base_score = 1.5 if cvss_score == 0 else cvss_score * 0.55

        weighted_score = (
            base_score
            + recentness_bonus
            + urlhaus_score
            + dread_score
            + llm_bonus
            - age_penalty
        )
        weighted_score = max(0.0, min(round(weighted_score, 2), 10.0))

        risk_level = self._level_from_score(weighted_score)

        explanations: List[str] = [
            f"Base risk derived from CVSS ({cvss_version}) score: {cvss_score}",
        ]

        if age_days is not None:
            explanations.append(f"Estimated vulnerability age: {age_days} day(s).")

        if recentness_bonus > 0:
            explanations.append("Recently published or updated vulnerability increased priority.")

        if age_penalty > 0:
            explanations.append("Older vulnerability record reduced current priority score.")

        explanations.extend(urlhaus_explanations)
        explanations.extend(dread_explanations)
        explanations.extend(llm_explanations)

        if not urlhaus_matches and not dread_matches:
            explanations.append("No cross-source corroboration found; score relies mainly on CVE metadata.")

        llm_text_explanation = generate_explanation(
            {
                "entity_type": "cve",
                "entity_id": cve_id,
                "risk_score": weighted_score,
                "risk_level": risk_level,
                "cvss_score": cvss_score,
                "cvss_version": cvss_version,
                "age_days": age_days,
                "urlhaus_matches": len(urlhaus_matches),
                "dread_matches": len(dread_matches),
                "llm_info": llm_info,
            }
        )

        if llm_text_explanation:
            explanations = [llm_text_explanation] + explanations

        confidence = self._calculate_confidence(
            has_cvss=cvss_score > 0,
            urlhaus_match_count=len(urlhaus_matches),
            dread_match_count=len(dread_matches),
            keyword_count=len(keywords),
            llm_fields_count=self._count_non_empty_llm_fields(llm_info),
        )

        return {
            "entity_type": "cve",
            "entity_id": cve_id,
            "risk_score": weighted_score,
            "risk_level": risk_level,
            "confidence": confidence,
            "diagnosis": (
                f"{cve_id} evaluated as {risk_level} "
                f"(dynamic score={weighted_score}, base CVSS={cvss_score})."
            ),
            "explanation": explanations,
            "evidence": {
                "keywords": keywords,
                "cvss_score": cvss_score,
                "cvss_version": cvss_version,
                "age_days": age_days,
                "related_urlhaus_count": len(urlhaus_matches),
                "related_dread_count": len(dread_matches),
                "dread_categories": dread_categories,
                "sample_urlhaus_hits": self._sample_urlhaus_hits(urlhaus_matches),
                "sample_dread_hits": self._sample_dread_hits(dread_matches),
                "llm_products": llm_info.get("products", []),
                "llm_versions": llm_info.get("versions", []),
                "llm_vuln_type": llm_info.get("vuln_type"),
                "llm_impact": llm_info.get("impact"),
            },
        }

    def _analyze_urlhaus(
        self,
        data: Dict[str, Any],
        db: Optional[Any],
    ) -> Dict[str, Any]:
        threat = (data.get("threat") or "unknown").lower()
        tags = [str(tag).lower() for tag in (data.get("tags") or [])]
        url = data.get("url", "")
        status = (data.get("url_status") or "").lower()

        text = " ".join([threat, url, " ".join(tags)])
        keywords = self._extract_keywords(text)

        related_cves = db.find_related_cves(keywords, limit=10) if db else []
        related_dread = db.find_related_dread(keywords, limit=10) if db else []

        base_score = 1.8
        explanations = ["Base risk assigned from malicious URL / IOC feed presence."]

        category_score, category_notes = self._score_urlhaus_category(threat, tags)
        base_score += category_score
        explanations.extend(category_notes)

        status_score, status_notes = self._score_urlhaus_status(status)
        base_score += status_score
        explanations.extend(status_notes)

        structure_score, structure_notes = self._score_url_structure(url)
        base_score += structure_score
        explanations.extend(structure_notes)

        tag_count = len(set(tags))
        if tag_count >= 3:
            base_score += 0.45
            explanations.append("Multiple IOC tags increased contextual confidence.")
        elif tag_count == 2:
            base_score += 0.20
            explanations.append("More than one IOC tag slightly increased confidence.")

        if related_cves:
            bonus = min(len(related_cves) * 0.45, 2.0)
            base_score += bonus
            explanations.append(f"Related CVE references found ({len(related_cves)} match).")

        if related_dread:
            bonus = min(len(related_dread) * 0.25, 1.0)
            base_score += bonus
            explanations.append(f"Dark-web discussion overlap found ({len(related_dread)} match).")

        if status == "offline" and category_score < 1.5 and structure_score < 0.8:
            base_score -= 0.35
            explanations.append("Lower operational urgency due to weak signal combination.")

        risk_score = min(round(max(base_score, 0.0), 2), 10.0)
        risk_level = self._level_from_score(risk_score)

        llm_text_explanation = generate_explanation(
            {
                "entity_type": "urlhaus",
                "entity_id": data.get("urlhaus_id") or data.get("url"),
                "risk_score": risk_score,
                "risk_level": risk_level,
                "threat": threat,
                "tags": tags,
                "url_status": status,
                "related_cves": len(related_cves),
                "related_dread": len(related_dread),
            }
        )

        if llm_text_explanation:
            explanations = [llm_text_explanation] + explanations

        confidence = self._calculate_confidence(
            has_cvss=False,
            urlhaus_match_count=1,
            dread_match_count=len(related_dread),
            keyword_count=len(keywords),
            llm_fields_count=0,
        )

        return {
            "entity_type": "urlhaus",
            "entity_id": data.get("urlhaus_id") or data.get("url") or "unknown-urlhaus",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "confidence": confidence,
            "diagnosis": f"Malicious URL intelligence evaluated as {risk_level}.",
            "explanation": explanations,
            "evidence": {
                "keywords": keywords,
                "threat": threat,
                "tags": tags,
                "url_status": status,
                "related_cve_count": len(related_cves),
                "related_dread_count": len(related_dread),
                "sample_related_cves": self._sample_cve_hits(related_cves),
                "sample_dread_hits": self._sample_dread_hits(related_dread),
            },
        }

    def _analyze_dread(
        self,
        data: Dict[str, Any],
        db: Optional[Any],
    ) -> Dict[str, Any]:
        title = data.get("title", "")
        content = data.get("content", "")
        combined = f"{title} {content}".lower()

        categories: List[str] = []
        matched_terms: List[str] = []

        for category, terms in self.DREAD_CLASSIFIERS.items():
            hits = [term for term in terms if term in combined]
            if hits:
                categories.append(category)
                matched_terms.extend(hits)

        llm_cls = classify_dread(combined) if combined.strip() else {}
        llm_category = llm_cls.get("category")
        llm_confidence = llm_cls.get("confidence", 0.0)

        if llm_category and llm_category not in categories:
            categories.append(llm_category)

        keywords = self._extract_keywords(combined)
        related_cves = db.find_related_cves(keywords, limit=10) if db else []
        related_urlhaus = db.find_related_urlhaus(keywords, limit=10) if db else []

        base_score = 2.0
        explanations = [
            "Dark-web source is treated as experimental/low-trust supporting intelligence."
        ]

        if categories:
            base_score += min(len(categories) * 1.2, 3.0)
            explanations.append(f"Detected dark-web activity categories: {', '.join(categories)}.")
        if llm_category:
            explanations.append(
                f"LLM classified the post as '{llm_category}' with confidence {llm_confidence}."
            )
        if related_cves:
            base_score += min(len(related_cves) * 0.35, 1.5)
            explanations.append(f"Possible overlap with CVE records ({len(related_cves)} match).")
        if related_urlhaus:
            base_score += min(len(related_urlhaus) * 0.25, 1.0)
            explanations.append(f"Possible overlap with URLhaus indicators ({len(related_urlhaus)} match).")

        risk_score = min(round(base_score, 2), 8.5)
        risk_level = self._level_from_score(risk_score)

        llm_text_explanation = generate_explanation(
            {
                "entity_type": "dread",
                "risk_score": risk_score,
                "risk_level": risk_level,
                "categories": categories,
                "llm_category": llm_category,
                "llm_confidence": llm_confidence,
                "related_cves": len(related_cves),
                "related_urlhaus": len(related_urlhaus),
            }
        )

        if llm_text_explanation:
            explanations = [llm_text_explanation] + explanations

        confidence = round(
            min(
                0.35
                + (0.10 * len(categories))
                + (0.03 * len(related_cves))
                + (0.02 * len(related_urlhaus))
                + min(float(llm_confidence or 0.0) * 0.10, 0.08),
                0.85,
            ),
            2,
        )

        return {
            "entity_type": "dread",
            "entity_id": str(data.get("_id", "unknown-dread")),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "confidence": confidence,
            "diagnosis": f"Experimental dark-web intelligence classified as {risk_level}.",
            "explanation": explanations,
            "evidence": {
                "keywords": keywords,
                "matched_terms": sorted(set(matched_terms)),
                "categories": categories,
                "llm_category": llm_category,
                "llm_confidence": llm_confidence,
                "related_cve_count": len(related_cves),
                "related_urlhaus_count": len(related_urlhaus),
                "sample_related_cves": self._sample_cve_hits(related_cves),
                "sample_related_urlhaus": self._sample_urlhaus_hits(related_urlhaus),
            },
        }

    def _score_urlhaus_category(self, threat: str, tags: List[str]) -> Tuple[float, List[str]]:
        score = 0.0
        notes: List[str] = []

        all_text = f"{threat} {' '.join(tags)}"

        if "cobaltstrike" in all_text:
            score += 2.6
            notes.append("Cobalt Strike-related indicator significantly increased priority.")
        elif "ransomware" in all_text:
            score += 2.4
            notes.append("Ransomware-related signal significantly increased priority.")
        elif "botnet" in all_text:
            score += 1.7
            notes.append("Botnet-related signal increased priority.")
        elif "stealer" in all_text:
            score += 1.5
            notes.append("Stealer-related signal increased priority.")
        elif "phishing" in all_text:
            score += 1.0
            notes.append("Phishing-related signal increased priority.")
        elif "malware" in all_text:
            score += 1.1
            notes.append("Generic malware signal increased priority.")

        if "loader" in all_text or "dropper" in all_text:
            score += 0.45
            notes.append("Loader/dropper behavior strengthened malicious confidence.")

        return score, notes

    def _score_urlhaus_status(self, status: str) -> Tuple[float, List[str]]:
        score = 0.0
        notes: List[str] = []

        if status == "online":
            score += 1.1
            notes.append("Indicator is still online, increasing urgency.")
        elif status == "offline":
            score -= 0.15
            notes.append("Indicator is offline, lowering operational urgency.")
        elif status == "unknown":
            score += 0.2
            notes.append("Indicator status is unknown, keeping moderate caution.")

        return score, notes

    def _score_url_structure(self, url: str) -> Tuple[float, List[str]]:
        score = 0.0
        notes: List[str] = []

        lowered = (url or "").lower()
        if not lowered:
            return score, notes

        if lowered.count("/") >= 4:
            score += 0.20
            notes.append("Deeper URL path increased suspicion slightly.")

        suspicious_extensions = (
            ".exe", ".dll", ".zip", ".rar", ".7z", ".js", ".vbs",
            ".ps1", ".bat", ".cmd", ".scr", ".jar", ".msi", ".apk"
        )
        if any(ext in lowered for ext in suspicious_extensions):
            score += 1.1
            notes.append("Suspicious payload or script extension increased priority.")

        suspicious_keywords = (
            "login", "update", "invoice", "payment", "verify",
            "download", "secure", "office", "doc", "xls", "pdf"
        )
        keyword_hits = sum(1 for kw in suspicious_keywords if kw in lowered)
        if keyword_hits >= 2:
            score += 0.45
            notes.append("Multiple lure-related URL keywords increased suspicion.")
        elif keyword_hits == 1:
            score += 0.15

        return score, notes

    def _get_primary_description(self, data: Dict[str, Any]) -> str:
        descriptions = data.get("descriptions", [])
        if not descriptions:
            return ""

        for item in descriptions:
            if item.get("lang", "").lower() == "en":
                return item.get("value", "")
        return descriptions[0].get("value", "")

    def _extract_cvss_score(self, metrics: Dict[str, Any]) -> Tuple[float, str]:
        metric_order = [
            ("cvss_metric_v40", "CVSS v4.0"),
            ("cvss_metric_v31", "CVSS v3.1"),
            ("cvss_metric_v30", "CVSS v3.0"),
            ("cvss_metric_v2", "CVSS v2.0"),
        ]

        for metric_key, metric_label in metric_order:
            metric_values = metrics.get(metric_key) or []
            if metric_values:
                cvss_data = metric_values[0].get("cvss_data", {})
                score = float(cvss_data.get("base_score", 0.0) or 0.0)
                return score, metric_label

        return 0.0, "Unknown"

    def _extract_keywords(self, text: str, extra: str = "") -> List[str]:
        combined = f"{text} {extra}".lower()
        cve_ids = re.findall(r"cve-\d{4}-\d{4,7}", combined, flags=re.IGNORECASE)

        tokens = re.findall(r"[a-zA-Z0-9\-_\.]{4,}", combined)
        cleaned: List[str] = []
        for token in tokens:
            token = token.strip("._- ").lower()
            if not token:
                continue
            if token in self.STOPWORDS:
                continue
            if token.isdigit():
                continue
            cleaned.append(token)

        boosted: List[str] = []
        for token in cleaned:
            if token in self.HIGH_SIGNAL_TERMS:
                boosted.append(token)
            elif any(ch.isdigit() for ch in token):
                boosted.append(token)
            elif token[0].isalpha():
                boosted.append(token)

        seen = set()
        result: List[str] = []
        for item in cve_ids + boosted:
            if item not in seen:
                seen.add(item)
                result.append(item)

        return result[:12]

    def _calculate_age_days(self, published_value: Optional[str]) -> Optional[int]:
        if not published_value:
            return None
        try:
            normalized = published_value.replace("Z", "+00:00")
            published_dt = datetime.fromisoformat(normalized)
            if published_dt.tzinfo is None:
                published_dt = published_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            return max((now - published_dt).days, 0)
        except Exception:
            return None

    def _calculate_recentness_bonus(self, age_days: Optional[int]) -> float:
        if age_days is None:
            return 0.0
        if age_days <= 3:
            return 1.2
        if age_days <= 14:
            return 0.8
        if age_days <= 30:
            return 0.4
        return 0.0

    def _calculate_age_penalty(self, age_days: Optional[int]) -> float:
        if age_days is None:
            return 0.0
        if age_days > 3650:
            return 3.0
        if age_days > 1825:
            return 2.5
        if age_days > 365:
            return 1.8
        if age_days > 90:
            return 0.8
        return 0.0

    def _score_urlhaus_matches(
        self,
        matches: List[Dict[str, Any]],
    ) -> Tuple[float, List[str]]:
        if not matches:
            return 0.0, []

        score = 0.0
        explanations = [f"Cross-source URLhaus correlation found ({len(matches)} match)."]

        for match in matches[:5]:
            threat = str(match.get("threat", "")).lower()
            tags = [str(tag).lower() for tag in (match.get("tags") or [])]
            status = str(match.get("url_status", "")).lower()
            combined = f"{threat} {' '.join(tags)}"

            if "cobaltstrike" in combined:
                score += 0.9
            elif "ransomware" in combined:
                score += 0.8
            elif "botnet" in combined:
                score += 0.6
            elif "malware" in combined:
                score += 0.45

            if "loader" in combined or "dropper" in combined:
                score += 0.20

            if status == "online":
                score += 0.15

        return min(score, 2.4), explanations

    def _score_dread_matches(
        self,
        matches: List[Dict[str, Any]],
    ) -> Tuple[float, List[str], List[str]]:
        if not matches:
            return 0.0, [], []

        score = 0.0
        explanations = [f"Experimental dark-web overlap found ({len(matches)} match)."]
        categories: List[str] = []

        for match in matches[:5]:
            combined = f"{match.get('title', '')} {match.get('content', '')}".lower()
            for category, terms in self.DREAD_CLASSIFIERS.items():
                if any(term in combined for term in terms):
                    categories.append(category)

            if any(term in combined for term in ["exploit", "0day", "zero-day", "zeroday", "rce"]):
                score += 0.45
            elif any(term in combined for term in ["leak", "database", "breach", "access"]):
                score += 0.30
            else:
                score += 0.15

        return min(score, 1.5), explanations, sorted(set(categories))

    def _score_llm_cve_info(self, llm_info: Dict[str, Any]) -> Tuple[float, List[str]]:
        if not llm_info:
            return 0.0, []

        score = 0.0
        explanations: List[str] = []

        vuln_type = str(llm_info.get("vuln_type") or "").lower()
        products = llm_info.get("products") or []
        impact = str(llm_info.get("impact") or "").lower()

        if vuln_type in {"rce", "remote code execution"}:
            score += 1.0
            explanations.append("LLM identified the vulnerability type as remote code execution.")
        elif vuln_type in {"privilege escalation", "lpe"}:
            score += 0.6
            explanations.append("LLM identified a privilege escalation pattern.")
        elif vuln_type in {"sqli", "sql injection", "xss"}:
            score += 0.4
            explanations.append("LLM identified a commonly exploitable web vulnerability type.")

        if products:
            explanations.append("LLM extracted affected product context from the CVE description.")

        if any(term in impact for term in ["execute", "compromise", "bypass", "takeover"]):
            score += 0.4
            explanations.append("LLM-derived impact suggests stronger attacker effect.")

        return min(score, 1.5), explanations

    def _count_non_empty_llm_fields(self, llm_info: Dict[str, Any]) -> int:
        count = 0
        for key in ("products", "versions", "vuln_type", "impact"):
            value = llm_info.get(key)
            if value:
                count += 1
        return count

    def _calculate_confidence(
        self,
        has_cvss: bool,
        urlhaus_match_count: int,
        dread_match_count: int,
        keyword_count: int,
        llm_fields_count: int = 0,
    ) -> float:
        confidence = 0.40
        if has_cvss:
            confidence += 0.20
        confidence += min(urlhaus_match_count * 0.04, 0.20)
        confidence += min(dread_match_count * 0.02, 0.10)
        confidence += min(keyword_count * 0.01, 0.10)
        confidence += min(llm_fields_count * 0.03, 0.12)
        return round(min(confidence, 0.95), 2)

    def _level_from_score(self, score: float) -> str:
        if score >= 8.5:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.5:
            return "MEDIUM"
        return "LOW"

    def _sample_urlhaus_hits(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        sampled = []
        for item in matches[:3]:
            sampled.append(
                {
                    "url": item.get("url"),
                    "threat": item.get("threat"),
                    "tags": item.get("tags", []),
                    "url_status": item.get("url_status"),
                }
            )
        return sampled

    def _sample_dread_hits(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        sampled = []
        for item in matches[:3]:
            sampled.append(
                {
                    "title": item.get("title"),
                    "category": item.get("category"),
                    "author": item.get("author"),
                    "url": item.get("url"),
                }
            )
        return sampled

    def _sample_cve_hits(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        sampled = []
        for item in matches[:3]:
            sampled.append(
                {
                    "cve_id": item.get("_id"),
                    "published": item.get("published"),
                }
            )
        return sampled