"""
rag.py - Lightweight local retrieval-augmented generation (RAG) module.

Indexes MITRE ATT&CK technique descriptions and incident response playbooks
using scikit-learn TF-IDF vectorization with cosine similarity.
Runs entirely offline with zero paid APIs or heavy model downloads.
"""

import json
import os
from typing import Any, Dict, List, Optional, Union
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from schemas import Alert, Incident
from mitre_map import ATTACK_DESCRIPTIONS, ATTACK_TECHNIQUES

_KB_PATH = os.path.join(os.path.dirname(__file__), "knowledge_base", "mitre_playbooks.json")


class LocalKnowledgeRetriever:
    """TF-IDF based in-memory retriever for MITRE and SOC playbooks."""

    def __init__(self, kb_path: Optional[str] = None):
        self.kb_path = kb_path or _KB_PATH
        self.documents: List[Dict[str, Any]] = []
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.tfidf_matrix = None
        self._load_corpus()

    def _load_corpus(self):
        docs = []
        if os.path.exists(self.kb_path):
            try:
                with open(self.kb_path, "r", encoding="utf-8") as f:
                    docs = json.load(f)
            except Exception:
                docs = []

        existing_ids = {d.get("source_id") for d in docs}
        for tid, desc in ATTACK_DESCRIPTIONS.items():
            sid = f"MITRE-{tid}"
            if sid not in existing_ids:
                name, tactic = ATTACK_TECHNIQUES.get(tid, ("Unknown", "Unknown"))
                docs.append({
                    "source_id": sid,
                    "title": f"{tid}: {name} ({tactic})",
                    "category": "mitre_technique",
                    "content": desc,
                })

        self.documents = docs
        corpus_texts = [f"{d.get('source_id', '')} {d['title']} {d['content']}" for d in docs]
        if corpus_texts:
            self.vectorizer = TfidfVectorizer(
                stop_words="english",
                token_pattern=r"(?u)\b[\w\.]+\b",
                ngram_range=(1, 2),
            )
            self.tfidf_matrix = self.vectorizer.fit_transform(corpus_texts)

    def search(self, query: str, k: int = 3) -> List[Dict[str, Any]]:
        if not self.documents:
            return []
        if not self.vectorizer or not query.strip():
            top_doc = self.documents[0]
            return [{
                "source_id": top_doc["source_id"],
                "title": top_doc["title"],
                "category": top_doc.get("category", "general"),
                "content": top_doc["content"],
                "score": 0.0,
            }]

        query_vec = self.vectorizer.transform([query])
        similarities = cosine_similarity(query_vec, self.tfidf_matrix).flatten()
        top_indices = similarities.argsort()[::-1][:k]

        results = []
        for idx in top_indices:
            score = float(similarities[idx])
            if score > 0.001:
                doc = self.documents[idx]
                results.append({
                    "source_id": doc["source_id"],
                    "title": doc["title"],
                    "category": doc.get("category", "general"),
                    "content": doc["content"],
                    "score": round(score, 4),
                })

        # If zero matches above threshold, return top document as baseline
        if not results and self.documents:
            top_doc = self.documents[0]
            results.append({
                "source_id": top_doc["source_id"],
                "title": top_doc["title"],
                "category": top_doc.get("category", "general"),
                "content": top_doc["content"],
                "score": 0.0,
            })

        return results[:k]


# Singleton retriever instance
_RETRIEVER = LocalKnowledgeRetriever()


def get_context(incident: Union[Incident, Dict[str, Any]], k: int = 3) -> List[Dict[str, Any]]:
    """
    Retrieve top-k relevant knowledge base snippets for a given incident.
    
    Args:
        incident: Incident object or dict.
        k: Maximum number of snippets to return.
        
    Returns:
        List of dicts: [{source_id, title, category, content, score}]
    """
    query_parts = []

    if isinstance(incident, Incident):
        for alert in incident.alerts:
            query_parts.append(alert.alert_type)
            query_parts.append(alert.description)
    elif isinstance(incident, dict):
        alerts = incident.get("alerts", [])
        for a in alerts:
            if isinstance(a, dict):
                query_parts.append(a.get("alert_type", ""))
                query_parts.append(a.get("description", ""))
            elif isinstance(a, Alert):
                query_parts.append(a.alert_type)
                query_parts.append(a.description)
        # Also include any techniques/tactics if already mapped
        query_parts.extend(incident.get("techniques", []))
        query_parts.extend(incident.get("tactics", []))

    query_str = " ".join([str(p) for p in query_parts if p is not None]).strip()
    return _RETRIEVER.search(query_str, k=k)


def retrieve(query: str, k: int = 3) -> List[str]:
    """
    Backward-compatible helper returning a list of formatted strings.
    """
    results = _RETRIEVER.search(query, k=k)
    return [f"[{r['source_id']}] {r['title']}: {r['content']}" for r in results]


def context_for_incident(incident: Any, k: int = 3) -> List[str]:
    """
    Backward-compatible helper returning list of formatted strings for an incident.
    """
    results = get_context(incident, k=k)
    return [f"[{r['source_id']}] {r['title']}: {r['content']}" for r in results]
