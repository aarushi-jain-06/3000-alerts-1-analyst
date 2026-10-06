"""Small, deterministic retrieval layer for grounded incident briefs.

The default implementation uses lexical overlap and requires no paid API or
model download.  It is intentionally replaceable with FAISS or an embedding
service while preserving the same ``retrieve`` interface.
"""

from mitre_map import ATTACK_DESCRIPTIONS, ATTACK_TECHNIQUES


def _tokens(text):
    return {token.lower() for token in str(text).replace("/", " ").split() if len(token) > 2}


def retrieve(query, k=3):
    query_tokens = _tokens(query)
    docs = []
    for technique_id, description in ATTACK_DESCRIPTIONS.items():
        name, tactic = ATTACK_TECHNIQUES[technique_id]
        doc = f"{technique_id} — {name} ({tactic}): {description}"
        score = len(query_tokens & _tokens(doc))
        docs.append((score, technique_id, doc))
    docs.sort(key=lambda item: (-item[0], item[1]))
    return [doc for score, _, doc in docs[:max(1, k)] if score > 0] or [docs[0][2]]


def context_for_incident(incident, k=3):
    query = " ".join(incident.get("techniques", []) + incident.get("tactics", []))
    return retrieve(query, k=k)
