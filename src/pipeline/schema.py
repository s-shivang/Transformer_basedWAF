from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
import json


@dataclass
class ParsedRequest:
    """
    Standardized request schema for the Transformer-based WAF pipeline.
    Preserves exact raw content alongside structured, canonicalized views
    and security audit flags.
    """
    id: str
    raw_text: str
    method: str
    path: str
    query_params: Dict[str, Union[str, List[str]]] = field(default_factory=dict)
    body_params: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    canonical_payloads: List[str] = field(default_factory=list)
    encoding_flags: Dict[str, bool] = field(default_factory=dict)
    label: Optional[int] = None  # 0: benign, 1: malicious
    source: str = ""             # Dataset name (e.g., 'ai_waf', 'csic2010')
    split: Optional[str] = None  # 'train', 'dev', 'test'

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON/Parquet storage."""
        return {
            "id": self.id,
            "raw_text": self.raw_text,
            "method": self.method,
            "path": self.path,
            "query_params": self.query_params,
            "body_params": self.body_params,
            "headers": self.headers,
            "canonical_payloads": self.canonical_payloads,
            "encoding_flags": self.encoding_flags,
            "label": self.label,
            "source": self.source,
            "split": self.split,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ParsedRequest":
        """Reconstruct a ParsedRequest instance from a dictionary."""
        return cls(
            id=data.get("id", ""),
            raw_text=data.get("raw_text", ""),
            method=data.get("method", "GET"),
            path=data.get("path", "/"),
            query_params=data.get("query_params", {}),
            body_params=data.get("body_params", {}),
            headers=data.get("headers", {}),
            canonical_payloads=data.get("canonical_payloads", []),
            encoding_flags=data.get("encoding_flags", {}),
            label=data.get("label"),
            source=data.get("source", ""),
            split=data.get("split"),
        )

