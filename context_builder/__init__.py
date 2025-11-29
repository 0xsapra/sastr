"""
CVE Context Builder Package
Aggregates vulnerability context from multiple sources for CVE analysis
"""

from .database import ContextDatabase
from .collectors import (
    NucleiCollector,
    GitHubAdvisoriesCollector,
    CVEListCollector,
    ReferenceLinkParser
)
from .context_builder import ContextBuilder

__version__ = "1.0.0"
__all__ = [
    "ContextDatabase",
    "NucleiCollector",
    "GitHubAdvisoriesCollector",
    "CVEListCollector",
    "ReferenceLinkParser",
    "ContextBuilder"
]
