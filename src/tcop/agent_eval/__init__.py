"""Isolated v0.6 agent-based external-validation study layer.

This package deliberately composes the frozen TCOP validators, receipts, and
strategies.  It owns no protocol fields or remote-enforcement operation.
"""

from .plan import AGENT_STUDY_KIND, verify_agent_source
from .runner import AgentStudy

__all__ = ("AGENT_STUDY_KIND", "AgentStudy", "verify_agent_source")
