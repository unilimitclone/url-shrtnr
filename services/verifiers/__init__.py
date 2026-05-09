"""Domain-ownership verifier strategies."""

from services.verifiers.a_record_verifier import ARecordVerifier
from services.verifiers.cname_verifier import CnameVerifier
from services.verifiers.protocol import DomainVerifier, VerificationResult
from services.verifiers.txt_challenge_verifier import TxtChallengeVerifier

__all__ = [
    "ARecordVerifier",
    "CnameVerifier",
    "DomainVerifier",
    "TxtChallengeVerifier",
    "VerificationResult",
]
