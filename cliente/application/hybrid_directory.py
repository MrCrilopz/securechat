"""Consulta experimental de preclaves solo para identidades ya verificadas."""
from typing import Protocol


class VerifiedContactPort(Protocol):
    def verified_bundle(self, peer: str) -> dict: ...


class HybridDirectoryPort(Protocol):
    def hybrid_prekey(self, peer: str) -> dict: ...


class HybridVerifierPort(Protocol):
    def verify_hybrid(self, record: dict, pinned_bundle: dict) -> None: ...


class HybridDirectory:
    def __init__(self, contact_client: VerifiedContactPort, gateway: HybridDirectoryPort,
                 verifier: HybridVerifierPort):
        self.contact_client = contact_client
        self.gateway = gateway
        self.verifier = verifier

    def verified_prekey(self, peer):
        bundle = self.contact_client.verified_bundle(peer)
        record = self.gateway.hybrid_prekey(peer)
        self.verifier.verify_hybrid(record, bundle)
        return record
