"""Aceptación experimental híbrida con registro atómico de la transcripción.

No integra el chat. El almacenamiento suministrado debe persistir la marca y el
estado cifrado en una sola transacción durable, y fallar cerrado ante errores.
"""
import copy
from typing import Protocol


class HybridReplayError(ValueError):
    """La transcripción ya fue aceptada por este almacén."""


class HybridPersistenceError(RuntimeError):
    """No se pudo confirmar el resultado durable del almacenamiento."""


class HybridStateStorePort(Protocol):
    def save_once(self, digest: bytes, state: dict, plaintext: bytes) -> None: ...
    def load(self, digest: bytes) -> tuple[dict, bytes] | None: ...


class HybridAcceptance:
    def __init__(self, authenticate, digest_transcript, store: HybridStateStorePort):
        self.authenticate = authenticate
        self.digest_transcript = digest_transcript
        self.store = store

    def accept(self, packet):
        packet = copy.deepcopy(packet)
        state, plaintext = self.authenticate(packet)
        digest = self.digest_transcript(packet)
        self.store.save_once(digest, state, plaintext)
        return state, plaintext

    def recover(self, packet):
        packet = copy.deepcopy(packet)
        expected = self.authenticate(packet)
        stored = self.store.load(self.digest_transcript(packet))
        if stored is not None and stored != expected:
            raise HybridPersistenceError('El estado guardado no coincide con el paquete autenticado')
        return stored
