"""Verificación local de la preclave recibida de un directorio no confiable."""
from securechat.infrastructure import crypto
from securechat.infrastructure.hybrid_handshake import verify_hybrid_prekey


class HybridPrekeyVerifier:
    def verify_hybrid(self, record, pinned_bundle):
        verify_hybrid_prekey(crypto, record, pinned_bundle)
