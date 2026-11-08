"""Domain-level errors for safe handling of malformed messages."""


class InvalidMessageNonce(ValueError):
    """A message nonce is malformed and cannot be authenticated."""


class InvalidClassicMessage(ValueError):
    """Untrusted classic message metadata or ciphertext encoding is invalid."""


class UnexpectedOldMessage(ValueError):
    """An old counter lacks exact evidence of an already accepted envelope."""


class LocalStateWriteFailed(OSError):
    """The local encrypted state could not be committed."""


class ClientStateInvalidated(RuntimeError):
    """A failed write left the durable state uncertain; reload is required."""


class UnsupportedMessageFormat(ValueError):
    """A message has an unknown or tampered content format."""


class ConcurrentRatchetSession(ValueError):
    """Authenticated session conflict; preserve all messages and both states."""


class UnknownRatchetSession(ValueError):
    """A DR message references a session whose authenticated start is unavailable."""


class RatchetAuthenticationFailed(ValueError):
    """At least one DR packet failed authentication and remains unacknowledged."""


class RatchetPacketRejected(ValueError):
    """An untrusted DR packet could not be processed; no state was committed."""


class DrReplayEvidenceFull(ValueError):
    """The DR replay record is full; a new message stays unacknowledged."""


class UnknownContact(LookupError):
    """The requested identity does not exist in the authenticated directory."""


class ContactNotVerified(ValueError):
    """A contact's safety number has not been independently confirmed."""


class ContactIdentityChanged(ValueError):
    """A contact's identity differs from the verified identity."""


class InvalidPrekeySignature(ValueError):
    """A contact's signed public-key bundle failed signature verification."""


class InvalidIncomingEnvelope(ValueError):
    """An untrusted inbound envelope is structurally invalid."""


class InvalidClassicHeader(ValueError):
    """An untrusted classic-session header is invalid or unexpected."""


class InvalidClassicCounter(ValueError):
    """A classic message counter is ahead of the expected state."""


class ReusedNonceCounter(ValueError):
    """The server already issued this send counter, so it must not be encrypted again."""
