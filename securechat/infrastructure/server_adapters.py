"""Compatibilidad con la ubicación anterior."""
import sys
from servidor.infrastructure import server_adapters as _implementation
sys.modules[__name__] = _implementation
