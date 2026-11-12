"""Compatibilidad con la ubicación anterior."""
import sys
from cliente.infrastructure import http_gateway as _implementation
sys.modules[__name__] = _implementation
