"""Compatibilidad con la ubicación anterior."""
import sys
from cliente.infrastructure import local_store as _implementation
sys.modules[__name__] = _implementation
