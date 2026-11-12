"""Compatibilidad con la ubicación anterior."""
import sys
from servidor.application import service as _implementation
sys.modules[__name__] = _implementation
