"""Compatibilidad con la ubicación anterior."""
import sys
from cliente.application import client as _implementation
sys.modules[__name__] = _implementation
