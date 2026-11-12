"""Compatibilidad con la ubicación anterior."""
import sys
from cliente import workspace as _implementation
sys.modules[__name__] = _implementation
