"""Compatibilidad con el punto de entrada anterior."""
from cliente.client import *

if __name__ == "__main__":
    import sys
    try:
        main()
    except Exception as exc:
        print(explain_failure(exc), file=sys.stderr)
        sys.exit(1)
