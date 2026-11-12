"""Crea dos identidades desechables para que la demostración no use cuentas registradas."""

def ephemeral_pair(crypto):
    sender = crypto.Identity.generate('sender')
    recipient = crypto.Identity.generate('recipient')
    return sender, recipient
