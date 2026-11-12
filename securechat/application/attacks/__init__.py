"""Dirige cada ataque a su módulo y valida el texto de la demostración."""
from securechat.application.attacks.ciphertext_tampering import run as tamper_ciphertext
from securechat.application.attacks.message_replay import run as replay_message
from securechat.application.attacks.prekey_substitution import run as substitute_prekey

_ATTACKS = {
    'prekey': substitute_prekey,
    'tamper': tamper_ciphertext,
    'replay': replay_message,
}

def run_scenario(crypto, scenario, text):
    attack = _ATTACKS.get(scenario)
    if attack is None:
        raise ValueError('Escenario desconocido')
    if not text.strip() or len(text) > 500:
        raise ValueError('El mensaje debe tener entre 1 y 500 caracteres')
    return attack(crypto, text)
