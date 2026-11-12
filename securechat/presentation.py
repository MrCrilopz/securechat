"""Muestra el antes y el después de un ataque y escapa todo el texto visible."""
import html

_LABELS = {
    'prekey': 'Preclave pública (Base64)',
    'tamper': 'Texto cifrado y etiqueta GCM (Base64)',
    'replay': 'Contador del mensaje',
}

def describe_attack(scenario, result):
    outcome = 'RECHAZADO' if result['rejected'] else 'NO RECHAZADO — revisar el protocolo'
    return outcome + '\n' + _LABELS[scenario] + '\nAntes: ' + result['before'] + '\nDespués: ' + result['after'] + '\nQué ocurrió: ' + result['explanation']

def render_result(result):
    lines = str(result).split('\n')
    before = next((line[7:] for line in lines if line.startswith('Antes: ')), None)
    after = next((line[9:] for line in lines if line.startswith('Después: ')), None)
    if before is None or after is None or len(before) != len(after):
        return html.escape(str(result), quote=True)
    changed = [a != b for a, b in zip(before, after)]
    def highlighted(value):
        chunks = []
        index = 0
        while index < len(value):
            end = index + 1
            while end < len(value) and changed[end] == changed[index]:
                end += 1
            text = html.escape(value[index:end], quote=True)
            chunks.append('<mark class="diff">' + text + '</mark>' if changed[index] else text)
            index = end
        return ''.join(chunks)
    return '\n'.join('Antes: ' + highlighted(before) if line.startswith('Antes: ') else
                     'Después: ' + highlighted(after) if line.startswith('Después: ') else
                     html.escape(line, quote=True) for line in lines)

