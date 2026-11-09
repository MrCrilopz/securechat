"""Prepara el historial visible sin exponer al navegador las claves de adjuntos."""


def visible_history(history, attachments):
    rows = []
    for index, row in enumerate(history):
        visible = {'peer': row['peer'], 'direction': row['direction']}
        if row.get('author'):
            visible['author'] = row['author']
        if row.get('kind') == 'group-v1':
            visible['kind'] = 'group-v1'
        if row.get('kind') == 'group-key-v1':
            visible['kind'] = 'group-key-v1'
            visible['text'] = 'Clave de grupo actualizada'
        elif row.get('kind') == 'attachment-v1':
            try:
                name, _ = attachments.open(row['text'])
                visible.update(kind='attachment-v1', name=name, index=index)
            except Exception:
                visible['text'] = 'Adjunto no disponible o inválido.'
        else:
            visible['text'] = row['text']
        rows.append(visible)
    return rows


def describe_visible_row(row):
    if row.get('kind') == 'attachment-v1':
        return 'Archivo: ' + row['name']
    return row['text']
