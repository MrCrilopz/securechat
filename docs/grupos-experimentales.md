# Mensajería grupal: laboratorio experimental

La pestaña **Grupos** crea un grupo, reparte la clave de cada emisor dentro de un mensaje clásico de a dos y envía los mensajes del grupo con esa clave. No debe emplearse con información sensible. No es un grupo de Signal.

## Qué prueba el laboratorio

Cada emisor crea una cadena simétrica y una clave de firma independientes para una época. Los mensajes derivan claves sucesivas con HMAC-SHA256, se cifran con AES-256-GCM y se firman con Ed25519. El grupo, la época, el emisor, el identificador de clave y el contador están autenticados. El receptor verifica la firma, limita los saltos y solo acepta el estado nuevo si también se valida el cifrado. Se admiten hasta 32 saltos por mensaje y hasta 128 claves omitidas conservadas.

Las pruebas muestran que dos receptores con la misma distribución descifran de manera independiente, que las alteraciones y repeticiones se rechazan y que una clave de una época anterior no descifra la nueva. Este último resultado **solo se cumple si la nueva distribución permanece desconocida para la persona excluida**.

## Qué hace el chat

- El creador verifica a cada miembro, guarda el grupo en el estado local cifrado y envía la clave de emisor como texto `GRP1` dentro del cifrado de a dos. Ese sobre lleva el protocolo `group-key-v1`. El historial del grupo dice «Clave de grupo actualizada» y no muestra la clave.
- En Grupos, el buscador solo lista contactos con la huella verificada. El grupo aparece en Conversaciones por su nombre. Cada mensaje muestra quién lo envió.
- El mensaje de grupo es un solo sobre en el buzón del grupo. Cada miembro lo recoge y lo confirma; el sobre se borra cuando todos los destinatarios lo han hecho. El cliente lo guarda en el grupo y no en el chat privado. Si la clave todavía no llegó, el mensaje queda sin confirmar.
- Quitar a un miembro sube la época y reparte una clave nueva solo a quienes siguen. Una distribución de una época anterior no restaura la lista de miembros.
- Quien ya recibió un mensaje conserva ese texto. Python no borra secretos de la memoria. Restaurar a la vez el cliente y la base del servidor puede repetir un contador. No hay revisión criptográfica independiente.

Para ejecutar las pruebas desde la raíz:

```sh
.venv/bin/python -m unittest tests.test_group_sender_keys -v
```
