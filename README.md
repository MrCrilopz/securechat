# Mensajería segura extremo a extremo

Prototipo académico local en Python. El servidor mantiene cuentas, claves públicas y mensajes cifrados; las claves privadas y el historial se guardan cifrados en cada cliente. No es Signal y no debe utilizarse para información sensible ni en producción.

## Requisitos e instalación

Se requiere Python 3.10 o superior y `cryptography` con soporte Argon2id. En una terminal situada en esta carpeta:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

La instalación de dependencias requiere conexión a Internet. El servidor escucha solo en `127.0.0.1`; no está diseñado para exposición de red. Las contraseñas deben tener al menos 12 caracteres. El directorio `clients/` es privado y no se debe compartir ni subir al repositorio.

## Demostración

Hacen falta tres terminales. Cada comando se queda ejecutando, así que no se pegan los tres en la misma ventana. Desde la carpeta del proyecto:

Terminal 1, el servidor:

```sh
python -m servidor.server --database server.sqlite3
```

Terminal 2, la aplicación de usuarios:

```sh
python -m cliente.ui
```

Esa aplicación no abre `server.sqlite3`. Habla con el servidor en el puerto 8765 y guarda cada cuenta en `clients/<usuario>.json`.

Abra http://127.0.0.1:8766 en dos ventanas distintas, una normal y otra privada. En cada una pulse **Crear cuenta**. Por ejemplo, cree las cuentas `alice` y `bruno`, cada una con una contraseña diferente elegida por su usuario. Luego **Iniciar sesión** con esa misma contraseña. En **Contactos**, muestre la huella en las dos ventanas, compruebe que coinciden, cópiela y pulse **Verificar**. En **Conversaciones**, una persona envía primero; la otra recibe el mensaje sola, en unos segundos, y después puede responder. **Enviar** sigue siendo la sesión clásica. **Enviar con Double Ratchet** abre una sesión con cambio de claves Diffie-Hellman. Si ya existe una conversación clásica, el botón **Pasar a Double Ratchet** conserva esos mensajes: cada persona sigue enviando por la sesión clásica hasta que ella misma lo pulsa. Si ambas lo inician a la vez, los dos primeros mensajes se entregan y los siguientes usan la sesión de identificador menor. Una tercera sesión autenticada queda en cola, sin impedir los mensajes de las sesiones ya conocidas. Después de ese cambio, **Enviar** y los archivos usan Double Ratchet. Antes de usarlo, **Enviar** y los adjuntos siguen en la sesión clásica. **Enviar con acuerdo híbrido** solo aparece antes de abrir una sesión y combina X25519 con ML-KEM-768; si el contacto no publicó su preclave, no se envía un mensaje clásico en su lugar. En **Grupos**, el nombre, los miembros y el primer mensaje crean el grupo: la clave de emisor viaja cifrada en las conversaciones de a dos.

Terminal 3, el panel del operador:

```sh
python -m servidor.admin --database server.sqlite3
```

Defina una contraseña distinta para el panel cuando se le solicite. Abra http://127.0.0.1:8767 e ingrese esa contraseña. El panel muestra solo textos cifrados pendientes y permite lanzar los tres ataques. Al cerrar esa terminal, el panel se apaga y la próxima vez hay que volver a iniciar el comando.

Los mensajes pueden enviarse con el destinatario desconectado y permanecen cifrados hasta que los recibe. No comparta la carpeta `clients/` ni abra dos sesiones del mismo usuario.

## Carpetas

Hay dos pares con nombres parecidos y hacen cosas distintas.

- `cliente/` es el código de la aplicación de usuarios: la página web, la consola, el envío, la recepción y el cifrado del estado local.
- `servidor/` es el código del servidor y del panel del operador. El servidor guarda cuentas, claves públicas y sobres cifrados en `server.sqlite3`.
- `securechat/` es el código compartido: identidades, firmas, acuerdos, cifrado, ataques y las reglas que usan las dos partes. Los comandos antiguos siguen ahí y abren el mismo programa: `python -m securechat.server`, `python -m securechat.ui`, `python -m securechat.admin` y `python -m securechat.client`.
- `clients/` no es código. La aplicación la crea al registrar una cuenta y guarda ahí `alice.json`, `bruno.json` y las descargas descifradas. Cada archivo va cifrado con la contraseña de esa persona. No se comparte ni se sube.

`tests/` contiene las pruebas. `docs/` explica cada extensión y sus límites. El recorrido de la demostración está en `GUIA_DE_DEMOSTRACION.md`.

Los casos de uso no importan SQLite, HTTP ni bibliotecas criptográficas concretas. El proveedor criptográfico implementa un esquema educativo X3DH simplificado: claves Ed25519 y X25519, tres acuerdos X25519, HKDF-SHA256, ratchet simétrico HMAC-SHA256 y AES-256-GCM. Se deriva una clave diferente por mensaje y dirección. El nonce de cada mensaje nuevo es de 96 bits y está fijado al contador: un byte de dominio seguido del contador. El servidor asigna ese contador una sola vez para la sesión, el emisor y el destinatario, y el cliente cifra solo después de recibir la asignación. Si el contador ya fue usado, no se cifra otro mensaje y aparece una alerta. Restaurar a la vez el cliente y la base del servidor todavía puede repetir el contador. Una asignación confirmada por el servidor y no guardada en el cliente bloquea ese envío, en lugar de reutilizar la clave y el nonce. Los datos asociados contienen sesión, emisor, destinatario y contador.

El servidor almacena contraseñas mediante Argon2id (64 MiB, 3 iteraciones, 4 carriles, sal aleatoria) y tokens aleatorios con caducidad de una hora almacenados como hash. El estado local utiliza scrypt y AES-GCM. La verificación de la firma de la preclave y la comparación externa de huellas son requisitos diferentes: la firma por sí sola no autentica una identidad suministrada por un servidor malicioso.

## Adjuntos en la conversación

Seleccione un contacto verificado, pulse **Adjuntar archivo** y **Enviar archivo**. Se aceptan archivos de hasta 24 KiB. La recepción es automática; **Guardar archivo** crea una copia descifrada en `clients/descargas/<usuario>/`, sin sobrescribir archivos existentes ni seguir enlaces simbólicos. Ambos clientes deben ejecutar la versión actualizada. No hay borrado desde la aplicación.

El servidor observa que se envió un archivo y metadatos de transporte, pero no el nombre, contenido ni clave en claro. El archivo guardado en el equipo está descifrado y debe protegerse. La documentación de límites y pruebas está en `docs/adjuntos-experimentales.md`.

## Ataques reproducibles

```sh
python -m unittest tests.test_protocol.ProtocolTests.test_prekey_substitution_rejected -v
python -m unittest tests.test_protocol.ProtocolTests.test_modified_ciphertext_rejected_and_state_unchanged -v
python -m unittest tests.test_protocol.ProtocolTests.test_replay_rejected -v
```

Las pruebas sustituyen una preclave firmada, alteran un byte del texto cifrado y reenvían un mensaje ya aceptado. Se espera el rechazo en cada caso. Las pruebas no son una auditoría criptográfica independiente.

## Limitaciones importantes

- Diseño simplificado y no interoperable con Signal. **Enviar con Double Ratchet** añade el cambio de clave Diffie-Hellman. Después de ese cambio, una copia anterior de la cadena de envío no lee los mensajes nuevos. **Pasar a Double Ratchet** no borra la conversación clásica ni recupera una clave de identidad comprometida: esa clave se detecta al comparar la huella.
- **Enviar con acuerdo híbrido** no es PQXDH. La identidad sigue autenticada con Ed25519. No hay rotación ni protección si un servidor malicioso repite una preclave híbrida anterior. Una conversación ya abierta no cambia de protocolo en silencio.
- En un grupo, quien sale deja de recibir la clave nueva y no descifra los mensajes posteriores. El texto que ya había recibido sigue en su equipo. La conversación se ve por el nombre del grupo y cada mensaje indica quién lo envió. El texto del grupo viaja en un solo sobre compartido. La clave de cada emisor sigue yendo cifrada de a dos.
- Sin TLS: solo se permite conexión local. No exponer el servicio a Internet ni redes compartidas.
- Restaurar solo el cliente ya no permite cifrar de nuevo con un contador usado: el servidor rechaza la asignación y el mensaje no se cifra. En Double Ratchet, cada mensaje posterior al inicio reserva la sesión, la clave pública y el contador; restaurar solo el cliente tampoco cifra ese envío otra vez. Restaurar también la base del servidor, o perder la asignación antes de guardar el estado local, sigue siendo inseguro o deja la conversación bloqueada. No restaurar estados ni ejecutar el mismo cliente al mismo tiempo en distintos procesos.
- La primera huella debe compararse mediante un canal confiable, y se deben verificar cambios de identidad. El servidor puede ocultar, retrasar o reordenar mensajes; el cliente rechaza mensajes fuera de orden.
- El primer estado local es persistido después del registro remoto: si falla el guardado, la cuenta creada no se puede recuperar mediante esta versión.
- No se garantiza el borrado físico de secretos de memoria en Python, ni protección frente a malware, compromiso del equipo, ataques de canal lateral o denegación de servicio.
- No existe recuperación de cuenta, rotación de claves, gestión de múltiples dispositivos, expiración de mensajes, ni protección frente a pérdida de archivos locales.
- Si ambos usuarios inician una conversación clásica al mismo tiempo, se generan dos sesiones incompatibles y ambos clientes muestran `Unexpected concurrent or replaced session`. Para esa conversación, un usuario debe enviar primero y el otro debe recibir antes de responder. Con **Enviar con Double Ratchet**, disponible antes de abrir una sesión clásica, los dos inicios se conservan y los mensajes siguientes usan la misma sesión. Un tercer inicio no sustituye a los dos anteriores ni detiene el resto de la cola. Al llegar a 256 mensajes aceptados, uno nuevo permanece sin confirmar y no se borra la evidencia anterior. **Pasar a Double Ratchet** deja la conversación clásica disponible para los mensajes ya enviados y para quien todavía no haya pulsado el botón. Los archivos de una conversación que ya usa Double Ratchet van cifrados dentro de ese protocolo. No se debe borrar o restaurar el estado local como solución improvisada, pues ello puede causar reutilización de claves y nonces.

## Interfaz de mensajería y panel del servidor

Los tres comandos de la demostración usan la base `server.sqlite3`. La aplicación de usuarios está en http://127.0.0.1:8766 y el panel en http://127.0.0.1:8767. La presencia puede tardar hasta 35 segundos en cambiar al cerrar una ventana. Para usar dos usuarios al mismo tiempo, utilice navegadores o perfiles separados. Cerrar sesión revoca el token. El cliente conserva la contraseña en memoria durante la sesión para cifrar su estado local.

El servidor, los clientes y el panel son solo locales y no deben exponerse a redes. Para otros puertos, consulte `--help` de cada comando. El recorrido detallado está en `GUIA_DE_DEMOSTRACION.md`.

## Laboratorio visual de ataques

El panel del servidor incluye una prueba por separado para la sustitución de preclave, la alteración de un mensaje cifrado y la repetición de un mensaje. La demostración crea identidades efímeras aisladas, utiliza el proveedor criptográfico real y muestra valores antes y después. No modifica las conversaciones reales.

La implementación criptográfica está dividida en `securechat/infrastructure`: `signatures.py` (Ed25519), `key_agreement.py` (X25519), `key_derivation.py` (HKDF), `ratchet.py` (HMAC), `message_cipher.py` (AES-GCM), `identity.py` (identidades y huellas) y `encoding.py` (serialización). `crypto.py` mantiene la interfaz de compatibilidad. Cada ataque vive en su archivo dentro de `application/attacks`: `prekey_substitution.py`, `ciphertext_tampering.py` y `message_replay.py`. El laboratorio recibe el proveedor por inyección.

### Intercepción de un mensaje real

El panel del operador muestra cada mensaje pendiente con su emisor y su destinatario. **Interceptar este mensaje** altera solo una copia de ese mensaje cuando la otra persona abre la conversación. El original se conserva y se entrega después. La activación caduca a los dos minutos. Mientras el destinatario está en otra conversación, el mensaje sigue pendiente y el número de mensajes sin leer aparece junto al contacto.


### Compatibilidad de mensajes anteriores

Los clientes actualizados pueden descifrar mensajes anteriores sin campo `nonce`, que usaban un nonce de 96 bits igual a cero, y también los que traían un nonce aleatorio. Los mensajes nuevos llevan el nonce del contador. Los clientes antiguos no pueden leerlos: antes de continuar, cierre y reinicie los procesos de cliente con la misma versión actualizada. No se modifican ni migran automáticamente los archivos de identidad, el historial o la base de datos.

### Mensajes repetidos y contadores antiguos

El cliente conserva, dentro de su estado local cifrado, una huella del sobre completo de cada mensaje aceptado. Si se reenvía exactamente el mismo sobre tras una confirmación perdida, se confirma sin volverlo a mostrar. Si llega un mensaje distinto con un contador ya utilizado, se muestra una alerta y el mensaje permanece sin confirmar en la cola; no se borra silenciosamente ni se avanza la sesión. Los estados anteriores a esta funcionalidad no contienen huellas de mensajes ya recibidos, por lo que cualquier sobre antiguo sin evidencia se trata de la misma forma conservadora. La huella almacenada requiere espacio adicional por mensaje; esta medida no detecta ni impide todas las restauraciones del estado y no soluciona la recuperación automática de la conversación.

### Recuperación ante fallos al guardar

El cliente prepara cada cambio en una copia, escribe el estado cifrado antes de exponerlo en memoria y solo confirma la recepción después de guardar. El almacén sincroniza el archivo temporal y el directorio tras su reemplazo. Si el guardado informa un error, no se puede asumir si el reemplazo ocurrió: el cliente invalida su sesión y requiere iniciar sesión de nuevo para cargar lo que exista en disco. En la consola, se debe volver a ejecutar el comando. Un envío ya aceptado por el servidor podría repetirse si se perdió la respuesta; los sobres idénticos ya recibidos se confirman sin volver a mostrarlos.

Estas medidas no son una transacción distribuida ni garantizan durabilidad absoluta ante apagones, comportamiento del sistema de archivos, restauración de copias anteriores o modificación maliciosa. El estado anterior a las huellas de sobres recibidos puede requerir intervención cuando aparece un contador antiguo sin evidencia suficiente.

### Escrituras simultáneas del estado local

Las versiones actualizadas coordinan las escrituras mediante un bloqueo por archivo y una revisión autenticada. Si otro proceso guardó una copia más reciente, no se sobrescribe: la sesión afectada se invalida y se debe iniciar de nuevo para cargar el estado vigente. Los archivos locales antiguos se leen y se actualizan al guardar sin cambiar sus datos de conversación.

**Antes de utilizar esta versión, cierre y reinicie todos los procesos de cliente y de interfaz.** Las versiones anteriores no participan en el bloqueo y no pueden leer el nuevo formato de estado; mantenerlas activas podría causar pérdida de cambios. El control requiere `fcntl.flock` y `O_NOFOLLOW`; si no están disponibles, la escritura falla en lugar de continuar sin protección. No elimina el riesgo de restaurar copias antiguas, borrar o reemplazar archivos manualmente, ni protege frente a procesos que no respeten el bloqueo. Un proceso con un envío pendiente ya guardado puede reenviar ese mismo sobre antes de advertir que su estado está obsoleto; la detección de duplicados exactos evita mostrarlo dos veces en condiciones normales.
