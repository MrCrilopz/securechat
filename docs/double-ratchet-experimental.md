# Double Ratchet experimental

La conversación puede iniciar este protocolo con **Enviar con Double Ratchet**. No es Signal, no debe usarse con información sensible y sus pruebas no sustituyen una revisión criptográfica independiente.

## Alcance

La implementación explora cadenas simétricas y cambios X25519 de claves por turno. Deriva claves con HKDF y HMAC-SHA256 mediante `cryptography`; cifra y autentica con AES-GCM, incluidos los datos de identidad suministrados por el llamador y la cabecera completa. Acepta mensajes fuera de orden dentro de límites: como máximo 32 saltos por cadena procesada y 128 claves omitidas conservadas en total. Una recepción con cambio DH puede procesar hasta 32 saltos de la cadena anterior y 32 de la nueva. Una autenticación fallida descarta la transición propuesta sin modificar el estado original.

El módulo de aplicación depende de un contrato de primitivas; el adaptador concreto está en infraestructura. `tests/test_double_ratchet.py` ejercita mensajes intercambiados, reordenamiento entre cadenas, límites, alteraciones y repetición.

## Restricciones

- El llamador debe establecer y autenticar el secreto inicial, la clave pública inicial y las identidades por un protocolo separado. El laboratorio no implementa por sí solo ese establecimiento.
- El estado contiene claves privadas y claves de mensajes omitidos. La API experimental no implementa serialización, cifrado de estado, transacciones durables ni protección contra restauraciones antiguas. Una copia anterior permite volver a procesar mensajes aceptados después de la copia.
- El emisor debe conservar de manera atómica el estado actualizado antes de transmitir. El nonce de cada mensaje posterior al inicio es el contador de esa cadena, de 96 bits. En el chat, el servidor reserva la tupla de sesión, clave pública Diffie-Hellman y contador antes de cifrar. Restaurar solo el cliente no cifra otro mensaje con esa tupla. Restaurar también la base del servidor todavía puede repetirla. Una reserva confirmada y no guardada bloquea ese envío. El primer paquete de inicio crea una sesión aleatoria nueva si todavía no estaba guardado.
- El borrado de secretos en memoria no está garantizado por Python. No hay expiración automática de claves omitidas ni recuperación cuando se alcanza el límite total; se rechaza la transición correspondiente.
- No se ha validado interoperabilidad con Signal. La interfaz puede iniciar una conversación nueva. Si ya hay una sesión clásica, el cambio es explícito por cada persona y los mensajes clásicos se conservan. Un adjunto posterior viaja dentro del mensaje DR. No se presenta como el protocolo Signal.
- Después de un paso Diffie-Hellman, la cadena de envío anterior no descifra los mensajes nuevos. Una clave de identidad robada no se recupera con ese paso: se detecta al comparar la huella.

Referencia de diseño: [The Double Ratchet Algorithm, Signal](https://signal.org/docs/specifications/doubleratchet/), secciones 3 y 8.

## Codificación de estado experimental

`securechat/application/ratchet_state_codec.py` transforma el estado, incluidas las claves de mensajes omitidos, en una representación JSON versionada y valida su estructura, longitudes, contadores, duplicados y límite de claves. La representación contiene claves secretas y **no se debe guardar ni transmitir en claro**. Las pruebas demuestran su uso con el almacén local cifrado existente y la recuperación de un mensaje fuera de orden. Esta demostración no integra Double Ratchet al chat, no coordina estado, historial y confirmaciones, y no evita restauraciones de archivos anteriores. Antes de su uso real siguen siendo necesarios el acuerdo inicial autenticado, el versionado y migración de sesiones, la persistencia transaccional, las pruebas de fallo y una revisión independiente.

## Inicialización autenticada experimental

`securechat/infrastructure/ratchet_bootstrap.py` es un prototipo aislado: usa tres acuerdos X25519, identifica explícitamente la suite, ambas identidades verificadas, los roles, el identificador aleatorio de sesión y la preclave firmada; vincula la transcripción a la firma, la derivación de raíz y la autenticación del primer mensaje. La inicialización requiere un paquete completo de identidad confiable por cada contacto, verificado previamente por un canal independiente. La prueba comprueba un mensaje inicial y una respuesta, y rechaza cambios en los campos autenticados.

Este diseño propio **no es X3DH ni un protocolo Signal interoperable**, no ha sido auditado y no debe usarse en producción. El receptor acepta una repetición idéntica si el llamador no mantiene y verifica un registro duradero de sesiones; no hay persistencia coordinada con historial, outbox ni ACK, migración, protección de rollback o recuperación tras fallo. El identificador no debe considerarse una defensa antirrepetición por sí solo. El prototipo no está conectado al chat y no acredita la extensión completa. Las comprobaciones criptográficas usan `cryptography`; la política para los mensajes posteriores y sus datos asociados debe estar autenticada por la futura integración.

## Aceptación inicial con registro experimental

`DurableBootstrap` autentica el primer paquete antes de guardar una marca única de transcripción, el estado serializado y el texto en el almacén cifrado experimental, en una sola transacción. Rechaza repeticiones contra la misma base y permite recuperar el resultado exacto tras un fallo de respuesta; para ello vuelve a autenticar el paquete completo y compara su huella con la registrada. La recuperación conserva el estado original: una nueva autenticación crea material de ratchet aleatorio diferente y no debe sustituirlo.

Este adaptador sigue aislado. Requiere que el llamador proporcione una clave de almacén estable y protegida; no coordina la aceptación con el historial, el ACK ni el estado de conversación real. Borrar o restaurar una base anterior permite aceptar de nuevo el paquete. No ofrece protección frente a rollback, una auditoría criptográfica ni una integración completa.

## Transiciones transaccionales experimentales

`TransactionalRatchet` explora guardar el agregado completo (ratchet, cola de salida, mensajes aceptados e historial) antes de enviar o confirmar. Un error de persistencia invalida la instancia y obliga a recargar; duplicados exactos conocidos no se entregan de nuevo. El almacenamiento, cifrado, exclusión entre procesos y adaptación al transporte del chat son responsabilidad del llamador y no forman parte de este experimento. El registro se limita a 256 sobres y falla cerrado al llenarse; no implementa compactación ni garantías frente a restauración. El agregado contiene claves y mensajes en claro en memoria y debe cifrarse y autenticarse al persistir. No está integrado a la UI ni constituye mensajería lista para usar.

## Codec del agregado experimental

`ratchet_session_codec` convierte el agregado transaccional a JSON versionado y limita tamaño de campos y colecciones; contiene claves y mensajes y requiere almacenamiento cifrado autenticado. Las pruebas guardan un agregado en el almacén local cifrado, reinician y continúan el intercambio; también simulan un fallo de transporte y reenvían el sobre persistido. Esto no conecta Double Ratchet a las conversaciones existentes ni resuelve migración, rechazo durable de replay entre sesiones o transición cuando se llena el registro de 256 sobres. Los límites de codec pueden rechazar un agregado grande y exigen una política futura explícita de transición y retención; no se descartan evidencias automáticamente.

La sesión y el codec comparten límites de identificación (128 caracteres), historial (1024 mensajes) y texto (65536 bytes). Cuando se alcanza un límite, la operación nueva se rechaza antes de persistir, transmitir o confirmar; un duplicado exacto ya aceptado se puede confirmar incluso con historial lleno. La transición de sesión y la paginación segura siguen sin implementarse; no se eliminan pruebas de repetición para liberar espacio.

### Transporte versionado experimental

`securechat/application/ratchet_transport.py` define un sobre JSON v1 que
el relay actual puede almacenar. El contexto usado como AAD vincula protocolo,
versión, identidades y un identificador de sesión previamente autenticado.
La recepción exige identidades, versión e identificador esperados y valida la
forma del paquete; AES-GCM autentica el contenido. Una prueba HTTP con base
temporal comprueba envío, recepción y confirmación sin texto claro en la base.

Este formato no se anuncia ni se usa en el chat real. El llamador debe limitar
el tamaño de entrada antes de analizar JSON y obtener identidades y sesión de un
acuerdo autenticado. Faltan integración de inicialización y recepción, estado
persistente coordinado, transición segura cuando se agota la evidencia de replay,
compatibilidad y migración de sesiones, y revisión independiente. Un relay
observa identidades, tipo, identificador de sesión, tamaño y tiempos; puede
bloquear o repetir mensajes. No se garantiza resistencia a rollback ni se
implementa el protocolo Signal.
El bootstrap experimental codifica `session` en base64 URL; para usar este
transporte se deben convertir los 16 bytes autenticados a hexadecimal minúsculo.
El primer paquete del bootstrap conserva su propio contexto de autenticación;
este contexto del transporte solo corresponde a mensajes posteriores.

### Candidato de integración por API

`Client.send_dr` permite seleccionar DR explícitamente al inyectar el adaptador
`DoubleRatchetChat`. El estado DR, la evidencia contra repetición, el historial
y la cola se guardan juntos en el estado local del cliente antes de envío o ACK;
la operación normal de persistencia exige recargar si falla. Para mensajes
posteriores, el AAD incorpora también el emisor, además del contexto de los dos
participantes y la sesión. Sin una sesión clásica, `Client.send` usa DR en
cuanto esa sesión existe. Si la conversación ya era clásica, los envíos nuevos
usan DR solo después de que esa persona pulsa el cambio; hasta entonces sigue
enviando y recibiendo por la sesión clásica.

La interfaz muestra **Enviar con Double Ratchet** antes de abrir una sesión y
**Pasar a Double Ratchet** cuando ya hay una sesión clásica. La consola puede
recibir esos mensajes. Un adjunto de una conversación que ya usa DR viaja dentro
del mensaje DR, con su propia clave de archivo. El servidor puede ver protocolo,
participantes, identificador de sesión, tamaño y tiempos.

Dos inicios autenticados del mismo contacto se conservan. Los envíos siguientes
usan la sesión de identificador menor. Un tercer inicio autenticado no se
confirma y no impide entregar los mensajes de las sesiones ya conocidas.

Cada sesión guarda como máximo 256 sobres aceptados. Un duplicado exacto se
confirma aunque el registro esté lleno. Un mensaje nuevo se autentica, no se
guarda ni se confirma, y no impide entregar el resto de la cola. No se borra
evidencia para hacer espacio. Los mensajes posteriores al inicio reservan en el
servidor la sesión, la clave pública y el contador antes de cifrar; restaurar
solo el cliente no emite otro texto con esa misma clave. Restaurar a la vez el
cliente y la base del servidor sigue pudiendo repetir el contador. Copiar la
cadena de envío no permite leer un mensaje cifrado después del siguiente paso
Diffie-Hellman. Una clave de identidad comprometida sigue detectándose por la
huella, no por el ratchet. El acuerdo híbrido y los grupos tienen su propio
botón y no sustituyen esta sesión.
