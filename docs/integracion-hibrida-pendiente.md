# Integración híbrida al chat: lo que queda abierto

**Enviar con acuerdo híbrido** abre una conversación nueva con X25519 y ML-KEM-768. No convierte una conversación clásica ya abierta y no es PQXDH. Lo que sigue sin resolverse es el rollback del directorio, la rotación, la caducidad y el uso único de la preclave. Ed25519 no es autenticación poscuántica.

## Estado actual comprobable

- `Client.send_hybrid` solo actúa si todavía no hay sesión clásica ni de Double Ratchet. El primer paquete usa el protocolo `hybrid-v1`. Los mensajes siguientes usan las claves derivadas y el encabezado clásico de ese acuerdo. Una sesión ya abierta no se reetiqueta.
- La semilla privada queda en el estado local cifrado del cliente. La preclave pública firmada se publica después de guardar esa semilla. El directorio sigue admitiendo una sola preclave inmutable por cuenta. Un servidor malicioso puede repetir un registro válido anterior.
- `HybridPrekeyStore` y `HybridAcceptance` continúan aparte del estado del chat. El camino del chat no los usa como segunda transacción.
- El almacén experimental de preclaves usa un registro inmutable por identidad y crea o relee la clave bajo `BEGIN IMMEDIATE`, evitando sobrescrituras entre instancias que utilicen esa misma base. Este mecanismo no coordina por sí solo las escrituras del archivo del chat ni impide restaurar o eliminar la base.
- `HybridAcceptance` registra una aceptación y su estado inicial en una base local cifrada independiente. El cliente real guarda sesiones, historial y confirmaciones en otro archivo cifrado mediante `local_store.save`. Estas dos operaciones no son una sola transacción: conectarlas sin un protocolo de recuperación podría registrar una aceptación sin instalar la sesión o instalar un resultado no recuperable tras un fallo. Las versiones actualizadas del cliente clásico usan bloqueo por archivo y comparación de una revisión autenticada al escribir; una copia obsoleta falla y debe recargarse. Esta protección no coordina binarios antiguos, archivos restaurados ni las dos bases distintas del laboratorio híbrido.
- `HybridAcceptance` deduplica el transcript en su propio almacén y valida la recuperación del paquete; no protege frente a restauración o borrado de ese almacén y no persiste de forma coordinada los avances posteriores del chat.

## Lo que sigue abierto

1. El directorio admite una sola preclave firmada e inmutable por cuenta. No hay caducidad, rotación, agotamiento ni uso único. Un servidor malicioso puede ocultar o repetir un registro válido anterior.
2. No hay claves anteriores guardadas para mensajes que lleguen después de un cambio de preclave, porque ese cambio no existe.
3. Restaurar a la vez el archivo del cliente y la base del servidor puede repetir un contador de los mensajes posteriores. No hay revisión criptográfica independiente ni prueba de corte eléctrico real.
4. Ed25519 no es autenticación poscuántica y este camino no es PQXDH.

## Decisión de las conversaciones ya abiertas

Una conversación clásica o de Double Ratchet se queda en ese protocolo. El acuerdo híbrido solo empieza una conversación que todavía no tiene sesión. No hay cambio silencioso ni se reinician los contadores de una sesión existente.

Referencia: [documentación oficial de ML-KEM de cryptography](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/mlkem/).
