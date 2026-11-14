# Acuerdo híbrido experimental

**Enviar con acuerdo híbrido** combina X25519 y ML-KEM-768 en una conversación nueva. No implementa PQXDH de Signal, no sustituye una conversación ya abierta y no debe usarse para información sensible. No se debe afirmar que protege íntegramente frente a un atacante cuántico activo. La autenticación de identidad sigue siendo Ed25519.

## Uso en el chat

El botón aparece solo antes de abrir una sesión clásica o de Double Ratchet. La semilla ML-KEM se guarda en el estado local cifrado y se publica la preclave firmada después de ese guardado. Si el contacto no tiene preclave, no se envía un mensaje clásico en su lugar. La repetición del mismo inicio se confirma una vez. Los mensajes siguientes usan las claves derivadas. `HybridAcceptance` y `HybridPrekeyStore` siguen siendo almacenes de laboratorio, separados de este camino. Un servidor malicioso puede repetir una preclave válida anterior: no hay protección de rollback del directorio, ni rotación, caducidad o preclaves de un solo uso.

## Dependencia y capacidades

Se requiere `cryptography` 47.0.0 o posterior dentro del rango de `requirements.txt`; la disponibilidad de la clase no garantiza que el backend la soporte. Si el mecanismo falta o el backend lo rechaza, se informa `HybridUnavailable`. No se utiliza una alternativa clásica silenciosa.

## Esquema aislado

1. El receptor genera una preclave pública ML-KEM-768 y la firma con Ed25519 junto con la suite y su paquete público clásico. El llamador conserva la clave privada separadamente.
2. El emisor debe recibir, por un canal de confianza independiente, la identidad fijada del receptor. Verifica esa identidad y las firmas antes de encapsular el secreto ML-KEM y realizar el acuerdo clásico X25519 existente.
3. HKDF-SHA256 combina las dos claves direccionales del acuerdo clásico y el secreto KEM. Su contexto incluye un identificador específico de este protocolo y el hash de la transcripción canónica: suite, identidades públicas, preclave firmada, cabecera clásica, encapsulado y nonce.
4. Se derivan una clave AES-GCM para el mensaje inicial y dos claves direccionales separadas. El receptor verifica la identidad fijada del emisor y autentica el mensaje inicial antes de devolver estado o texto.

La identidad fijada que recibe cada función debe provenir de una verificación independiente; copiarla del mismo directorio no confiable no autentica al contacto. El estado del emisor es provisional hasta contar con confirmación del destinatario; esta API no implementa esa confirmación.

## Límites

La protección de identidad sigue usando Ed25519 y no es autenticación poscuántica. No se implementan rotación o preclaves KEM de un solo uso, confirmación mutua de claves, recuperación posterior a compromiso, borrado garantizado de secretos, negociación con clientes antiguos ni migración de cuentas. El llamador debe tratar como fallo cualquier suite o campo ausente: no hay retorno a X25519 por sí solo. La función criptográfica `accept_hybrid` por sí sola **no evita repeticiones**. Existe una ruta experimental separada `HybridAcceptance` con `HybridStateStore`: tras autenticar el mensaje, registra de forma atómica la huella de la transcripción y el estado inicial cifrado en SQLite; la misma transcripción no puede aceptarse dos veces en ese almacén. Si el guardado tiene resultado incierto, se puede consultar el estado cifrado antes de reintentar: la recuperación vuelve a autenticar el paquete completo y comprueba que su resultado coincide con el estado guardado. Esta ruta todavía no está conectada al chat ni integra las actualizaciones posteriores de la sesión.

El llamador debe proteger y recuperar de forma segura la clave del almacén y garantizar que todos los procesos utilicen el mismo archivo; borrar, alterar o restaurar una copia anterior de la base puede permitir repetir aceptaciones. SQLite reduce riesgos de fallo, pero no garantiza durabilidad absoluta ante apagones o almacenamiento defectuoso. La recuperación y las garantías ante fallos reales requieren revisión independiente y pruebas adicionales antes de la integración.

Las pruebas pueden ejecutarse con `.venv/bin/python -m unittest tests.test_hybrid_handshake -v`. Los casos de manipulación verifican el fallo de autenticación del primer mensaje, no suponen que ML-KEM rechace directamente todos los encapsulados alterados: el mecanismo puede producir otro secreto implícitamente.

Referencias: [documentación de ML-KEM de cryptography 50.0.2](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/mlkem/) y [especificación PQXDH de Signal](https://signal.org/docs/specifications/pqxdh/), utilizada como referencia conceptual, no como afirmación de compatibilidad.

Pruebas de persistencia aisladas: `.venv/bin/python -m unittest tests.test_hybrid_replay_storage -v`. Se cubren repetición tras reinicio, concurrencia y fallos simulados antes y después de confirmar, sin simular un corte eléctrico real.

## Preclave local experimental

`HybridPrekeyStore` ofrece almacenamiento separado del chat para una preclave por identidad. Guarda la semilla privada cifrada con AES-GCM y vuelve a comprobar la firma y correspondencia con la clave pública al recuperarla. La creación o lectura ocurre bajo una transacción SQLite con bloqueo de escritura; dos procesos que usan la misma base y la misma clave para una identidad recuperan el mismo registro. Las distintas identidades pueden usar claves de almacén diferentes en la misma base; cada identidad debe conservar de forma segura su clave estable, y abrir su registro con otra clave falla la autenticación. El registro es inmutable: todavía no hay rotación ni eliminación. Los ensayos con errores antes y después de confirmar permiten reconsultar el resultado; no son una prueba de corte eléctrico real.

El llamador debe proporcionar y proteger una clave de 32 bytes estable para el almacén; aún no existe derivación ni gestión de esa clave integrada en la aplicación. El almacén no comparte transacción con el estado del chat ni publica preclaves. No evita restauración, eliminación o reemplazo de la base, ni coordina instancias que utilicen bases diferentes. No debe conectarse ni publicarse como solución completa antes de resolver esas restricciones y obtener una revisión independiente.

Pruebas: `.venv/bin/python -m unittest tests.test_hybrid_prekeys_state -v`.

## Directorio de preclaves experimental

El servidor expone publicación y consulta a usuarios autenticados. Solo acepta una preclave con suite reconocida y firma vinculada al paquete público completo de la cuenta autenticada. Antes de guardar, `cryptography` debe reconocer como válida la codificación de la clave ML-KEM; una clave inválida no ocupa el registro inmutable. Si el mecanismo o su backend no están disponibles, la publicación falla y la interfaz HTTP responde 503. Repetir la misma publicación es idempotente y sustituirla por otra se rechaza. La migración crea una tabla adicional sin borrar cuentas ni mensajes. No se envía al servidor la semilla privada.

La verificación del servidor no sustituye la del cliente. El botón del chat publica y consulta la preclave por el gateway y usa el contacto ya verificado; `HybridDirectory` sigue siendo un ayudante de laboratorio y no negocia protocolos. Una preclave válida anterior puede ser reproducida por un servidor malicioso; no se ha resuelto el rollback del directorio, ni rotación, caducidad, uso único o cambio de preclave. No anunciar protección contra downgrade por disponer del directorio.

Pruebas: `.venv/bin/python -m unittest tests.test_hybrid_prekey_directory -v`.
