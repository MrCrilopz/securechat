# Adjuntos cifrados

La conversación admite archivos de hasta **24 KiB**. La persona selecciona el archivo y pulsa **Enviar archivo**; la otra lo recibe automáticamente y utiliza **Guardar archivo**. Los dos contactos deben estar verificados.

El nombre, el contenido y la clave del archivo se envían dentro de un mensaje cifrado de extremo a extremo. El archivo se cifra además con AES-256-GCM y una clave independiente. Antes de confirmar la recepción se valida tanto el mensaje como el adjunto; si una validación falla, el sobre permanece en la cola y la interfaz presenta una alerta, incluso si el identificador del formato es desconocido.

El servidor no recibe el nombre, contenido ni clave en claro. Sí puede observar que se trata de un adjunto, así como el emisor, destinatario, tamaño aproximado y momento de envío. La interfaz local necesita acceso al archivo seleccionado para cifrarlo.

## Guardado local

El botón guarda una copia **descifrada** en `clients/descargas/<usuario>/`, o bajo el directorio indicado mediante `--home`. La carpeta se crea privada y el archivo con permisos `0600`. La apertura comprueba que los directorios no sean enlaces simbólicos y crea el archivo de forma exclusiva: si el nombre existe, se intenta con un sufijo numérico sin sobrescribirlo. Esta protección requiere un sistema que admita las operaciones POSIX utilizadas; si no están disponibles, se rechaza el guardado. El archivo guardado queda en texto claro en el equipo; su protección y eliminación fuera de la aplicación corresponden a la persona usuaria. Por ahora no hay borrado desde la interfaz. La consola puede recibir adjuntos y muestra el nombre en su historial sin imprimir la clave, pero no dispone de una acción de consola para guardarlos.

## Compatibilidad y límites

Los mensajes de texto anteriores siguen siendo legibles y no se interpretan como archivos aunque contengan JSON. El formato nuevo de adjunto está autenticado y es visible para el servidor como identificador de formato. Clientes antiguos no pueden descifrarlo: se deben actualizar ambos clientes antes de intercambiar archivos. Si un cliente sin soporte recibe uno, no lo confirma y la cola queda pendiente hasta actualizar o resolver el problema.

El límite es por archivo y todo el contenido se procesa en memoria; no se implementa transmisión por partes ni control de cuota acumulada. La aplicación conserva el sobre y la clave en el estado local cifrado, de forma que múltiples archivos hacen crecer ese estado. La recepción automática y el guardado se han probado mediante HTTP local y bases temporales, pero no sustituyen una revisión de seguridad independiente. No se ha evaluado resistencia frente a malware local, alteración maliciosa del sistema de archivos por el propio usuario o pérdida del archivo local.

Pruebas desde la raíz:

```sh
.venv/bin/python -m unittest tests.test_attachment_chat tests.test_attachment_ui_integration tests.test_safe_download -v
```
