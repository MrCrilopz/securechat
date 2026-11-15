# Guía de ejecución y demostración

## Preparación

En una terminal, entre en la carpeta del proyecto, cree el entorno e instale la dependencia:

```bash
cd /ruta/al/proyecto
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

La instalación necesita conexión a Internet. En cada terminal nueva, entre en la carpeta y active el entorno con los dos primeros comandos siguientes:

```bash
cd /ruta/al/proyecto
source .venv/bin/activate
```

## Iniciar las tres partes

1. Primera terminal: `python -m servidor.server --database server.sqlite3`.
2. Segunda terminal: `python -m cliente.ui`. Esta aplicación no abre la base del servidor: habla con el puerto 8765 y escribe cada cuenta en `clients/<usuario>.json`.
3. Tercera terminal: `python -m servidor.admin --database server.sqlite3`. Invente una contraseña de operador de al menos 12 caracteres. No aparece al escribirla. No cierre esa terminal.
4. Abra la aplicación de usuarios en http://127.0.0.1:8766 y el panel del servidor en http://127.0.0.1:8767. Ingrese al panel con la contraseña que acaba de definir.

## Demostrar las conversaciones

1. Abra la aplicación de usuarios en dos navegadores distintos, o en una ventana normal y otra privada. Las pestañas del mismo perfil comparten sesión.
2. Cree dos cuentas diferentes, por ejemplo `alice` y `bruno`, y elija para cada una una contraseña distinta de al menos 12 caracteres. Inicie sesión en ambas con la contraseña que acaba de elegir.
3. En **Contactos**, solicite la huella del otro usuario en cada ventana. Compruebe que coincidan por un canal independiente; use **Copiar huella** para pegarla en **Huella confirmada**. Pulse **Verificar** en ambas cuentas.
4. En **Conversaciones**, seleccione al otro contacto y envíe un mensaje desde la primera cuenta. El destinatario lo recibirá automáticamente en unos segundos. Después puede responder.
5. Para observar la cola, envíe un mensaje mientras la otra persona está en Contactos, en Grupos o en otra conversación. El mensaje sigue en **Mensajes cifrados pendientes** y, junto a ese contacto, aparece el número de mensajes sin leer. Cuando abre esa conversación, el mensaje se lee y sale de la cola. Si ya estaba dentro de esa misma conversación, se lee solo.
6. Use **Cerrar sesión** en cada cuenta al terminar.

El mismo usuario no debe abrir dos sesiones a la vez. Para iniciar la primera conversación clásica, una persona envía primero y la otra debe recibir antes de responder. No restaure copias antiguas del estado local ni de `server.sqlite3`.

`cliente/` y `servidor/` son el código. `clients/` son los datos cifrados de cada cuenta. `securechat/` es la criptografía compartida; `python -m securechat.ui` abre la misma aplicación que `python -m cliente.ui`.

## Double Ratchet, acuerdo híbrido y grupos

Estas opciones están en la aplicación web. La consola (`python -m cliente.client`) registra, verifica, envía y recibe la conversación de a dos; no tiene botones para el híbrido ni para los grupos.

1. **Enviar** usa la conversación clásica. Úselo para la demostración de los ataques y de los archivos.
2. **Enviar con Double Ratchet** aparece antes de que exista una conversación. Las dos personas pueden pulsarlo. Los dos primeros mensajes se entregan y los siguientes usan la misma sesión. Si la conversación clásica ya existe, el botón dice **Pasar a Double Ratchet**: cada persona sigue en la sesión clásica hasta que ella lo pulsa. Los mensajes anteriores se conservan.
3. **Enviar con acuerdo híbrido** también aparece solo antes de abrir una conversación. Al iniciar sesión, cada cuenta publica su preclave. Si la otra no la tiene, no se envía un mensaje clásico en su lugar. Una conversación ya abierta no cambia a este acuerdo.
4. En **Grupos**, escriba el nombre, los otros usuarios separados por comas y el primer mensaje. Esas personas tienen que estar verificadas. La clave del emisor viaja cifrada en las conversaciones de a dos y el historial muestra «Clave de grupo actualizada». La pantalla crea el grupo y envía ese primer mensaje. Quitar a un miembro, para que deje de recibir la clave nueva, está cubierto por las pruebas del programa y esta pantalla no tiene ese botón.

Los límites de cada opción están en `docs/double-ratchet-experimental.md`, `docs/acuerdo-hibrido-experimental.md`, `docs/grupos-experimentales.md` y `docs/adjuntos-experimentales.md`.

## Demostrar los ataques

En el panel del servidor, ejecute cada botón: **Sustituir preclave**, **Modificar mensaje** y **Repetir mensaje**. En cada caso se muestran los valores relevantes y el rechazo. Estos escenarios usan identidades y mensajes de prueba aislados y no alteran las conversaciones reales. Registre o capture los resultados para el anexo del informe.

## Cerrar

Cierre las sesiones y pulse `Ctrl+C` en las tres terminales. La contraseña de operador tendrá que definirse de nuevo al volver a iniciar el panel.

## Interceptar un mensaje real con ambos usuarios conectados

1. Inicie los tres servicios y abra la aplicación en dos navegadores o perfiles diferentes. Inicie sesión con ambos usuarios y verifique sus huellas.
2. En el panel del servidor, en **Mensajes cifrados pendientes**, pulse **Interceptar este mensaje** en el mensaje que quiere alterar. Ahí se ve el emisor y el destinatario. No hay que escribirlos.
3. Desde el emisor, envíe un mensaje nuevo al destinatario indicado. La activación solo afecta el primer mensaje que coincida con ambos usuarios y caduca a los dos minutos; puede cancelarse antes de que ocurra.
4. El panel mostrará el texto cifrado original y el de la copia alterada. El destinatario mostrará una alerta al rechazar la copia modificada.
5. El servidor conserva el mensaje original sin modificaciones. En la siguiente consulta automática, el destinatario recibe el original; esto evita perder mensajes o desincronizar la conversación.

La alteración se aplica exclusivamente a una copia durante la entrega, no a la copia persistida. La prueba no demuestra que el servidor pueda descifrar o modificar un mensaje sin que se detecte.

## Demostración de adjuntos

1. Inicie los clientes con la misma versión y verifique las huellas entre las dos cuentas.
2. En la conversación, seleccione un archivo de hasta 24 KiB y pulse **Enviar archivo**.
3. El destinatario lo recibe automáticamente y pulsa **Guardar archivo**. Revise la ruta mostrada, bajo `clients/descargas/<usuario>/`. La copia guardada está descifrada.
4. En el panel del servidor, antes de que se entregue, puede observarse el mensaje cifrado. El servidor conoce que es un adjunto y sus metadatos de transporte, pero no su nombre ni contenido en claro.

Clientes antiguos no aceptan adjuntos nuevos: actualice ambos antes de enviarlos. El guardado evita sobrescribir nombres existentes y rechaza enlaces simbólicos en la ruta; no hay borrado de adjuntos desde la aplicación.
