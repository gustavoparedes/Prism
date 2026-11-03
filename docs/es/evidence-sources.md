# Fuentes de evidencia

[Inicio de documentación](../../README.es.md) | [English](../en/evidence-sources.md)

| Entrada | Comportamiento | Límites |
|---|---|---|
| E01 | Lee los archivos compatibles por demanda, sin extraerlos a disco. | Los volúmenes y archivos requeridos deben ser legibles. Desbloquear volúmenes cifrados queda fuera de esta versión. |
| AD1 | Lee directamente los miembros lógicos compatibles, incluidos contenedores segmentados. | Quedan fuera el cifrado, las entradas eliminadas, el slack y los descriptores que solo contienen metadatos. |
| Carpeta | Lee los originales en su ubicación. | Depende de los permisos disponibles. La ausencia de hives limita los artefactos extraíbles. |
| Sistema vivo | Intenta primero la lectura normal. Los hives autorizados bloqueados pueden requerir una copia temporal mediante NTFS a bajo nivel. | Requiere elevación. Las otras fuentes ilegibles se reportan y se omiten. |

## Política de adquisición

Prism no crea instantáneas del sistema operativo ni Volume Shadow Copies. Las
entradas E01, AD1 y carpeta no se exportan a colecciones temporales de archivos.
Las copias temporales de hives live se eliminan normalmente al terminar. Ejecutar
una herramienta live y crear temporales puede dejar actividad en el equipo;
no usar instantáneas no equivale a ausencia de impacto ni a una captura atómica
de todas las fuentes.

La opción CLI `--keep-live-copies` conserva las copias de adquisición live para
diagnóstico o preservación cuando el procedimiento del examen lo requiera.
No habilita la extracción de fuentes E01, AD1 o carpeta. Revisa las rutas y hashes
de adquisición registrados antes de utilizar los archivos conservados.

## Casos y originales

Un `.pri` contiene resultados, procedencia, información de procesamiento, labels
y comentarios. No sustituye de forma completa todos los archivos o hives fuente.
Conserva por separado la imagen o los originales. Revisar un caso no requiere
las copias temporales de adquisición, pero el reanálisis independiente puede
necesitar las fuentes originales.

La evidencia fuente se lee; las anotaciones modifican deliberadamente el `.pri`.
El análisis de eventos, la adquisición de memoria y el carving están fuera del
alcance definido.
