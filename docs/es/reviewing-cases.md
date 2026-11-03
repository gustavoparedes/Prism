# Revisión de un caso

[Inicio de documentación](../../README.es.md) | [English](../en/reviewing-cases.md)

## Distribución

La interfaz tiene tres paneles redimensionables: navegación de artefactos, grilla
de resultados y Details. La información del caso puede contraerse para priorizar
la navegación de artefactos.

- **All Artifacts** presenta registros compatibles con campos comunes.
- Una categoría muestra sus resultados combinados.
- Un artefacto individual muestra su tabla completa.
- Los conteos aparecen junto a los nombres y se resaltan cuando son mayores de cero.
- La grilla permite ordenar, filtrar, desplazarse y bloquear columnas por demanda.
- Details permite seleccionar texto de forma continua y copiar el registro seleccionado.

Los campos comunes incluyen Timestamp, Timestamp Meaning, Time Basis, Artifact
Type, Potential Activity, User, Summary y Source File. Las tablas individuales
exponen los campos propios de cada artefacto. Los detalles de las vistas agregadas
conservan el contexto del registro original; las columnas comunes no sustituyen
el detalle completo.

## Búsquedas

Combina un rango temporal, texto o una expresión regular y una condición de label.
Al iniciar una búsqueda, la grilla presenta todos sus resultados combinados.
Los conteos reflejan el contexto de búsqueda; seleccionar un artefacto limita los
resultados a ese tipo. Las coincidencias de texto o regex pueden resaltarse en Details.

Los filtros temporales requieren el mismo cuidado interpretativo que las fechas
visibles. Consulta Timestamp Meaning y Time Basis antes de tratar las filas como
una secuencia de acciones.

## Labels y comentarios

El menú contextual permite asignar labels o editar comentarios. Los labels
disponibles se muestran con nombre y color. Su administrador permite crearlos,
editarlos y eliminarlos. Se pueden etiquetar varios registros seleccionados a la
vez. Son anotaciones del investigador, no valores de la evidencia original.

## Información de procesamiento

Revisa la fuente, las fechas y la duración en Case information. El log conserva
diagnósticos, advertencias y fallos por archivo. Una finalización con advertencias
requiere revisar esos mensajes aunque haya resultados. Una grilla vacía o un
conteo cero no demuestra por sí solo que una actividad nunca ocurrió.
