# Timestamps y offsets de visualización

[Inicio de documentación](../../README.es.md) | [English](../en/timestamps.md)

Los instantes conocidos en UTC se guardan como UTC. Elegir una zona horaria de
visualización cambia su presentación mediante el offset base de esa zona de
Windows. No modifica la base de datos ni guarda una zona de visualización en el
caso. No se aplican conversiones históricas automáticas de horario de verano;
el perito elige el offset apropiado para el examen.

No toda fecha fuente establece un instante UTC. Las fechas locales con zona
desconocida, las fechas sin hora y las fechas ausentes mantienen su interpretación
explícita; no deben presentarse silenciosamente como UTC conocido.

| Campo | Finalidad |
|---|---|
| Timestamp | Timestamp disponible seleccionado para el registro. |
| Timestamp Meaning | Evento o propiedad fuente que describe realmente esa fecha. |
| Time Basis | Base temporal necesaria para interpretar el valor. |

LastWrite de una clave no equivale necesariamente a ejecución de un programa,
visita a una URL o conexión de un disco. Si hay varias fechas, consulta los campos
originales además del timestamp común. La ausencia de fecha no demuestra ausencia
de actividad.

Los valores bias de Windows son datos de configuración. Los DWORD con signo se
interpretan como minutos con signo; cuando cambia la representación textual,
se conserva la representación original. Leer estos valores no configura
automáticamente el offset de visualización del caso.
