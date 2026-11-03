# Validación y límites

[Inicio de documentación](../../README.es.md) | [English](../en/validation.md)

Este es un resumen preparado para publicación de la validación del build 1.0,
fechado el 3 de noviembre de 2026. El repositorio no incluye evidencia privada,
casos, informes internos detallados ni sus ubicaciones de almacenamiento.

## Comprobaciones registradas

| Suite | Controles aprobados |
|---|---:|
| Correcciones específicas de la entrega | 14 |
| System Profile | 51 |
| Lector de casos | 28 |
| Comportamiento de grilla | 40 |
| Integración WPF | 102 |
| Referencias y casos límite AD1 | 567 |
| **Total** | **802** |

Pasaron además tres pruebas de carga nativa: directorio del paquete UI, directorio
CLI local y directorio CLI en SMB. Verificaron que el runtime Visual C++ requerido
se cargó desde el paquete sin estar precargado en el proceso de prueba.

## Procesamientos de evidencia

| Prueba | Resultado observado |
|---|---|
| E01 Windows 10 | 827 fuentes, 22.332 registros, 19 instancias de disco registradas y cero errores de parser. Cuatro advertencias corresponden a fuentes de perfil no disponibles. |
| E01 Windows 11 | 5.201 registros, tres instancias de disco y 527 Prefetch válidos. Ocho advertencias corresponden a cinco fuentes de perfil no disponibles y tres Prefetch inválidos. |
| Carpeta de hives de máquina Windows 11 | DEFAULT, SAM, SOFTWARE y SYSTEM produjeron 3.378 registros. Todas las filas y campos coincidieron con los mismos hives del E01 por procedencia, normalizando solo el prefijo de origen. |
| CLI publicado ejecutado desde SMB | Un AD1 controlado produjo 13 registros sin errores ni advertencias. El caso aprobó controles de integridad y procedencia. |

La prueba de carpeta usó hives originales mediante una imagen montada en solo
lectura, sin extraerlos. Las tablas vacías no se contaron como cobertura positiva.

## Alcance de las conclusiones

- Se comprobaron integridad, preservación de fuentes, procedencia y los cotejos
  pertinentes de campos para los casos indicados.
- Las correcciones de discos, bias y falsos Prefetch se verificaron contra las
  fuentes originales. Se conservaron los conteos de Prefetch válidos.
- Los live elevados Win10/11 y flujos SMB validados previamente respaldan el
  mecanismo de adquisición sin cambios. No son nuevos live elevados del paquete
  final exacto; la aceptación final del operador es una comprobación distinta.
- Pasaron las pruebas WPF y se revisó un render sintético de componentes. La
  captura automática de la ventana de escritorio no pudo completarse.
- Estos resultados no certifican todas las configuraciones Windows, variantes de
  artefactos ni campos de cualquier fuente posible.

Un acceso directo parcialmente decodificado puede conservar información válida
del contenedor o la cabecera y dejar otros campos no disponibles. Revisa su estado
y diagnóstico. Los datos ausentes no se inventan.

En cada examen, comprueba finalización, cobertura de fuentes, advertencias,
registros representativos y reapertura del caso. Conserva la evidencia original,
la versión exacta del software y el manifiesto del paquete utilizado.
