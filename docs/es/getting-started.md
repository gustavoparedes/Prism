# Primeros pasos

[Inicio de documentación](../../README.es.md) | [English](../en/getting-started.md)

Esta guía describe la aplicación preparada de Prism 1.0. Por ahora no se publican
descargas de software en este repositorio de documentación.

## Requisitos

- Windows 10 o Windows 11, x64.
- Permiso de lectura sobre la evidencia y de escritura en el destino del caso.
- Un proceso elevado para adquisición live.
- La carpeta completa de la aplicación portable. Conserva sus dependencias junto
  a los ejecutables; copiar únicamente el ejecutable no es suficiente.

La distribución preparada es autocontenida. Incluye las dependencias nativas de
E01 junto a los ejecutables de UI y CLI; no ejecuta un instalador de runtime aparte.

## Interfaz gráfica

1. Inicia `Prism.Wpf.exe`.
2. Elige **New Case**, un destino `.pri` nuevo y la fuente de evidencia.
   El procesamiento comienza al confirmar la selección.
3. Elige **Open Case** para revisar un `.pri` existente; abrirlo no solicita otra
   ejecución del procesamiento de evidencia.
4. Revisa el estado, las advertencias y la cobertura de fuentes antes de interpretar
   los conteos de artefactos.
5. Selecciona **All Artifacts**, una categoría o un artefacto individual.

Usa un caso nuevo para cada procesamiento. Las mejoras de parsers no reemplazan
retroactivamente los resultados guardados en casos existentes.

## Línea de comandos

Ejecuta estos ejemplos desde la carpeta de la aplicación, ajustando las rutas al
examen. El archivo de caso de destino no debe existir.

```powershell
.\cli\Prism.Cli.exe scan --case D:\Cases\Image.pri --input D:\Evidence\Disk.E01 --kind e01
.\cli\Prism.Cli.exe scan --case D:\Cases\Logical.pri --input D:\Evidence\Logical.ad1 --kind ad1
.\cli\Prism.Cli.exe scan --case D:\Cases\Hives.pri --input D:\Evidence\Hives --kind folder
.\cli\Prism.Cli.exe scan --case D:\Cases\Live.pri --input C: --kind live
```

El último comando requiere una terminal elevada. Los tipos de entrada son `auto`,
`e01`, `ad1`, `folder` y `live`. Consulta [fuentes de evidencia](evidence-sources.md)
para conocer alcance, comportamiento de adquisición y límites.
