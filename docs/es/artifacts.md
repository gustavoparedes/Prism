# Cobertura de artefactos

[Inicio de documentación](../../README.es.md) | [English](../en/artifacts.md)

El catálogo actual contiene **37 entradas lógicas**. Es un catálogo de navegación
y cobertura, no un conteo de motores de decodificación independientes ni una
prueba de compatibilidad con todas las variantes.

| Categoría | Entradas del catálogo |
|---|---|
| Execution | UserAssist, MUICache, RunMRU, ShimCache, AmCache, AmCache Programs, BAM/DAM, Prefetch |
| File and Folder Access | Shellbags, OpenSaveMRU, ComDlg32 MRU, RecentDocs, TypedPaths, WordWheelQuery, Office MRU, LNK, JumpLists, Recycle Bin |
| USB and Devices | Disk Devices, USBSTOR, MountPoints2, SetupAPI |
| Network and Remote Access | NetworkList, Network Interfaces, RDP Client, Firewall Rules, Hosts |
| Persistence and System | Autorun, Services, Scheduled Tasks, PowerShell History, Installed Programs, User Accounts, User Profiles, System Information, Windows Updates, Defender Exclusions |

System Profile ofrece vistas adicionales de los registros de sistema existentes:
SO, identidad, configuración horaria y software registrado, entre otros. Estas
vistas no representan adquisiciones independientes adicionales. Inventariar
navegadores instalados no implica analizar historial, cookies o caché.

## Interpretación

- Una instancia de disco registrada no representa necesariamente un disco físico
  distinto conectado en ese momento. Su identificador de instancia no debe
  presentarse como número de serie físico.
- LastWrite del registro corresponde a la clave, no necesariamente a cada acción
  que aparece listada.
- Prefetch puede conservar varias ejecuciones. Revisa los timestamps disponibles
  y su significado, sin tratar cualquier fecha fuente como prueba de ejecución.
- La presencia en una caché de aplicaciones no demuestra por sí sola ejecución
  por parte de una persona identificada.
- Potential Activity describe actividad compatible con el registro. No identifica
  por sí sola al responsable ni demuestra de forma independiente la acción.

Solo pueden aparecer artefactos respaldados por las fuentes disponibles. Un cero
puede indicar fuentes ausentes, datos inexistentes, errores de lectura o variantes
no soportadas. Revisa el log antes de extraer una conclusión negativa.
