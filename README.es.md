# Prism

[English](README.md) | [Español](README.es.md)

**Análisis y revisión forense de artefactos de Windows, en una aplicación portable.**

Prism extrae y presenta artefactos del Registro de Windows y artefactos seleccionados
del sistema de archivos desde **imágenes E01/EWF, imágenes lógicas AD1 sin cifrar,
carpetas y sistemas Windows vivos**. Permite revisar los registros, sus timestamps
y su procedencia, y organizar hallazgos con labels de color y comentarios. Los
casos se guardan en archivos SQLite `.pri`.

**Paquete para Windows:** [Releases](https://github.com/gustavoparedes/Prism/releases). Conserva completa la carpeta extraída de la aplicación.

![Prism — All Artifacts](assets/screenshots/02-all-artifacts.png)

## Funciones principales

- **All Artifacts y vistas por categoría:** revisa campos comunes entre familias
  de artefactos o entra en una familia y consulta todos sus detalles extraídos.
- **System Profile:** consulta propiedades registradas del SO, identidad, usuarios,
  software, dispositivos y configuración, junto a sus fuentes.
- **Búsquedas y filtros:** combina fechas, palabras clave, expresiones regulares
  y labels; refina los resultados con filtros nativos por columna.
- **Labels y comentarios:** crea labels reutilizables con color, asígnalos a uno
  o varios registros y añade observaciones individuales.
- **Visualización temporal:** presenta los instantes UTC conocidos con un offset
  fijo elegido por el usuario, conservando los valores y su base temporal documentada.
- **Acceso directo a la evidencia:** lee E01, AD1 y carpetas directamente. En live,
  intenta primero la lectura normal y copia temporalmente solo hives autorizados
  bloqueados, sin crear instantáneas del SO.
- **UI y CLI portables:** la carpeta autocontenida para Windows 10/11 x64 permite
  revisión interactiva y procesamiento automatizado.

## Artefactos de Windows

| Categoría | Ejemplos |
| --- | --- |
| Execution | Prefetch, BAM/DAM, UserAssist, ShimCache, AmCache, RunMRU, MUICache |
| File and Folder Access | Shellbags, RecentDocs, OpenSaveMRU, TypedPaths, LNK, JumpLists, Recycle Bin |
| USB and Devices | Disk Devices, USBSTOR, MountPoints2, SetupAPI |
| Network and Remote Access | NetworkList, interfaces, RDP Client, reglas de firewall, Hosts |
| Persistence and System | Autorun, servicios, tareas programadas, historial PowerShell, software instalado |
| System Profile | Propiedades del SO, identidad, cuentas, perfiles, configuración horaria e inventario de dispositivos |

La cobertura depende del formato del artefacto y de la evidencia disponible.
Interpreta cada registro junto con el significado de su timestamp y su fuente.

## Primeros pasos

Conserva completa la carpeta portable y abre `Prism.exe`. Para adquisición
live, ejecútalo con privilegios de administrador. El recorrido presenta **19
capturas reales** con la evidencia pública de entrenamiento PC-MUS-001. Los
labels y comentarios de ejemplo se añadieron a una copia del caso para mostrar
las funciones; no son conclusiones sobre la evidencia.

### Iniciar una revisión

Crea un caso nuevo o abre un caso `.pri` existente.

![Pantalla de inicio de Prism](assets/screenshots/01-start.png)

Elige **New Case** y selecciona el nombre y la ubicación del archivo `.pri`.

![Crear un caso](assets/screenshots/04-new-case.png)

### Elegir la evidencia

Selecciona una imagen E01/EWF, una imagen lógica AD1, una carpeta o un sistema
Windows vivo. Al elegir la evidencia comienza el procesamiento. Esta pantalla
muestra la configuración; las vistas de revisión usan el caso del CTF ya procesado.

![Fuentes de evidencia](assets/screenshots/05-evidence-sources.png)

### Ubicar el caso y su procedencia

Expande **Case information** para consultar la fuente, el inicio y fin del
procesamiento, su duración y los recuentos. Puedes contraerlo para dar más
espacio a la navegación por artefactos.

![Información del caso](assets/screenshots/07-case-information.png)

### All Artifacts

Revisa el caso en una tabla con campos comunes, filtros nativos por columna,
navegación por artefactos y detalles seleccionables. Este caso contiene 5.201 artefactos.

![All Artifacts](assets/screenshots/02-all-artifacts.png)

### Explorar una categoría

Selecciona el encabezado de una categoría para reunir sus familias de artefactos
en una tabla. Selecciona una familia para ver solo sus registros. Los recuentos
ayudan a identificar qué artefactos contiene el caso.

![Categoría Execution](assets/screenshots/08-execution-category.png)

### Prefetch

Selecciona una familia de artefactos para revisar sus registros y los campos
extraídos del registro seleccionado en Details. Los timestamps conservan su
significado y procedencia.

![Prefetch y detalles del registro](assets/screenshots/03-prefetch.png)

Cada familia conserva sus campos propios. Por ejemplo, Shellbags presenta las
referencias a carpetas y la procedencia del registro necesaria para interpretarlas.

![Registros y detalles de Shellbags](assets/screenshots/20-shellbags.png)

### Revisar el contexto del sistema

System Profile reúne propiedades registradas del sistema operativo, identidad,
cuentas, software, dispositivos y configuración. Cada registro conserva su fuente.

![System Profile](assets/screenshots/17-system-profile.png)

### Buscar entre los artefactos

Pulsa **From** o **To** para abrir el calendario y elegir fecha, hora, minuto
y segundo. Confirmar activa el filtro temporal; Cancelar conserva el valor anterior.

Busca por palabra clave o expresión regular, combinándolas con filtros de tiempo
y labels. Los resultados se reúnen entre las distintas familias de artefactos.
Selecciona uno para revisar sus campos y las coincidencias resaltadas en Details.

![Búsqueda con expresión regular](assets/screenshots/14-search.png)

Activa **Labels** para exigir además que el registro tenga un label. Esta vista
combina rango de tiempo, expresión regular y un label guardado.

![Filtros de tiempo, regex y labels combinados](assets/screenshots/19-label-search.png)

### Usar los filtros de la grilla

Los filtros por columna refinan la vista actual. El desplazamiento horizontal
permite consultar más campos extraídos; los paneles de navegación, resultados
y Details se pueden redimensionar.

![Filtro nativo de la grilla](assets/screenshots/16-grid-filter.png)

### Crear labels con color

Haz clic derecho sobre un registro y abre **Manage labels...**. Define un nombre,
una descripción y un color reutilizables durante la revisión. Estos labels de
ejemplo describen el flujo de trabajo; no modifican el artefacto extraído.

![Menú contextual del registro](assets/screenshots/09-annotation-menu.png)

![Administrador de labels](assets/screenshots/10-label-manager.png)

### Asignar un label

El submenú **Add label** presenta los nombres y colores disponibles. Selecciona
uno para anotar el registro. También puedes asignarlo a varios registros seleccionados.

![Labels disponibles con sus colores](assets/screenshots/11-add-label.png)

![Asignación a varios registros](assets/screenshots/18-bulk-labels.png)

### Añadir un comentario

Usa **Comments...** sobre un solo registro para dejar una observación, una
salvedad o el siguiente paso. Los comentarios y labels se guardan en el caso
y aparecen junto al registro revisado.

![Editor de comentarios](assets/screenshots/12-comment.png)

![Anotaciones guardadas](assets/screenshots/13-annotated-record.png)

### Elegir la zona horaria de visualización

El selector cambia cómo se muestran los instantes UTC conocidos. No reescribe
los timestamps almacenados y aplica el offset mostrado como un offset fijo.
Las fechas cuyo significado UTC no se conoce
conservan su base temporal documentada.

![Zona horaria de visualización](assets/screenshots/15-display-time-zone.png)

## Uso desde la línea de comandos

La CLI procesa evidencia compatible sin abrir la interfaz de revisión. Ejecuta
estos ejemplos desde la carpeta de la aplicación y usa un `.pri` nuevo para cada
procesamiento.

```powershell
.\CLI\Prism.Cli.exe scan --case D:\Cases\Image.pri --input D:\Evidence\Disk.E01 --kind e01
.\CLI\Prism.Cli.exe scan --case D:\Cases\Logical.pri --input D:\Evidence\Logical.ad1 --kind ad1
.\CLI\Prism.Cli.exe scan --case D:\Cases\Hives.pri --input D:\Evidence\Hives --kind folder
.\CLI\Prism.Cli.exe scan --case D:\Cases\Live.pri --input C: --kind live
```

Para live, abre el terminal con privilegios de administrador. Los tipos disponibles
son `auto`, `e01`, `ad1`, `folder` y `live`. Conserva la evidencia original por separado del caso extraído.

## Compilar los fuentes

Usa el SDK de .NET 8 o un SDK posterior compatible en Windows.

```powershell
dotnet restore Prism.sln
dotnet build Prism.sln -c Release
dotnet publish Prism.Wpf/Prism.Wpf.csproj -c Release -r win-x64 --self-contained true -o publish/UI
dotnet publish Prism.Cli/Prism.Cli.csproj -c Release -r win-x64 --self-contained true -o publish/CLI
```

La UI utiliza controles Syncfusion. Para tus propias compilaciones, registra una
licencia apropiada con `PRISM_SYNCFUSION_LICENSE_KEY` o un archivo local
`syncfusion-license.txt`, excluido de Git. El repositorio no incluye archivos de activación.

Prism se distribuye bajo la [licencia GNU GPL v3.0](LICENSE). Las licencias y los avisos
de las dependencias se conservan en [licenses](licenses) y
[THIRD-PARTY-NOTICES.json](THIRD-PARTY-NOTICES.json).
