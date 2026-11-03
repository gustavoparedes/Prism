# Prism 1.0 — notas del build preparado

[Inicio de documentación](../../README.es.md) | [English](../en/release-notes.md)

**Estado del repositorio: solo documentación.** Estas notas describen el build 1.0
preparado; no anuncian una publicación pública de software ni una descarga aquí.

## Capacidades incluidas

- Interfaz de revisión WPF y CLI para entradas E01, AD1, carpeta y live compatibles.
- Casos SQLite `.pri` con resultados, procedencia, información de procesamiento,
  diagnósticos y anotaciones del investigador.
- Tablas individuales, vistas por categoría y All Artifacts.
- Búsquedas combinadas, filtros de grilla, detalles seleccionables, bloqueo de
  columnas, labels y comentarios, incluida la aplicación de labels en lote.
- Almacenamiento UTC para instantes conocidos y offsets solo de visualización.

## Correcciones del build 1.0 preparado

- Inventario de instancias de disco en System Profile, con modelo, identificadores,
  procedencia, valores del registro y tiempos de clave.
- Interpretación correcta del bias Windows con signo, conservando la representación
  original cuando cambia.
- Exclusión de perfiles de color válidos con extensión `.pf`, sin suprimir
  diagnósticos de Prefetch realmente inválidos.
- Mayor precisión en los avisos de fuentes de perfil no disponibles.
- Inclusión del runtime Visual C++ nativo requerido por E01 junto a ambos
  ejecutables, con pruebas de carga desde el propio paquete.

Procesa un `.pri` nuevo para obtener los campos de extracción añadidos. Los casos
existentes no se reprocesan silenciosamente. Consulta [validación](validation.md)
para conocer alcance probado, distinciones de aceptación y límites.

Publicar fuentes, subir binarios, crear tags de release y cambiar la visibilidad
son decisiones posteriores del responsable y no se han ejecutado aquí.
