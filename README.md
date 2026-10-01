# Prometheus: transformacion general de Vmify y analisis Lua

`prometheus_devirt_100.py` necesita Python 3.9+ y, para ejecutar muestras,
Lua 5.1–5.4 o LuaJIT. El analisis dinamico no necesita paquetes de Python. La transformacion estatica
necesita la dependencia opcional `luaparser==4.2.0`. No interpreta Luau.

```bash
python3 prometheus_devirt_100.py 1CutGrassAdventure.txt --multi -y -o resultado
```

La salida debe ser una carpeta nueva o vacia. `--solo-estatico` no ejecuta Lua.
Las muestras se ejecutan con APIs simuladas; para entradas no confiables usa
un contenedor/VM desechable sin red. El arnes no es aislamiento del sistema.

## Archivos que consultar

- **`reconstructed.lua`**: efectos observados organizados en funciones, con
  referencias compartidas y retornos. Los cuerpos reflejan argumentos concretos
  y una ejecucion simulada, no funciones equivalentes para cualquier entrada.
- **`functions/fnN.lua`**: fragmentos individuales del archivo anterior; requieren
  sus tablas `values` y `functions`, no son modulos independientes.
- **`functions.json`**: closures encontradas, estados, lineas y upvalues escalares
  (bytes en hexadecimal). Un estado numerico capturado puede corresponder a la
  entrada de una funcion Vmify. `observed` significa que termino esa invocacion;
  **no** que se hayan cubierto todas las ramas.
- **`source_functions.json` / `source_functions.lua`**: indice de todas las
  funciones sintacticas y copia exacta de la fuente. Los offsets son bytes,
  inicio inclusivo y fin exclusivo. Conserva funciones no ejecutadas y relaciones
  de anidamiento; los cuerpos siguen ofuscados. No equivale al numero de closures
  que la VM puede crear durante la ejecucion.
- **`devirt.lua`**: traza cronologica, conservada por compatibilidad.
- **`pass_XX/`**: cada modelo con sus propias funciones, trazas y estados.
  Los nombres `fnN` son locales a cada pasada; no se mezclan entre pasadas.
- **`report.json`**: pasada seleccionada, limites, errores y procedencias.

## Cambios de esta version

Ademas de callbacks de APIs, se exploran funciones globales, tareas y funciones
retornadas. Se conservan retornos multiples y valores `nil`. Los toggles usan
booleanos segun `--branch-policy`; los sliders usan su `value` observado.

`--multi` prueba ambas politicas de comparacion y toggles con el entorno normal,
y despues con globales desconocidos simulados. Cada pasada empieza de cero.
Los callbacks comparten estado dentro de su pasada y solo se invocan una vez.

`--max-waits 3` corta bucles de `wait/task.wait` por bloque principal o callback;
`--max-callbacks 100`, `--timeout 20` y `--wall-timeout` limitan el trabajo.
Los cortes y errores quedan marcados. `--no-callbacks` conserva el inventario
sin ejecutar esos cuerpos. Las esperas simuladas no reproducen un planificador
real y sus limites pueden ser capturados por un `pcall` de la muestra; los
limites de CPU y tiempo real siguen disponibles.

## Transformacion general de Vmify

La ruta general detecta la estructura de la VM; **no depende de un archivo,
SHA-256, nombres de variables, estados concretos ni una semilla especifica**.

```bash
python3 -m pip install -r requirements-static.txt
python3 prometheus_devirt_100.py entrada.lua --solo-estatico --desvirtualizar --retirar-antitamper -o resultado
```

`--retirar-antitamper` es opcional. Neutraliza la comprobacion final del antitamper
estandar cuando reconoce su marcador, closure de bloqueo y bifurcacion final.
Conserva la inicializacion previa, porque el compilador puede mezclarla con codigo
necesario para la aplicacion. El informe distingue `antitamper_bypassed` de
`antitamper_removed`: esta opcion **no retira todas las protecciones**.
Si detecta un patron ambiguo o protecciones basadas en `debug.sethook`, lo rechaza.
Sin la opcion, se mantienen las protecciones y pueden detectar la transformacion.

La salida principal es **`vm_removed.lua`**. `static_vm.json` relaciona los
contenedores, las funciones, entradas y bloques originales, las constantes
sustituidas, las protecciones y los limites. El parser conserva los bytes de
las cadenas, incluidos escapes decimales mayores de 127.

| Patron | Comportamiento |
| --- | --- |
| Vmify directo, sin ConstantArray ni WrapInFunction | Detectado por estructura |
| ConstantArray con rotacion y codificacion de cadenas | Prefijo restringido e inlining de getters puros |
| Parametros, nombres y estados cambiados por semilla | Identificados sin nombres fijos |
| `<`, `<=`, `>`, `>=`, operandos invertidos y `elseif` | Particion de rangos con limites inclusivos/exclusivos |
| Varios contenedores visibles en el mismo archivo | Tablas de funciones distintas por contenedor |
| Flujo reducible | Funciones con `if`/`while` |
| Bucles con varias salidas u otros flujos sin estructura compatible | Etiquetas y `goto`; requiere Lua 5.2+ o LuaJIT |
| Getters con efectos o referencias que escapan | Se conserva el prefijo; no se inventan constantes |
| Strong con una VM compilada dentro de otra | Se transforma el contenedor exterior identificado; puede quedar flujo de la VM interior |

Se interpreta solo el prefijo de constantes mediante un evaluador restringido
de Python. Esta transformacion no ejecuta la aplicacion en Lua, no carga caches
pickle ni descarga recursos. Los layouts desconocidos producen un informe y
salida `3`, sin publicar un Lua parcialmente transformado. La opcion afecta a
`vm_removed.lua`; el analisis dinamico sigue usando el original.

**Alcance:** es una herramienta general para la estructura conocida de Vmify,
no una garantia universal para forks, configuraciones o versiones arbitrarias.
Se conservan el descifrado de cadenas en tiempo de ejecucion, los auxiliares de
closures/upvalues y parte del flujo aplanado. No se recuperan el fuente ni los
nombres originales. No se interpreta sintaxis Luau ni se certifica Roblox real.
`full_devirtualization` y `semantic_equivalence_verified` siguen en `false`.

### Perfil de la muestra adjunta

```bash
python3 prometheus_devirt_100.py 1CutGrassAdventure.txt --solo-estatico --perfil-cutgrass -o limpio
```

El perfil exige SHA-256
`b9cca37758d9000081dd6ba04be0625900a29b418630f6b8d19924c95562843b`.
Recupera **22 funciones**, sustituye **417 accesos a constantes**, descifra
**187 cadenas** y convierte el flujo en `if`/`while`, sin dispatcher ni `goto`.
Retira bloques de antitamper y el descifrador de la aplicacion resultante.
Esa retirada modifica el comportamiento de las protecciones de forma deliberada.
Otros archivos, incluso una copia con distintos saltos de linea, se rechazan.

**Limites:** se mantienen tablas de registros y auxiliares de closures/upvalues.
No se recuperan nombres originales, comentarios ni el codigo fuente exacto.
Los HTTP externos no se descargan. Las dos politicas de comparacion del arnes,
sin globales desconocidos simulados, produjeron trazas iguales a las del original
tras normalizar rutas y numeros de linea; ambas ejecuciones fueron parciales por
limites de esperas y errores de callbacks. Esto no verifica todas las ramas ni
el comportamiento en Roblox real. `full_devirtualization` y
`semantic_equivalence_verified` permanecen en `false`.

Codigos de salida: `0` analisis/transformacion terminado, `2` configuracion o
cancelacion, `3` analisis parcial o patron no soportado, `130` interrupcion.
Ninguno certifica recuperacion total.

## Pruebas

```bash
python3 -m unittest discover -s tests -v
```

Las pruebas basicas necesitan `lua` y la transformacion necesita `luaparser`.
La matriz de los presets oficiales requiere `luajit`: compara el original,
la salida transformada y la fuente de la prueba para Vmify, Weak, Medium y Strong,
cada uno con las semillas 3, 17 y 42. Las fixtures se generaron con LuaJIT para el
target Lua 5.1; su procedencia y hashes estan en `tests/fixtures/prometheus/`.
Esa prueba se omite explicitamente si LuaJIT no esta disponible.

Tambien se comparan ramas, bucles, estado compartido, retornos multiples y `nil`,
bytes binarios, metodos, getters con efectos, varios contenedores y colisiones
de identificadores. El hecho de conservar el comportamiento de Strong no prueba
que se haya eliminado su VM interior.

## Referencia

La deteccion se desarrollo examinando el generador oficial de Prometheus.
Las fixtures de integracion son salidas generadas por ese proyecto.

Based on Prometheus by Elias Oelschner, https://github.com/prometheus-lua/Prometheus
