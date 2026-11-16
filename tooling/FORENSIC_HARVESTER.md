# Forensic Harvester — рабочий комбайн для анализа FEAR3

`tooling/forensic_harvester.py` и `tooling/harvester_extras.py` объединяют уже выполненные исследования с проверенным побайтовым поиском. Они **ничего не устанавливают, не скачивают, не запускают EXE и не изменяют артефакты**. Нужен Python 3.10+; для всех команд кроме `disasm` достаточно стандартной библиотеки. Результаты выдаются в JSON на stdout, ошибки — на stderr с ненулевым кодом. Скрипты не обещают конкретного ускорения: они сокращают ручную работу по переходу между CSV, адресами и сырыми секциями.

## Быстрый старт

Запускать из корня репозитория:

```sh
# Проверить наличие индексов и файлы 31 секции по манифесту.
python tooling/forensic_harvester.py doctor
# Дополнительно требовать и сверить полный EXE.
python tooling/forensic_harvester.py doctor --require-exe

# Поиск по всем индексам с указанием источников и числа совпадений.
python tooling/forensic_harvester.py search GameScriptPlayer --limit 5
python tooling/forensic_harvester.py search ShowMovie --source api --source symbols

# Всё в одном: индексы, профили точных совпадений, опционально сырые байты и ссылки.
python tooling/forensic_harvester.py triage 'Despair::GameScriptPlayer' --bytes exe --refs --limit 3
python tooling/forensic_harvester.py triage 'GameScript.Game.ShowMovie'

# Структурные связи: COL, vtable, базы, ссылки в RTTI и символах, сравнение с API.
python tooling/forensic_harvester.py class 'Despair::GameScriptPlayer' --limit 10
python tooling/forensic_harvester.py class 0x169B418
python tooling/forensic_harvester.py api GameScript.Game.ShowMovie

# Адреса и байты.
python tooling/forensic_harvester.py sections
python tooling/forensic_harvester.py map --va 0x1870E7C
python tooling/forensic_harvester.py map --rva 0x1470E7C
python tooling/forensic_harvester.py map --file 0x13FB27C
python tooling/forensic_harvester.py dump --va 0x169B420 --size 32
python tooling/forensic_harvester.py find --text GameScriptPlayer --nul --limit 20
python tooling/forensic_harvester.py find --hex '2e 3f 41 56' --section .data
python tooling/forensic_harvester.py refs 0x169B418 --limit 10

# Дополнительные средства анализа.
python tooling/forensic_harvester.py at --va 0x169B418 --radius 16 --limit 3
python tooling/forensic_harvester.py stats --section Game_dat --extracted
python tooling/forensic_harvester.py strings --section Game_dat --contains GameScriptPlayer --nul --extracted
python tooling/forensic_harvester.py pattern 'E8 ?? ?? ?? ?? 83 C4' --section .text --limit 5
python tooling/forensic_harvester.py words --va 0x1870E7C --count 4 --extracted
python tooling/forensic_harvester.py vtable --va 0x1870E7C --count 4 --extracted
python tooling/forensic_harvester.py diff --left-va 0x1870E7C --right-va 0x1870E80 --size 16 --extracted
python tooling/forensic_harvester.py imports --dll KERNEL32 --symbol GetProcAddress
python tooling/forensic_harvester.py cpp-exports --query GThread
python tooling/forensic_harvester.py trace-string --text ShowMovie --nul --string-section Game_dat --reference-section .text
# Только если отдельно установлен Capstone:
python tooling/forensic_harvester.py disasm --va 0x127F4D6 --size 64 --count 12
```

## Расширенный набор: 50 команд

Комбайн содержит 50 команд всего (к прежним 21 добавлены 29). Кроме команд есть 20 выбираемых сигнатур, семь байтовых преобразований, фильтры таблиц и несколько вариантов разбора структур. Точный перечень всегда доступен через `python tooling/forensic_harvester.py --help`.

```sh
# Обзор, структура EXE, все экспорты (включая ordinal-only и forwarder).
python tooling/forensic_harvester.py overview
python tooling/forensic_harvester.py layout
python tooling/forensic_harvester.py compare-sections
python tooling/forensic_harvester.py pe-headers
python tooling/forensic_harvester.py pe-exports --query GThread

# Универсальная работа со всеми CSV в analysis/.
python tooling/forensic_harvester.py tables
python tooling/forensic_harvester.py schema analysis/cpp-classes/classes.csv
python tooling/forensic_harvester.py table analysis/cpp-classes/classes.csv --where kind eq struct --select display_name --select type_descriptor_va --limit 5
python tooling/forensic_harvester.py group analysis/cpp-classes/classes.csv --column kind

# RTTI: упоминания типа, дерево, кандидаты производных типов и сверка с байтами.
python tooling/forensic_harvester.py uses Despair::Vector3d
python tooling/forensic_harvester.py hierarchy Despair::GameScriptPlayer
python tooling/forensic_harvester.py derived Despair::Reflection::Object --direct --limit 5
python tooling/forensic_harvester.py audit-class Despair::GameScriptPlayer --require-complete

# Доступно без EXE для 31 извлечённой секции, при явном --extracted.
python tooling/forensic_harvester.py signatures --list
python tooling/forensic_harvester.py signatures --name gzip --name png --section Game_dat --extracted
python tooling/forensic_harvester.py windows --section Game_dat --window 4096 --step 4096 --min-entropy 7 --extracted
python tooling/forensic_harvester.py int-find 0x6C2D50 --width 4 --endian both --section Game_dat --extracted
python tooling/forensic_harvester.py hash --va 0x1870E7C --size 16 --extracted
python tooling/forensic_harvester.py unpack --va 0x1870E7C --layout 'ptr32,ptr32,u32,pad[2],u16' --extracted
python tooling/forensic_harvester.py cstring --va 0x1878B4C --encoding ascii --extracted
python tooling/forensic_harvester.py chain --va 0x1870E7C --extracted
python tooling/forensic_harvester.py probe --va 0x1870E7C --size 64 --max-output 128 --extracted
python tooling/forensic_harvester.py transform --va 0x1870E7C --size 16 --operation xor --key 0xff --extracted
python tooling/forensic_harvester.py xor-rank --va 0x1878B4C --size 16 --limit 3 --extracted
python tooling/forensic_harvester.py frequencies --section Game_dat --extracted
python tooling/forensic_harvester.py runs --section Game_dat --value 0 --min-length 1000 --extracted
python tooling/forensic_harvester.py section-diff --left Game_dat --right Central_ --extracted

# Представления чисел и упаковка полей без чтения EXE.
python tooling/forensic_harvester.py int-info -1 --width 4
python tooling/forensic_harvester.py float-info --bits 0x3F800000 --width 4
python tooling/forensic_harvester.py pack --layout 'u32,i16,ptr32,pad[2],f32' --value 0x1234 --value -4 --value 0x400000 --value 1.5
```

Аргументы `--root` и `--exe` — глобальные, ставятся **до** команды, например:

```sh
python tooling/forensic_harvester.py --exe '/path/to/F.E.A.R. 3.exe' find --text ShowMovie
```

Полный EXE не включён в Git: для побайтового анализа всех 35 секций положите локальный файл в `evidence/source-exe/F.E.A.R. 3.exe` либо передайте `--exe`. Размер и SHA-256 EXE перед каждым чтением байтов сверяются с `evidence/pe-inventory.json`; файл с другим хешем отвергается. Само совпадение с локальным инвентарём не удостоверяет подлинность файла.

**Без EXE** поиск по CSV, профили, список секций и перевод адресов работают по сохранённым артефактам. Сырые операции могут явно работать только с **31 предоставленной секцией**, каждая проверяется по манифесту и инвентарю перед использованием:

```sh
python tooling/forensic_harvester.py find --text GameScriptPlayer --nul --extracted
python tooling/forensic_harvester.py refs 0x169B418 --extracted
python tooling/forensic_harvester.py dump --va 0x1870E7C --size 16 --extracted
python tooling/forensic_harvester.py triage 'Despair::GameScriptPlayer' --bytes extracted --refs
```

В этом режиме `.text`, `.rdata`, `.data` и `.rsrc` **не сканируются**. Поле `coverage` всегда показывает источник и реально включённые секции; отсутствие совпадений в 31 файле не относится к исключённым секциям. Например, для `refs 0x169B418` в проверенном EXE найдены 3 сырых u32-совпадения, а при `--extracted` — 0: эти совпадения находятся за пределами 31 секции. Запрос несуществующей в выбранном источнике секции — ошибка; автоматического молчаливого переключения на урезанный охват нет. `--exe` и `--extracted` несовместимы. `doctor` без EXE выдаёт предупреждение, но считается успешным, если проверенные индексы и секции целы; `--require-exe` меняет отсутствие EXE на ошибку.

## Команды и интерпретация

| Команда | Что делает | Важные границы |
|---|---|---|
| `doctor` | Проверяет SHA-256 и метаданные файлов секций, согласованность SHA инвентаря и RTTI-сводки, наличие CSV и необходимых колонок; проверяет EXE, если он есть или затребован. | **Не** пересоздаёт анализ и не аутентифицирует содержимое CSV; не заменяет `tooling/verify.py` или `tooling/verify_cpp_classes.py`. Ошибки возвращают код 1. |
| `triage` | Поиск по пяти индексам, точные профили класса/API при наличии; `--bytes exe` или `--bytes extracted` добавляет буквальный поиск UTF-8/UTF-16LE/UTF-16BE, `--refs` — ссылки на точно выбранный TypeDescriptor. | Сырые строки ищутся **с учётом регистра**, без завершающего NUL, и являются только буквальным свидетельством. Декодированное имя C++ не обязательно присутствует в EXE в читаемом виде. `--refs` требует указать источник байтов и ровно один точный класс. |
| `search` | Регистронезависимый поиск подстроки по именам и декорированным именам классов, сводному указателю имён, C++ символам, путям API, script-строкам. `--source` можно повторить. | Это поиск по **выбранным полям пяти CSV**, не по всем CSV/байтам и не семантическая идентификация типа. |
| `class` | Требует точного имени или VA TypeDescriptor; возвращает оригинальную запись и связанные CSV-строки COL, vtable, баз, входящие/исходящие RTTI-упоминания, совпавшие упоминания символов, сравнение с API. | Неоднозначный/неполный запрос отклоняется; уточните через `search`. Базы — элементы RTTI-иерархии, не обязательно непосредственные родители. Ссылки в CSV сопоставлены по точным ключам и могут быть неполны. |
| `api` | Ищет точный полный путь в аудите и возвращает записи прокси и кандидатов регистрации из двух связанных CSV. | Сопоставление основано на имени; CFG-кандидат и совпадение количества аргументов не доказывают ABI, выполнение или идентичность версий игры и справочника. |
| `sections`, `map` | Использует сохранённый инвентарь для списка секций и конвертации file offset / RVA / preferred VA. | Виртуальный хвост без байтов не получает file offset, raw-padding помечается отдельно. Заголовки, зазоры и overlay не отображаются. При пересечениях выдаются все варианты. |
| `dump` | Читает `--size` байтов в одной файловой секции проверенного источника, выдаёт hex и ASCII-предпросмотр. | Не позволяет пересечь границу секции или прочитать виртуальный хвост; диапазон и ASCII не доказывают тип данных. |
| `find` | Ищет literal text или hex по сырым байтам секций, включая перекрывающиеся совпадения. `--encoding` задаёт `ascii`, `utf-8`, `utf-16le`, `utf-16be`; `--nul` добавляет терминатор только к тексту. | Это поиск байтов, не декодирование всего файла и не поиск в headers/overlay/zero-fill; NUL в начале не требуется, регистр не нормализуется. |
| `refs` | Ищет абсолютное 32-битное значение, сырые `E8/E9 rel32` и `FF 15/FF 25` с operand `disp32`; результаты сгруппированы, лимит применяется к каждой группе отдельно. | Все виды — сырые **кандидаты**, без проверки границ инструкций/CFG; u32 может быть данными. `FF 15/25` указывают на адрес **ячейки памяти**, например IAT-слота, а не непосредственно на адрес функции DLL. Один и тот же operand может числиться в нескольких группах. |
| `at` | Сопоставляет preferred VA с адресными полями девяти CSV и IAT-слотами PE-инвентаря; `--radius` находит поля в пределах смещения и указывает signed delta. | Это совпадения выбранных столбцов в сохранённых данных, не полный xref и не установленные диапазоны функций. При лимите выдаётся порядок CSV, не сортировка по расстоянию. |
| `stats` | Вычисляет хеш, энтропию, доли нулей/ASCII и длину самой длинной непрерывной последовательности нулей по каждой выбранной сырой секции. | Энтропия сама по себе не доказывает сжатие или шифрование; совпадение хеша — с локальным инвентарём, не проверка подлинности. |
| `strings` | Извлекает максимальные неперекрывающиеся printable ASCII-последовательности и ASCII-диапазон в UTF-16LE/BE на любой позиции, опционально фильтруя по NUL и подстроке. | Это **не полный Unicode** и не доказательство использования строки. Начальный NUL не требуется, записи ограничены пределами секции; длинные превью урезаны, но длина и SHA-256 полных байтов сохранены. UTF-16/ASCII могут давать ложные совпадения в данных. |
| `pattern` | Побайтовый шаблон с `??`/`?`, например `E8 ?? ?? ?? ?? 83 C4`, с перекрывающимися совпадениями. | Требуется хотя бы один буквальный байт; результаты сырые и не подтверждают инструкции. Разреженные шаблоны могут давать миллионы совпадений и выполняться долго: `--limit` ограничивает вывод, а не подсчёт. |
| `words` | Выводит маленькие 1/2/4/8-байтные little-endian значения со знаковым и беззнаковым представлением; для u32 показывает возможное отображение в секцию. | Предположение «число — указатель» не доказано. При `--extracted` отображение значений использует метаданные **всех** секций, но байты читаются только из выбранного источника. |
| `vtable` | Показывает выбранное число u32-слотов, предыдущее слово и совпадения с сохранёнными кандидатами виртуальных таблиц. | Длина таблицы не вычисляется; запрошенные соседние слова могут относиться к другим данным. Предыдущее слово — не доказанный COL без структурной проверки; использованы существующие кандидаты. |
| `diff` | Сравнивает два raw-backed диапазона preferred VA, хеширует их, считает различающиеся байты и показывает ограниченный список различий. | Нет сравнения с другой версией EXE и нет чтения через границу секции; равные байты не обязательно равнозначны по смыслу. |
| `imports`, `cpp-exports` | Просматривает обычные импорты/DLL и IAT из PE-инвентаря и MSVC-декорированные экспорты из сохранённого C++ CSV. | IAT VA — адрес слота, не функции; delay imports и содержимое внешних DLL не анализируются. `cpp-exports` не претендует на полный каталог всех видов экспортов. |
| `trace-string` | Ищет буквальную последовательность, затем для первых `--max-targets` (не более 10) ищет сырые ссылки на **начало совпадения**. Ограничение поиска строк и ссылок задаётся раздельно. | Паттерн может находиться внутри другой строки; обратные ссылки и границы инструкций не доказаны. Пропущенные из-за лимита совпадения явно помечены `truncated`. |
| `disasm` | С помощью необязательного Capstone линейно декодирует x86-32 от указанного адреса, показывает инструкции, байты и возможные секции immediate-значений. | Произвольная точка не гарантирует границы инструкций или функции; данные могут декодироваться как инструкции. Ни CFG, ни достижимость, ни выполнение не проверяются. Максимум 4096 байт и 512 инструкций. |

Для ручной сверки на данном EXE: `trace-string --text ShowMovie --nul --string-section Game_dat --reference-section .text` находит строку `0x1878B4C` и u32-совпадение `0x127F4DD`. Линейная декодировка от ранее исследованного `0x127F4D6` показывает непосредственный operand в `push` на `0x127F4DC`; произвольное сырое совпадение таким образом подтверждается не автоматически. `imports --dll KERNEL32 --symbol GetProcAddress` даёт IAT-слот `0x13F0254`; `refs 0x13F0254 --section .text` показывает девять сырых FF15-кандидатов, один из них `0x9DAD1D` декодируется как `call dword ptr [0x13f0254]`. Это статические наблюдения, не runtime-трасса.

`total`, `returned`, `truncated` выводятся вместе, чтобы ограниченный вывод не выглядел полным. Лимит 1–10000 управляется `--limit` (для каждой таблицы или вида ссылок отдельно); подсчёт продолжает проход после достижения лимита. Знак результата адреса всегда считается при preferred image base `0x400000`, **не runtime VA с ASLR**. Отметка `raw_padding_beyond_virtual_size` — сравнение с объявленным VirtualSize, а не гарантия фактического поведения загрузчика. При выводе в файл используйте shell-redirection и не перезаписывайте исходные CSV.

### Дополнительные операции и ограничения

- `overview` считает записи существующих индексов без утверждения их семантической уникальности. `layout` показывает интервалы, перекрытия, не занятые секциями диапазоны и размер хвоста; пробелы могут включать заголовки и padding, а не только overlay.
- `compare-sections` заново сверяет **31 извлечённый файл** с соответствующими raw-байтами проверенного EXE. `pe-headers` разбирает PE32-заголовки и 35 секций непосредственно из EXE, сверяя их с инвентарём; для security directory адрес помечен как file offset. `pe-exports` читает обычную таблицу экспортов из EXE, включая имена, ordinal-only и forwarder; внешняя функция при этом не загружается. Эти три команды требуют полный EXE и сверяют его SHA-256.
- `tables`, `schema`, `table`, `group` разрешают читать **только** точные имена CSV из `analysis/`; символические ссылки за пределы `analysis/` и обход путей отклоняются. Фильтры `--where COLUMN OP VALUE` можно повторять: `eq`, `ne`, `contains`, `starts`, `ends`, `gt`, `ge`, `lt`, `le`; они объединяются через AND. Числовые сравнения принимают целые decimal и `0x`-hex, нечисловые поля не проходят. `--ignore-case` относится к строковым фильтрам/группам; `--select` повторяется, `--offset` и `--limit` дают страницу с полным `total`. Сортировка `--sort COLUMN` строковая, `--numeric-sort` — целочисленная; в числовой сортировке нечисловые значения идут после чисел при прямом порядке и перед ними при обратном. Для сортировки допускается максимум 150 000 совпадений; фильтруйте большие таблицы заранее.
- `uses` ищет точное раскодированное написание даже у типов без собственного RTTI. `hierarchy` проверяет и раскладывает последовательные `contained_bases` в кандидатов родительских индексов; `derived --direct` использует те же интервалы для кандидатов непосредственного наследования. Это реконструкция структур RTTI, а не проверка исходников или поведения, и дубликаты баз остаются отдельными вхождениями.
- `audit-class` сравнивает поля выбранного TypeDescriptor, COL, первых слотов vtable и base-descriptor с сырыми байтами. `complete=false` при лимите или недоступных секциях, а `all_match=true` только если всё проверенное доступно и совпало. С `--extracted` у `GameScriptPlayer` доступны 2 vtable-проверки, но RTTI/COL/base в отсутствующих секциях: это **не** полный аудит. Несовпадение возвращает код 1; `--require-complete` возвращает 1 также при неполноте. Проверяются только указанные поля существующего индекса, не все возможные ссылки и не истинность типа в runtime.
- `signatures` ищет 20 готовых префиксов, включая PNG, DDS, ZIP, gzip, XZ, LZ4, Zstandard и распространённые двухбайтные zlib-заголовки. Совпадение сигнатуры — кандидат, не проверенный файл; короткие значения особенно шумные. `windows` вычисляет энтропию пересекающихся или отдельных окон одной секции (до 100 000 окон), с опциональным последним неполным окном. `frequencies` и `runs` показывают распределение байтов и максимальные серии одинаковых байтов. Ничто из этого не доказывает компрессию или шифрование.
- `int-find` ищет представления целого по одной или нескольким ширинам и endian, включая невыровненные совпадения. `int-info` и `float-info` переводят значения/битовые шаблоны; для IEEE NaN и бесконечности JSON содержит строковые значения. `pack` создаёт байты, `unpack` читает их как явно заданную **packed**, без автоматического выравнивания, структуру. Допустимы `u8/i8/u16/i16/u32/i32/u64/i64/f32/f64/ptr32/pad[N]`; не более 256 полей и 4096 байт. `ptr32` — лишь кандидат указателя.
- `hash` считает MD5/SHA-1/SHA-256/SHA-512/BLAKE2b/CRC32/Adler-32 диапазона до 1 MiB; первые два и контрольные суммы не подходят для доказательства подлинности. `cstring` ограниченно читает одну NUL-строку в ASCII/UTF-8/Latin-1/UTF-16 и отдельно сообщает отсутствие терминатора, обрезку и ошибки декодирования. `chain` читает не более 32 little-endian u32 подряд, останавливается на нуле, цикле, недоступной секции или лимите; это raw preferred VA без ASLR/релокаций, не runtime-память.
- `probe` пытается декодировать **только** zlib, gzip и raw DEFLATE из заданного начала диапазона. Вход и вывод ограничены 1 MiB, результат содержит статус, длину и хеш ограниченного префикса, не записывая извлечённые данные. Отказ или `incomplete` ничего не говорит о других смещениях, LZX/LZD и других форматах; успешная проба не подтверждает происхождение данных. `transform` ограничен 4096 байтами и поддерживает XOR, NOT, циклические сдвиги, разворот, swap16/swap32. `xor-rank` перебирает 256 однобайтовых ключей по доле печатных байтов; это слабая эвристика, не доказательство шифрования или расшифровки. `section-diff` сравнивает два сырых диапазона секций по смещениям, показывая различия в общем префиксе и длины хвостов; оно не выравнивает разные версии или структуру данных.

### Необязательный дизассемблер

Все прочие команды не требуют установки пакетов. Для `disasm` отдельно установите закреплённую версию через Python/pip; скрипт никогда не делает это автоматически:

```sh
python -m pip install --target tooling/python capstone==5.0.9
python tooling/forensic_harvester.py disasm --va 0x43E8A0 --size 64 --count 12
```

В пакетах `tooling/requirements.txt` версии закреплены, но хеши wheel не зафиксированы. Используйте доверенное окружение и совместимый wheel.

## Проверка

```sh
python -m unittest discover -s tooling -p 'test_forensic_harvester.py' -v
python -m unittest discover -s tooling -p 'test_harvester_extras.py' -v
python -m unittest discover -s tooling -p 'test_harvester_advanced.py' -v
python tooling/verify.py --exe 'evidence/source-exe/F.E.A.R. 3.exe'
# При установленном pefile и наличии EXE, дополнительно:
python tooling/verify_cpp_classes.py
```

Тесты комбайна используют стандартную библиотеку и синтетические байты плюс сохранённые CSV/секции: проверяют пересечения и границы адресов, zero-fill/padding, перекрывающиеся совпадения, signed rel32, отдельные лимиты, повреждённые файлы, пути манифеста, ограниченный охват `--extracted`, отказ при неверном EXE и интеграционные примеры класса и API. Дополнительные тесты включают 300 случайных wildcard-паттернов против простого независимого алгоритма, строковые кодировки и терминаторы, FF15/FF25, word/diff/entropy, реальную vtable и поиск адресов. Расширенные тесты проверяют запросы CSV и защиту путей, синтетический PE с экспортами по имени/ordinal/forwarder, все 9 656 сохранённых иерархий на согласованность интервалов, ограниченное декодирование zlib/gzip/DEFLATE и большинство новых команд. При наличии EXE сравниваются все 199 экспортов с `pefile` (если он установлен) и проверяется полный аудит класса; при отсутствии EXE соответствующая проверка пропускается. Тест дизассемблера пропускается, если Capstone не установлен. Их успех не подтверждает достоверность каждой исходной интерпретации в индексах. Полные детали старых исследований и их воспроизведение — в [`analysis/cpp-classes/REPORT.md`](../analysis/cpp-classes/REPORT.md) и [`analysis/script-api-audit/REPORT.md`](../analysis/script-api-audit/REPORT.md).

### Повторная проверка и остаточные RTTI-кандидаты

См. `analysis/harvester-validation/REPORT.md`: проверка всех 50 CLI-команд на примерах, независимая сверка всех 35 секций и индивидуальные свидетельства для 2 295 TypeDescriptor без найденного COL. Запустить: `python tooling/validate_rtti_candidates.py` и `python tooling/validate_harvester_commands.py` (нужны локальный проверенный EXE, `pefile` и `capstone`). Байтовые шаблоны и эвристический CFG не доказывают runtime-выполнение.
