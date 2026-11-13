# Сопоставление `Resource.bin` с восстановленными Lua-скриптами

## Краткий результат

Проверены все **271** восстановленных Lua-файла и все 34 ранее выделенные строки `Resource.bin`. В восстановленных скриптах и каталоге API не найдены по имени **19** различных классов из прочитанных RTTI секции, включая `ResourceMgr2`, `RenameStream`, `ResourceJobWrapper`, `Workspace` и `FlexMLWrapperLoadResource`. Это отрицательный результат поиска в конкретном наборе, а не доказательство отсутствия этих классов в игре.

При этом обнаружены игровые скрипты, вызывающие потоковую загрузку миров и работу с анимационными ресурсами. В EXE обнаружены записи, связывающие имена `StreamWorlds`, `StreamWorldsWithSaveOverride`, `SetAnimationGraphResource`, `RemoveAnimationGraphResource` с конкретными адресами нативных функций. Одна из функций на отдельном условном пути вызывает адрес, также встречающийся в таблице `ResourceMgr2`. **Этот адрес содержит универсальное `return this+0x28` и повторяется в других местах EXE; поэтому это не доказательство вызова именно объекта `ResourceMgr2`.**

Ни скрипты, ни игра не запускались. Это не полное восстановление нативной реализации и не доказательство того, что каждое действие Lua проходит через эту секцию.

## 1. Проверенные материалы и воспроизводимость

Снимок репозитория [FEAR3-DespairEngineLuaAPI](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/tree/4a7a7cf3d48f09dca446441d8af427f30556280d) зафиксирован на коммите `4a7a7cf3d48f09dca446441d8af427f30556280d`. ZIP codeload SHA-256: `1f3aa0fb555a8e2bbb05b04b6464aa49951416baaed568e5963440b6ea2b80e6`. Содержимое извлечённых 622 файлов проверено относительно ZIP. Снимок хранится локально в `external/lua-api/`, исключён из Git; upstream не указал лицензию.

Из них 271 файл — Lua в `recovered/`: 43 в boot и 228 в resources. Их SHA-256 совпали с полем `recovered_sha256` соответствующих upstream-манифестов. Upstream заявляет сравнение исполняемых деревьев с исходным байткодом; здесь оригинальный байткод не предоставлен и та проверка **не повторялась**. Указанное пользователем происхождение из `.dspack` не проверено по самим контейнерам. `luasense_decompiled.lua` — реконструкция API с заглушками, не реализация движка, что отдельно подчёркивает [README источника](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/blob/4a7a7cf3d48f09dca446441d8af427f30556280d/README.md).

Данные образца: `Resource.bin` SHA-256 `6e4679833292366db29855d40f4f32734028740291142b9d1ffc2e62cb7e9ec6`, EXE SHA-256 `caa1f80d49da5dbadee3b1a44c470a87ffcb6afa8c0ed24af01741a155c326c2`. Подробный побайтовый разбор — [предыдущий отчёт](../REPORT.md); статическое поведение методов — [FLOW_REPORT](../FLOW_REPORT.md).

```sh
# Только если локального снимка ещё нет; загрузка через Python, проверяется закреплённый SHA-256:
python tooling/fetch_lua_api.py
python tooling/correlate_lua_resource.py
```

Второй скрипт сверяет список/хеш каждого файла снимка с ZIP, хеши Lua с манифестами, хеши EXE и секции, затем заново создаёт таблицы. Содержимое третьего репозитория при этом не исполняется. Скрипт загрузки отказывается перезаписывать существующий снимок.

## 2. Полный поиск по установленному набору строк и RTTI

[`literal-summary.csv`](literal-summary.csv) содержит все **34** наблюдаемые NUL-терминированные строки из секции; [`literal-hits.csv`](literal-hits.csv) — все 764 найденных посимвольных вхождения в 271 восстановленный Lua-файл с путём, номером строки и байтовым смещением. Поиск точный, с учётом регистра, и включает комментарии, текстовые литералы и части более длинных идентификаторов. Он **не** является семантическим разбором Lua.

Наиболее специфичные строки секции — `ResourceBase`, `Resource\RequestHandle`, `WorkspaceItem`, `UniqueResource`, `uniqueResourceId`, `ResourceMgr2`, `dvdEmulationEnabled`, `ResourceLoaderJob`, `/flexml/by/stream/%i.%s`, `ResourceJob::Execute()` с начальным переводом строки, `FlexMLWrapperLoadResource`, `Resource\LoadRequest` — не найдены в выбранных скриптах целиком. `Resource` встречается 15 раз как подстрока в трёх скриптах; общие `name`, `file`, `params`, `items` и символы `/`, `:`, `\`, `::` тоже встречаются, но их совпадение не устанавливает связь с одинаковыми байтами секции.

[`rtti-class-matches.csv`](rtti-class-matches.csv) содержит все **19** уникальных коротких имён из 26 RTTI секции. Для каждого выполнен регистронезависимый поиск подстроки в каждом восстановленном Lua-файле и во всех 3 879 объектах `api/despair-api.json` (имя, сигнатура, call-tip и прочие поля). Результат — **0 файлов и 0 объектов API для каждого из 19 имён**. Nested-имена записаны короткой частью декорированного имени, например `FileMakerReceipt`; такой поиск шире поиска только по полному C++-имени, но не находит синонимы.

[`related-script-lines.csv`](related-script-lines.csv) — более широкий поиск `resource|stream|flexml` без учёта регистра: **74 строки в девяти файлах**. Среди них два файла о типе урона `Bullet Stream`; это ложные тематические совпадения. Остальные семь файлов анализируются ниже. Список содержит и комментарии/литералы, поэтому он не равен числу вызовов.

## 3. Что показывают восстановленные скрипты

### 3.1. Потоковая загрузка миров

- [boot: `StreamWorlds.lua`, строки 1–19](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/blob/4a7a7cf3d48f09dca446441d8af427f30556280d/recovered/boot/script/game/Common/StreamWorlds.lua#L1-L19): регистрируются переменные `Desired Worlds` и `Required Worlds`. Восстановленная функция вызывает `GameScript.Game.StreamWorlds` с их именами, затем при включённом `save` вызывает `SaveGame`. При положительном `DelayTime` вызов ставится на таймер, иначе выполняется сразу.
- [resources: `StreamWorldsOnRegion.lua`, строки 1–33](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/blob/4a7a7cf3d48f09dca446441d8af427f30556280d/recovered/resources/EXTRACTresources/Script/Game/Common/StreamWorldsOnRegion.lua#L1-L33): тот же вызов инициируется при входе в регион; возможна проверка присутствия всех игроков, таймер и снятие обработчика.
- [resources: вариант с задержкой сохранения](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/blob/4a7a7cf3d48f09dca446441d8af427f30556280d/recovered/resources/EXTRACTresources/Script/Game/Common/StreamWorldsOnRegion_SaveDelay.lua#L1-L37): после `StreamWorlds` сохранение при включённой опции ставится отдельным таймером; значение `SaveDelay` по умолчанию в скрипте — `0.1`.
- [resources: `RiftsDirector.lua`, строки 197–257](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/blob/4a7a7cf3d48f09dca446441d8af427f30556280d/recovered/resources/EXTRACTresources/Script/Game/MP/Rifts/RiftsDirector.lua#L197-L257): наборы требуемых и желаемых миров изменяются между волнами. Используется `GS.Game.StreamWorldsWithSaveOverride(..., false)`; если желаемые миры ещё загружаются, предусмотрен повторный таймер.
- [resources: `LevelTransition_AfterSummary.lua`, строки 27–44](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/blob/4a7a7cf3d48f09dca446441d8af427f30556280d/recovered/resources/EXTRACTresources/Script/Game/Common/LevelTransition_AfterSummary.lua#L27-L44): после события завершения ролика или по другой ветке вызывается `GameScript.Game.ShowIntroLoadingMovieAndStreamWithMenu(nextLevelIndex, transitionMenu)`.

[Подсказки API](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/blob/4a7a7cf3d48f09dca446441d8af427f30556280d/docs/reference/GameScript.Game.md#L5427-L5500) описывают приоритет `RequiredWorlds`, ожидание требуемых миров и выгрузку тех, которые отсутствуют в списках. Это **утверждения call-tip из справочника**, не независимо проверенное здесь поведение; тела нативных функций целиком не восстановлены.

### 3.2. Анимационные ресурсы

- [resources: `AISpawnerIntroAnimaton.lua`, строки 11–15, 24–35, 50–63](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/blob/4a7a7cf3d48f09dca446441d8af427f30556280d/recovered/resources/EXTRACTresources/Script/Game/ai/AISpawnerIntroAnimaton.lua#L11-L63): регистрируется переменная анимационного графа; при спавне вызывается `SetAnimationGraphResource`, а `Done` вызывает `RemoveAnimationGraphResource` и удаление объекта из набора.
- [resources: `AISpawnerIntroAnimaton_Event.lua`, строки 11–62](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/blob/4a7a7cf3d48f09dca446441d8af427f30556280d/recovered/resources/EXTRACTresources/Script/Game/ai/AISpawnerIntroAnimaton_Event.lua#L11-L62): аналогичная регистрация и вызовы с дополнительной логикой событий.
- [resources: `RiftsDirector.lua`, строки 542–588](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/blob/4a7a7cf3d48f09dca446441d8af427f30556280d/recovered/resources/EXTRACTresources/Script/Game/MP/Rifts/RiftsDirector.lua#L542-L588): граф ставится при определённых условиях, а при событии завершения вызывается удаление. Его имя регистрируется в том же файле на строках 24 и 80.

[Call-tip `RegisterAnimationGraphResourceVariable`](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/blob/4a7a7cf3d48f09dca446441d8af427f30556280d/docs/reference/GameScript.Support.md#L1330-L1361) содержит и слова про animation resource, и формулировки про movie resource. Это внутренне неоднозначный исходный текст; здесь он не исправляется догадкой и не принимается как доказательство типа объекта.

## 4. Мост между именами Lua API и нативным EXE

Полные машинные байты отрывков — в [`native-bridge-asm.txt`](native-bridge-asm.txt). Точные строки имён ниже лежат в секции **Game_dat**, не в самой `Resource`.

| Имя в EXE | Предпочитаемый VA строки | Инструкции, передающие имя и адрес кода | Переданный адрес функции |
|---|---:|---:|---:|
| `StreamWorlds` | `0x18788A8` | `0x127F9CE–0x127F9E4` | `0xC316A0` |
| `StreamWorldsWithSaveOverride` | `0x1878888` | `0x127FA01–0x127FA17` | `0x9DA070` |
| `SetAnimationGraphResource` | `0x1878CBC` | `0x127F197–0x127F1AD` | `0x93CC90` |
| `RemoveAnimationGraphResource` | `0x1878C78` | `0x127F1F7–0x127F20D` | `0x436020` |

В первых трёх случаях отдельно просмотрены функции создания дескрипторов. Например, вызываемая `0x82C4A0` сохраняет первый аргумент (адрес имени) в `[созданный_объект+0x10]`, а второй (адрес `0xC316A0`) — в `[созданный_объект+0x20]`. Тот же шаблон виден для `0x4A2D30` и `0x67B820`. После создания первый вызывающий участок передаёт результат дальше в `0x77AC20`. Это сильное статическое свидетельство связывания имени с функцией; точный алгоритм поиска Lua-пути во время работы и фактическая доступность в игре не проверены. Совпадение имени с API и скриптом само по себе не доказывает, что конкретный Lua-вызов был выполнен.

### 4.1. `StreamWorlds` и общий accessor

`0xC316A0` принимает два аргумента, дополнительно помещает на стек ноль и на `0xC316AC` вызывает `0x9DA070` — адрес, который отдельно передаётся рядом с именем `StreamWorldsWithSaveOverride`. Это наблюдаемая общая цепочка кода; предположение о смысле третьего нуля на основании имени не заменяет проверку конкретной ABI/реализации.

В `0x9DA070` есть условный путь к вызову `0xC2D6F0` на `0x9DA1DC`; более ранние ветки на `0x9DA0BD`, `0x9DA0C7`, `0x9DA0F0` и `0x9DA0FA` ведут на другие участки, завершающиеся возвратом, минуя этот вызов. `0xC2D6F0` состоит из `lea eax, [ecx+0x28]; ret`. Тот же адрес хранится в слове `Resource+0x5F4`, следующем за RTTI `ResourceMgr2`. Функция возвращает адрес поля текущего ECX, **не выполняет загрузку ресурсов сама по себе**.

Почему нельзя считать это доказательством вызова именно `ResourceMgr2`:

1. В `0x9DA1DA` в ECX передаётся EBX. На показанном пути EBX перезаписывается результатом вызова `0xD12950` на `0x9DA106`; тип полученного объекта в данном анализе не установлен.
2. Поиск сырых четырёх байтов адреса `0xC2D6F0` на любом выравнивании обнаружил **46 совпадений** в EXE, в том числе в `Game_dat`, `GameAI_d`, `Device` и других секциях. Их список — [`shared-accessor-u32-occurrences.csv`](shared-accessor-u32-occurrences.csv). Попадание байтов — не автоматическое доказательство указателя.
3. Поиск шаблонов `E8 rel32`, численно направленных на тот же адрес, дал **292 кандидата** в `.text` ([CSV](shared-accessor-e8-candidates.csv)). Это сырые шаблоны, среди них могут быть совпадения внутри данных или других инструкций; все 292 границы независимо не подтверждены.

Следовательно, доказаны **общая нативная цель** и условный прямой вызов; конкретный экземпляр менеджера, виртуальная диспетчеризация из этой ветки и связь с каждым Lua-сценарием остаются открытыми.

### 4.2. Анимационный граф и константа перехода

Точка `0x93CC90`, переданная рядом с именем `SetAnimationGraphResource`, загружает `float32` из `0x145B2D0`, передаёт его вместе с аргументами в `0x7681F0` и возвращается. Точка `0x436020`, переданная рядом с `RemoveAnimationGraphResource`, загружает тот же `float32` и вызывает `0xA34E10`. Сырые байты константы — `CD CC 4C 3E`, IEEE-754 binary32 ≈ **0.200000003**. [Call-tip SetAnimationGraphResource](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/blob/4a7a7cf3d48f09dca446441d8af427f30556280d/docs/reference/GameScript.Game.md#L3821-L3856) и [call-tip RemoveAnimationGraphResource](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/blob/4a7a7cf3d48f09dca446441d8af427f30556280d/docs/reference/GameScript.Game.md#L3225-L3255) описывают стандартный переход в 0,2 секунды. Это согласуется со значением и фактом передачи в коде, но без полного анализа вызываемых функций не доказывает, как параметр применяется во всех ветках и на работающей игре.

## 5. Каталог API и редакторы

[`api-name-candidates.csv`](api-name-candidates.csv) перечисляет все **455** путей из 3 879, в имени которых есть `resource`, `stream` или `flexml` без учёта регистра: 429 путей начинаются с `Despair.` (включая инструменты), 13 с `GameScript.`, ещё 13 — другие пути/алиасы. Это фильтр по именам, а **не 455 связей с `Resource.bin`**, не число реализаций и не доказательство доступности редакторских функций в релизной игре.

Например, [call-tip `Despair.Forge.AutomationUtility.IsFlexML`](https://github.com/foursecondfivefour/FEAR3-DespairEngineLuaAPI/blob/4a7a7cf3d48f09dca446441d8af427f30556280d/docs/reference/Despair.Forge.AutomationUtility.md#L327-L347) описывает проверку формата ресурса. Это тематически согласуется с названием `FlexMLWrapperLoadResource` и строкой формата в секции, но прямой цепочки вызовов между редакторской командой и этим классом не найдено. То же относится к многочисленным `ResourceView`.

## 6. Доказано / не доказано

**Доказано статическими данными:** сохранённый EXE содержит ранее идентифицированную секцию; все проверенные скрипты и справочник соответствуют зафиксированному снимку; указанные имена и пары адресов присутствуют в данном EXE; показанные прямые вызовы и передачи аргументов соответствуют машинным инструкциям.

**Не доказано:** что исходный EXE является именно той сборкой, из которой получен Lua-байткод; что API-снимок полон; что каждый скрипт вызывает `ResourceMgr2`, `RenameStream` или другой конкретный класс из секции; семантика всех полей, все пути обработки ошибок, точная загрузка `.dspack` и поведение во время запуска. Чтобы продвинуться дальше, нужны исходные чанки и подтверждение сборки, анализ остальной нативной цепочки/косвенных вызовов и при необходимости изолированная runtime-трассировка. Слово «полностью» здесь возможно только для заявленного набора буквальных поисков, не для поведения всего движка.
