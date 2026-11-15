# Найденные классы и структуры, связанные со скриптами

Основной [отчёт и методика](REPORT.md). Это извлечённые имена RTTI C++, не исходный код Lua. Выборка включает простые имена с точным фрагментом `Script` или `Lua`, в том числе вложенные имена; ActionScript вынесен отдельно. Имена не гарантируют наличие в Lua или выполнение в игре. Прочие 949 шаблонных и сложных RTTI, где упоминаются `Script`/`Lua`, см. `script-related-rtti.csv`; они не добавляются сюда как отдельные классы их параметров.

Всего простых RTTI-типов: **149**. Адрес — preferred VA строки имени; type descriptor находится на 8 байтов раньше. `COL / vtable` — числа структурных кандидатов, не подтверждение runtime-использования.

## GameScript (35)

| Имя | Тип | VA строки RTTI | COL / vtable кандидаты |
|---|---|---:|---:|
| `Despair::GameScriptAudio` | class | `0x172AF94` | 2 / 2 |
| `Despair::GameScriptCallbacks` | class | `0x16518F8` | 2 / 2 |
| `Despair::GameScriptCamera` | class | `0x171178C` | 2 / 2 |
| `Despair::GameScriptDeath` | class | `0x16C95BC` | 2 / 2 |
| `Despair::GameScriptDebug` | class | `0x17190EC` | 2 / 2 |
| `Despair::GameScriptDebugArrow` | class | `0x163DE20` | 1 / 1 |
| `Despair::GameScriptDebugHelper` | class | `0x16866D8` | 1 / 1 |
| `Despair::GameScriptDebugInTool` | class | `0x16530F0` | 2 / 2 |
| `Despair::GameScriptDebugLine` | class | `0x16DC128` | 1 / 1 |
| `Despair::GameScriptDebugSphere` | class | `0x172AAA4` | 1 / 1 |
| `Despair::GameScriptDoor` | class | `0x162AD98` | 2 / 2 |
| `Despair::GameScriptEmptyNamespace` | class | `0x1722120` | 2 / 2 |
| `Despair::GameScriptEnergy` | class | `0x16FC584` | 2 / 2 |
| `Despair::GameScriptFEAR` | class | `0x165F7D0` | 2 / 2 |
| `Despair::GameScriptFEARScore` | class | `0x1631D78` | 2 / 2 |
| `Despair::GameScriptGame` | class | `0x16DBFFC` | 2 / 2 |
| `Despair::GameScriptGlobalDataComponent` | class | `0x174B2C8` | 4 / 4 |
| `Despair::GameScriptGlobalDataComponent::GameScriptLibrary` | class | `0x170F5B0` | 1 / 1 |
| `Despair::GameScriptGraphics` | class | `0x16C39EC` | 2 / 2 |
| `Despair::GameScriptMgr` | class | `0x16A1914` | 3 / 3 |
| `Despair::GameScriptMP` | class | `0x1677B10` | 2 / 2 |
| `Despair::GameScriptNonProduction` | class | `0x165FFA0` | 2 / 2 |
| `Despair::GameScriptObjectives` | class | `0x17276A0` | 2 / 2 |
| `Despair::GameScriptObjectTags` | class | `0x17278DC` | 2 / 2 |
| `Despair::GameScriptPhysics` | class | `0x165E770` | 2 / 2 |
| `Despair::GameScriptPlayer` | class | `0x169B420` | 2 / 2 |
| `Despair::GameScriptPlayerInTool` | class | `0x16B424C` | 2 / 2 |
| `Despair::GameScriptReflector` | class | `0x16B1084` | 2 / 2 |
| `Despair::GameScriptRegions` | class | `0x1726F04` | 2 / 2 |
| `Despair::GameScriptSets` | class | `0x1634C44` | 2 / 2 |
| `Despair::GameScriptSupport` | class | `0x1725294` | 2 / 2 |
| `Despair::GameScriptSupportInTool` | class | `0x16B0994` | 2 / 2 |
| `Despair::GameScriptThread` | class | `0x1717EC4` | 1 / 1 |
| `Despair::GameScriptUtilities` | class | `0x16F179C` | 2 / 2 |
| `Despair::GameScriptUtilitiesInTools` | class | `0x17069D0` | 2 / 2 |

## GameAIScript (2)

| Имя | Тип | VA строки RTTI | COL / vtable кандидаты |
|---|---|---:|---:|
| `Despair::GameAIScriptActions` | class | `0x174DD70` | 2 / 2 |
| `Despair::GameAIScriptTargetInfo` | class | `0x162E85C` | 1 / 1 |

## Lua (5)

| Имя | Тип | VA строки RTTI | COL / vtable кандидаты |
|---|---|---:|---:|
| `Despair::LuaFunctionStack` | class | `0x1693A14` | 1 / 1 |
| `Despair::LuaScriptHost` | class | `0x1718384` | 2 / 2 |
| `Despair::LuaScriptHostMgr` | class | `0x174F3A4` | 2 / 2 |
| `Despair::LuaScriptTableInfo` | class | `0x16E0E20` | 1 / 1 |
| `Despair::LuaScriptThread` | class | `0x169C210` | 1 / 1 |

## Script и связанные типы (89)

| Имя | Тип | VA строки RTTI | COL / vtable кандидаты |
|---|---|---:|---:|
| `Despair::ADMScript` | class | `0x16C2EA0` | 2 / 2 |
| `Despair::AmmoPickupForCarrierMsgScriptTable` | class | `0x16483A8` | 1 / 1 |
| `Despair::CameraFilterGroupChangeMsgScriptTable` | class | `0x172BC9C` | 1 / 1 |
| `Despair::CollisionScriptObject` | class | `0x172BC48` | 1 / 1 |
| `Despair::ControllingGameCameraChangeScriptObject` | class | `0x16AC1A4` | 1 / 1 |
| `Despair::DamageMsgScriptTable` | class | `0x172BCD8` | 1 / 1 |
| `Despair::FlashlightStatusScriptObject` | class | `0x164D79C` | 1 / 1 |
| `Despair::Game::MissionSummaryScreenDisplayingMessageScriptObject` | class | `0x16D3D50` | 1 / 1 |
| `Despair::GameScriptFEAR::AnnoucementPacket` | class | `0x170D42C` | 1 / 1 |
| `Despair::HitPointDepletedMsgScriptTable` | class | `0x16A7294` | 1 / 1 |
| `Despair::IGameScriptMgr` | class | `0x171FB18` | 0 / 0 |
| `Despair::IScriptComponent` | class | `0x16F4AC4` | 1 / 1 |
| `Despair::IScriptDebugger` | class | `0x164A5E8` | 1 / 1 |
| `Despair::IScriptEventComponent` | class | `0x169EE58` | 1 / 1 |
| `Despair::IScriptHost` | class | `0x1665BC0` | 1 / 1 |
| `Despair::IScriptHostMgr` | class | `0x171729C` | 1 / 1 |
| `Despair::IScriptNetComponent` | class | `0x16B7934` | 1 / 1 |
| `Despair::IScriptOwner` | class | `0x17221D8` | 1 / 1 |
| `Despair::IScriptResource` | class | `0x162FC1C` | 2 / 2 |
| `Despair::IScriptTableInfo` | class | `0x16E8A70` | 1 / 1 |
| `Despair::IScriptThread` | class | `0x16BC42C` | 1 / 1 |
| `Despair::IScriptThreadMgr` | class | `0x16ACCFC` | 0 / 0 |
| `Despair::IScriptThreadReceipt` | class | `0x1671220` | 0 / 0 |
| `Despair::KillScriptObject` | class | `0x172BC74` | 1 / 1 |
| `Despair::LabelAnimationTagScriptObject` | class | `0x166BB94` | 1 / 1 |
| `Despair::MakerScript` | class | `0x16D3C38` | 1 / 1 |
| `Despair::MeleeFirstHitScriptTable` | class | `0x172BD04` | 1 / 1 |
| `Despair::MissionEventScriptObject` | class | `0x16BEA00` | 1 / 1 |
| `Despair::MovieScriptInfo` | class | `0x165C090` | 1 / 1 |
| `Despair::NetSyncScriptEventHelper` | class | `0x164D128` | 1 / 1 |
| `Despair::NetSyncScriptHelper` | class | `0x16DC918` | 1 / 1 |
| `Despair::ObjectInteractionScriptTable` | class | `0x167C9E8` | 1 / 1 |
| `Despair::ObjectStateChangeMsgScriptTable` | class | `0x16AFA40` | 1 / 1 |
| `Despair::PlayerCanPossessMsgScriptTable` | class | `0x16BDAC0` | 1 / 1 |
| `Despair::PlayerDeathScriptObject` | class | `0x167D29C` | 1 / 1 |
| `Despair::PlayerRegistrationScriptObject` | class | `0x16E93E4` | 1 / 1 |
| `Despair::PlayerRespawnRequestScriptObject` | class | `0x168A880` | 1 / 1 |
| `Despair::PlayerTransferControlScriptObject` | class | `0x1686ACC` | 1 / 1 |
| `Despair::PossessionAllowedMsgScriptTable` | class | `0x16EB1EC` | 1 / 1 |
| `Despair::PossessionEndedMsgScriptTable` | class | `0x17160D0` | 1 / 1 |
| `Despair::PossessionStartedMsgScriptTable` | class | `0x16C8C90` | 1 / 1 |
| `Despair::QueuedScriptAchievementsMessage` | class | `0x16B39EC` | 1 / 1 |
| `Despair::RayCollisionScriptObject` | class | `0x165B998` | 1 / 1 |
| `Despair::RegionCallbackScriptObject` | class | `0x16CF348` | 1 / 1 |
| `Despair::ScoreDeathScriptObject` | class | `0x16606E4` | 1 / 1 |
| `Despair::ScriptAchievementEvent` | class | `0x1662E54` | 1 / 1 |
| `Despair::ScriptApp` | class | `0x168E904` | 1 / 1 |
| `Despair::ScriptBoolVariable` | class | `0x16BB448` | 1 / 1 |
| `Despair::ScriptColorVariable` | class | `0x166F6A0` | 1 / 1 |
| `Despair::ScriptComponent` | class | `0x1639FB4` | 13 / 13 |
| `Despair::ScriptComponent::GameTimerCallback` | class | `0x16617B4` | 1 / 1 |
| `Despair::ScriptComponent::MsgCallback` | class | `0x17051C0` | 1 / 1 |
| `Despair::ScriptComponent::ObjectCallbackInfo` | class | `0x16562DC` | 1 / 1 |
| `Despair::ScriptComponent::SetTracker` | class | `0x16B02CC` | 2 / 2 |
| `Despair::ScriptDebugMgr` | class | `0x16F8730` | 1 / 1 |
| `Despair::ScriptDoorInfo` | class | `0x16431B4` | 1 / 1 |
| `Despair::ScriptEnumVariable` | class | `0x17227AC` | 1 / 1 |
| `Despair::ScriptEventComponent` | class | `0x172DCD4` | 7 / 7 |
| `Despair::ScriptEventComponent::ScriptEvent` | class | `0x172DC9C` | 1 / 1 |
| `Despair::ScriptEventVariable` | class | `0x16284E8` | 1 / 1 |
| `Despair::ScriptExternalStartCondition` | class | `0x1631F88` | 4 / 4 |
| `Despair::ScriptFloatVariable` | class | `0x1722780` | 1 / 1 |
| `Despair::ScriptGlobalObjectComponent` | class | `0x165ABBC` | 13 / 13 |
| `Despair::ScriptIntersectRayOutput` | class | `0x1658C10` | 1 / 1 |
| `Despair::ScriptNetComponent` | class | `0x16364FC` | 5 / 5 |
| `Despair::ScriptNetSharedData` | class | `0x162E88C` | 2 / 2 |
| `Despair::ScriptObjectHandleVariable` | class | `0x1631C6C` | 1 / 1 |
| `Despair::ScriptObjectListVariable` | class | `0x1681EF0` | 1 / 1 |
| `Despair::ScriptPlayerDamageHistory` | class | `0x16750D0` | 1 / 1 |
| `Despair::ScriptPlayerFilterSetValues` | class | `0x16BD3AC` | 1 / 1 |
| `Despair::ScriptRayDistanceOutput` | class | `0x172294C` | 1 / 1 |
| `Despair::ScriptRegionInfo` | class | `0x16D6250` | 1 / 1 |
| `Despair::ScriptResource` | class | `0x16ACAFC` | 2 / 2 |
| `Despair::ScriptResourceInfo` | class | `0x16B72F0` | 1 / 1 |
| `Despair::ScriptSharedData` | class | `0x16B50A8` | 2 / 2 |
| `Despair::ScriptStaticTextVariable` | class | `0x1667E80` | 1 / 1 |
| `Despair::ScriptStringVariable` | class | `0x16B774C` | 1 / 1 |
| `Despair::ScriptThreadMgr` | class | `0x174F3CC` | 1 / 1 |
| `Despair::ScriptThreadReceipt` | class | `0x1651E14` | 1 / 1 |
| `Despair::ScriptVariable` | class | `0x167DD94` | 1 / 1 |
| `Despair::ScriptVectorVariable` | class | `0x170EA84` | 1 / 1 |
| `Despair::ScriptWatchVariable` | class | `0x1637564` | 1 / 1 |
| `Despair::ScriptWatchVariableCallbackMsg` | class | `0x162ED90` | 1 / 1 |
| `Despair::SpawnerScriptObject` | class | `0x17112B8` | 1 / 1 |
| `Despair::SuspendTargetDamageMsgScriptTable` | class | `0x1702994` | 1 / 1 |
| `Despair::TextScriptObject` | class | `0x172BD34` | 1 / 1 |
| `Despair::UI::ScriptMovieInstanceHandle` | class | `0x1707A1C` | 3 / 3 |
| `Despair::UI::ScriptMovieResourceHandle` | class | `0x1743AA8` | 3 / 3 |
| `Despair::UsableStartUsingScriptObject` | class | `0x172BD5C` | 1 / 1 |

## ActionScript / Scaleform / UI (18)

| Имя | Тип | VA строки RTTI | COL / vtable кандидаты |
|---|---|---:|---:|
| `Despair::ActionScriptInvokeMessage` | class | `0x16F6B04` | 1 / 1 |
| `Despair::Scaleform::ActionScriptFunctionStack` | class | `0x162BF54` | 1 / 1 |
| `Despair::Scaleform::IActionScriptFunctionStack` | class | `0x1742228` | 1 / 1 |
| `Despair::Scaleform::IScriptInstanceMgr` | class | `0x16DF224` | 1 / 1 |
| `Despair::Scaleform::IScriptMovieInstance` | class | `0x16BDCA8` | 2 / 2 |
| `Despair::Scaleform::IScriptMovieResource` | class | `0x16F764C` | 2 / 2 |
| `Despair::Scaleform::ScriptInstanceMgr` | class | `0x167EE44` | 2 / 2 |
| `Despair::Scaleform::ScriptInstanceRegisterDelegate` | class | `0x16783B0` | 1 / 1 |
| `Despair::Scaleform::ScriptInstanceUnregisterDelegate` | class | `0x16A3940` | 1 / 1 |
| `Despair::Scaleform::ScriptMovieInstance` | class | `0x16CCDBC` | 3 / 3 |
| `Despair::Scaleform::ScriptMovieInstance::RegisterMethodReceipt` | class | `0x1742268` | 1 / 1 |
| `Despair::Scaleform::ScriptMovieResource` | class | `0x1657568` | 2 / 2 |
| `Despair::Scaleform::ScriptMovieResource::InstanceMgrReceipt` | class | `0x167E678` | 1 / 1 |
| `Despair::Scaleform::ScriptReceipt` | class | `0x16B6058` | 1 / 1 |
| `Despair::UI::ActionScriptFunctionStackReference` | class | `0x162F2DC` | 1 / 1 |
| `Despair::UI::ActionScriptVariableReference` | class | `0x1743E8C` | 2 / 2 |
| `Despair::UI::IActionScriptFunctionStackReference` | class | `0x1632A14` | 1 / 1 |
| `Despair::UI::IActionScriptVariableReference` | class | `0x1743E54` | 1 / 1 |

## Дополнительные кандидаты из имён шаблонов

Ниже только имена, извлечённые эвристикой из декорированных RTTI других типов; отдельный простой type descriptor с тем же коротким именем не найден. Пространство имён и даже границы типа могут требовать ручного подтверждения; `V`/`U` — сырой маркер в сигнатуре, не доказательство определённого класса.

| Возможное имя | Маркер | Вхождения | Пример VA родительского RTTI |
|---|---|---:|---:|
| `ScriptAABB` | `U` | 4 | `0x1630800` |
| `ScriptContractionsFogValues` | `V` | 3 | `0x164BCB0` |
| `ScriptDamageInfo` | `U` | 14 | `0x1660E80` |
| `ScriptDisplayTextInfo` | `V` | 3 | `0x1652EC8` |
| `ScriptEnvLightValues` | `V` | 7 | `0x1623098` |
| `ScriptFlashlightFlickerInfo` | `U` | 3 | `0x1669488` |
| `ScriptFogValues` | `V` | 3 | `0x167A930` |
| `ScriptIntersectRayInput` | `U` | 9 | `0x16295B8` |
| `ScriptTimedCurveValues` | `V` | 3 | `0x1637E18` |
