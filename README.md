# Tinkoff-backend-academy
## Присутствует демо сервер на который наш Hub умного дома отправляет запросы, получая в ответ команды с логикой взаимодействия устройств в сети умного дома. Hub должен отправлять команды на сервер в зависимости от поступивших команд.
## По сети передаются пакеты в бинарном формате, закодированные в Base64, поступают только значения полей json формата (значения могут быть закодированы через Uleb128)
## Примеры пакетов
Ниже приведены примеры пакетов в base64 для всех возможных пар из типа устройства и команды.

SmartHub, WHOISHERE (1, 1): DAH_fwEBAQVIVUIwMeE</br>
SmartHub, IAMHERE (1, 2): DAH_fwIBAgVIVUIwMak</br>
EnvSensor, WHOISHERE (2, 1): OAL_fwMCAQhTRU5TT1IwMQ8EDGQGT1RIRVIxD7AJBk9USEVSMgCsjQYGT1RIRVIzCAAGT1RIRVI03Q</br>
EnvSensor, IAMHERE (2, 2): OAL_fwQCAghTRU5TT1IwMQ8EDGQGT1RIRVIxD7AJBk9USEVSMgCsjQYGT1RIRVIzCAAGT1RIRVI09w</br>
EnvSensor, GETSTATUS (2, 3): BQECBQIDew</br>
EnvSensor, STATUS (2, 4): EQIBBgIEBKUB4AfUjgaMjfILrw</br>
Switch, WHOISHERE (3, 1): IgP_fwcDAQhTV0lUQ0gwMQMFREVWMDEFREVWMDIFREVWMDO1</br>
Switch, IAMHERE (3, 2): IgP_fwgDAghTV0lUQ0gwMQMFREVWMDEFREVWMDIFREVWMDMo</br>
Switch, GETSTATUS (3, 3): BQEDCQMDoA</br>
Switch, STATUS (3, 4): BgMBCgMEAac</br>
Lamp, WHOISHERE (4, 1): DQT_fwsEAQZMQU1QMDG8</br>
Lamp, IAMHERE (4, 2): DQT_fwwEAgZMQU1QMDGU</br>
Lamp, GETSTATUS (4, 3): BQEEDQQDqw</br>
Lamp, STATUS (4, 4): BgQBDgQEAaw</br>
Lamp, SETSTATUS (4, 5): BgEEDwQFAeE</br>
Socket, WHOISHERE (5, 1): DwX_fxAFAQhTT0NLRVQwMQ4</br>
Socket, IAMHERE (5, 2): DwX_fxEFAghTT0NLRVQwMc0</br>
Socket, GETSTATUS (5, 3): BQEFEgUD5A</br>
Socket, STATUS (5, 4): BgUBEwUEAQ8</br>
Socket, SETSTATUS (5, 5): BgEFFAUFAQc</br>
Clock, IAMHERE (6, 2): Dgb_fxUGAgdDTE9DSzAxsw</br>
Clock, TICK (6, 6): DAb_fxgGBpabldu2NNM</br>
