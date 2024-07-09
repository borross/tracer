![image](https://github.com/borross/tracer/assets/39199196/edb2c62c-052c-440c-868e-8ea020b8c58e)

# tracer
Утилита (скрипт) была написана для получения возможности обогощать событие по значению поля со сторонних систем с использованием языка программирования Python3. Tracer.py мимикрирует под механизм обогащения аналогично CyberTrace, с обогащенными данными можно работать подобно обогащению Threat Intelligence. Утилита может работать как на Linux (рекомендуется), так и Windows платформах (ОС).

Необходимые библиотеки для работы Tracer.py:
- import socket
- from select import select
- from sys import platform, exit
- from re import match, compile, search, error
- from datetime import datetime
- from optparse import OptionParser
- from urllib.parse import unquote
- from os.path import isfile, splitext, getsize
- from csv import DictReader
- from json import load, loads, dumps
- import pickle
- import logging

Для использования TCP_FASTOPEN (рекомендуется) на ОС Linux выполните команду ниже и переиспользование портов:
- echo 3 > /proc/sys/net/ipv4/tcp_fastopen
- echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse

Предварительные правки для Tracer.py:
- SERVER = "127.0.0.1" (строка кода 26) - укажите IP-адрес для прослушивания
- PORT = 16666 (строка кода 27) - укажите порт для прослушивания

## Режимы работы:
- Custom Mode (Режим пользовательских функций, по умолчанию, mode == 0): Позволяет использовать собственные функции для обогащения данных. Обогащение данными производится в строках 162-183 (mode == 0), в этой секции можете использовать произвольное обогащение данными, в коде есть примеры двух тестовых обогащений.
- Feed File Mode (Режим загрузки файла, mode == 1): Загружает данные из указанного файла(ов) JSON или CSV для обогащения. Пример: `python3 Tracer.py -f /root/tracer/example.csv -k ioc` или `python3 Tracer.py -f /root/tracer/example.json -k mask`. Примеры файлов рядом со скриптом. Для масок URL заполняется отдельный словарь с регулярными выражениями по маске.
- Dump Feed Mode (Режим дампа данных, mode == 2): Сохраняет данные в файл с расширением .tracer для последующего использования. Пример: `python3 Tracer.py -d /root/tracer/Phishing_URL_Data_Feed.json -k mask` или `python3 Tracer.py -d Malicious_Hash_Data_Feed.json -k MD5`
- Load Feed Mode (Режим загрузки данных, mode == 3): Загружает данные из нескольких файлов с расширением .tracer для обогащения. Пример: `python3 Tracer.py -l IP_Reputation_Data_Feed.json.tracer -l Phishing_URL_Data_Feed.json.tracer -l Malicious_Hash_Data_Feed.json.tracer`

Все действия сервера логируются в файл `Tracer.log` для отслеживания и анализа работы сервера.


На стороне KUMA нужно прописать следующее обогащение:
![image](https://github.com/borross/tracer/assets/39199196/ecbae16d-638b-4236-a809-fffd06ec7963)

По картинке выше, обогащается значение поля Code и сопоставляется с полем Tracer - url. Производительность скрипта состовляет ~ 50 EPS, при рекомендуемой настройке Enrichment (количество подключений): 50 connections и 50 RPS (запросов в секунду). Если использовать в пропорции 500 / 500, то можно обогащать максимально 500 EPS событий без потерь.

Возможно использовать только поле url в сопоставлении, но туда можно поместить произвольные данные

При обогащении события получаем следующие обогащенные данные:

![image](https://github.com/borross/tracer/assets/39199196/4935e2c5-b7fc-4c06-a57e-de7920e98085)

При обогащении нескольких индикаторов из события получаем следующее обогащенные данные:

![image](https://github.com/borross/tracer/assets/39199196/c324dec1-8902-4bf0-9663-a8be87bc2187)

Так как используется "нелегальный" механизм обогащения в логах коллектора копятся (периодически очищайте) ошибки следующего вида:

![image](https://github.com/borross/tracer/assets/39199196/783bd530-956f-4634-8a4b-2af4dd41a126)


