
# RSS-AmCache / Update 21.04.2026

<p align="center">
  <a href="#ru"><img alt="Русский" src="https://img.shields.io/badge/Русский-Read-1f6feb?style=for-the-badge" /></a>
  <a href="#en"><img alt="English" src="https://img.shields.io/badge/English-Read-1f6feb?style=for-the-badge" /></a>
</p>

<p align="center">
  <a href="https://github.com/Jumarf123/RSS-AmCache/releases/download/1.0/rss-amcache.exe">
    <img alt="Download RSS-AmCache" src="https://img.shields.io/badge/Скачать%20%2F%20Download-RSS--AmCache.exe-2ea043?style=for-the-badge&logo=github&logoColor=white" />
  </a>
</p>

<p align="center">
  <img alt="Windows" src="https://img.shields.io/badge/Platform-Windows-2ea043?style=flat-square" />
  <img alt="GUI" src="https://img.shields.io/badge/Type-GUI%20Utility-0969da?style=flat-square" />
  <img alt="Amcache" src="https://img.shields.io/badge/Source-Amcache-8250df?style=flat-square" />
  <img alt="YARA" src="https://img.shields.io/badge/Scanner-YARA-b7410e?style=flat-square" />
  <img alt="Languages" src="https://img.shields.io/badge/UI-RU%20%2B%20EN-5865F2?style=flat-square" />
</p>

<p align="center">
  Утилита с графическим интерфейсом для парсинга <b>Amcache</b> и проверки найденных файлов по встроенным <b>YARA</b> правилам.
</p>

---

## Navigation

- [Русский](#ru)
- [English](#en)

---

<a name="ru"></a>
## Русский

### Что это

`RSS-AmCache` — GUI-утилита для анализа данных `Amcache` с последующей проверкой найденных файлов по встроенным `YARA` правилам.

Программа ориентирована на быстрый просмотр результатов: после запуска она автоматически выполняет парсинг и сканирование, а затем показывает найденные записи в удобной таблице.

### Возможности

- Парсинг данных `Amcache`
- Проверка найденных файлов по встроенным `YARA` правилам
- Удобная таблица результатов
- Поиск по записям
- Фильтрация по дате
- Фильтрация по статусу удаления
- Отдельный фильтр для показа только записей с детектом
- Экспорт результатов
- Поддержка русского и английского языка интерфейса

### Быстрый старт

Запустите файл:

```powershell
.\rss-amcache.exe
```

или просто откройте:

```text
rss-amcache.exe
```

После запуска приложение автоматически начнёт парсинг и сканирование, а затем отобразит результаты в интерфейсе.

### Работа с результатами

В интерфейсе доступны:

* сортировка записей
* поиск по таблице
* фильтрация по дате
* фильтрация по удалённым файлам
* просмотр только тех файлов, по которым есть срабатывание
* экспорт полученных результатов

### Требования

* Windows

### Скачать

* **Download:** [rss-amcache.exe](https://github.com/Jumarf123/RSS-AmCache/releases/download/1.0/rss-amcache.exe)


---

<a name="en"></a>

## English

### What it is

`RSS-AmCache` is a GUI utility for parsing `Amcache` data and checking discovered files against embedded `YARA` rules.

The tool is designed for quick review: after launch, it automatically starts parsing and scanning, then displays the results in a convenient table-based interface.

### Features

* `Amcache` parsing
* Embedded `YARA` scanning for discovered files
* Convenient results table
* Search across records
* Date-based filtering
* Deleted-file filtering
* Dedicated filter for entries with detections only
* Export of results
* Russian and English UI support

### Quick start

Run:

```powershell
.\rss-amcache.exe
```

or simply open:

```text
rss-amcache.exe
```

After launch, the application will automatically begin parsing and scanning, then show the results in the interface.

### Working with results

The interface includes:

* record sorting
* table search
* date filtering
* deleted-file filtering
* view only files with detections
* export of collected results

### Requirements

* Windows

### Download


* **Download:** [rss-amcache.exe](https://github.com/Jumarf123/RSS-AmCache/releases/download/1.0/rss-amcache.exe)




