Задание 4. Кэширующий DNS сервер
Сервер запущен на ip-адресе 127.0.0.1 на локальном хосте. Чтобы обратиться к нему, нужно в вызове команды lookup указать его ip-адрес.
При запуске инициализирует свой кэш из данных, которые лежат в файле. Периодически проверяет кэш и очищает записи, TTL которых истек.
При выключении сервера сериализует данные из кэша в файл.