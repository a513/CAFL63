Для создания исполняемого файла приложения CAFL63 используктся
tcl-враппер tclexecomp (версия 1.0.4 и выше, http://tclexecomp/sourceforge.net).
Сборка для Android ведется на Androwish (https://www.androwish.org).

Необходимо также скачать пакет/библиотеку TclPKCS11 (https://github.com/a513/TclPKCS11).
Необходимо также скачать пакет tkfe (https://github.com/a513/TkFileExplorer).

Необходимо скачать соответствующие врапперы, настроить скрипты BUILD и выполнить их.
Например:

$BUILD_BIN_CAFL63_FOR_LINUX.sh 32

$BUILD_BIN_CAFL63_FOR_WIN_UTF8.sh 64

Цифры 32 и 64 определяют разряднось платформы, для которой собирается дистрибутив.