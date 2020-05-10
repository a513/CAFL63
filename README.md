# CAFL63
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome 
to redistribute it under certain conditions. 
See the file COPYING for details.\n
	
Приложение CAFL63 предназначено для создания Удостоверяющих Центров (УЦ) и 
выпуска цифровых сертификатов. 
Приложение разрабатывалось с учетом требованиям ФЗ-63 и регулятора и ориентировано
прежде всего на поддержку российской криптографии.
В качестве СКЗИ используются криптография openssl и токены/смарткарты PKCS#11  с российской криптографией.

Это программное обеспечение доступно в терминах
GNU General Public License.

Приложение работает на платформах Linux, OS X, Windows, Android и др.
Приложение разрабатывалось на Си и Tcl/Tk.
На Си разработан пакет [TclPKCS11](https://github.com/a513/TclPKCS11),
используемый для поддержки токенов/смарткарт PKCS#11

Для создания исполняемого файла приложения CAFL63 используется
tcl-враппер [tclexecomp](http://tclexecomp/sourceforge.net)

Сборка для Android ведется на [Androwish](https://www.androwish.org).

Автор - [Орлов Владимир](http://museum.lissi-crypto.ru/)

Email: vorlov@lissi.ru
Copyright(C) [LISSI-Soft Ltd](http://soft.lissi.ru) 2017-2020
