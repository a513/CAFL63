echo "./BUILD_BIN_P11CONFGUI_FOR_WIN32_COPY.sh 32|64"
bb=$1
if [ ${bb:=0 } -eq 0   ]
    then 
	echo "Bad type 32|64"
	exit 1
fi
if [ $1 -ne 64  -a $1 -ne 32 ]
    then 
	echo "Bad type 32|64"
	exit 1
fi
a=WIN32_WRAP664
rm -f lirssl_static.exe
cp -f lirssl_static_win32.exe lirssl_static.exe
if [ "$1" -eq "64 " ]
    then a=WIN64_WRAP664
	a=WIN64_WRAP664
	rm -f lirssl_static.exe
	cp -f lirssl_static_win64.exe lirssl_static.exe
fi
echo $a
rm -f tclpkcs11.dll
cp -f tclpkcs11_win$1.dll ./tclpkcs11.dll
if [ "$1" -eq "64 " ]
    then 
	bs1=1173666
fi
if [ "$1" -eq "32 " ]
    then 
	bs1=1060514
fi
bs2=`expr $bs1 + 4286`
echo "bs1=$bs1"
echo "bs2=$bs2"

if [ "$1" -eq "32 " ]
    then 
	dd if=../WRAP_MAC/tclexecomp_v.1.0.4.win$1 of=tclexecomp.part1 skip=0 bs=$bs1 count=1
	dd if=../WRAP_MAC/tclexecomp_v.1.0.4.win$1 of=tclexecomp.part2 bs=$bs2 skip=1 
#cat tclexecomp.part1 icon_p7_32x32_32.ico.bin tclexecomp.part2 > tclexecompfull_win32.exe
	cat  iconCert_32x32_tclexec.ico tclexecomp.part2 >>tclexecomp.part1
	mv tclexecomp.part1 tclexecompfull_win$1.exe
	rm -f tclexecomp.part2
	cp -f tcltls_win$1.dll ./tcltls$1.dll
../WRAP_MAC/tclexecomp64_v.1.0.4 maincafl63.tcl CAFL63_PACK_STYLE.tcl tkfe.tcl breeze.tcl cert2text.tcl alloids.tcl ascii.enc cp1251.enc lirssl_static.exe tcltls$1.dll tclpkcs11.dll orlov_250x339.png -i iconCert.ico -w tclexecompfull_win$1.exe -forcewrap -forcewrap -o CAFL63_win$1.exe
	rm -f  tcltls$1.dll
fi
if [ "$1" -eq "64 " ]
    then 
../TCLEXECOMP/CUSTOM/tclexecomp64 maincafl63.tcl CAFL63_PACK_STYLE.tcl tkfe.tcl breeze.tcl cert2text.tcl alloids.tcl ascii.enc cp1251.enc lirssl_static.exe tclpkcs11.dll orlov_250x339.png -i iconCert.ico -w  ../TCLEXECOMP/CUSTOM/tclexecomp$1.exe -forcewrap -forcewrap -o CAFL63_win$1.exe

fi

chmod 755 CAFL63_win$1.exe
rm -f lirssl_static.exe
rm -f tclpkcs11.dll
rm -f tclexecompfull_win$1.exe
