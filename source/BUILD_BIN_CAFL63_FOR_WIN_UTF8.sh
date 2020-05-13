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
echo "./BUILD_BIN_P11CONFGUI_FOR_WIN32_COPY.sh 32|64"
a=WIN$1_WRAP664
echo $a
rm -f tclpkcs11.dll
cp -f tclpkcs11_win$1.dll ./tclpkcs11.dll

./tclexecomp64_v.1.0.4   maincafl63.tcl CAFL63_PACK_STYLE.tcl tkfe.tcl breeze.tcl cert2text.tcl alloids.tcl cp1251.enc ascii.enc tclpkcs11.dll orlov_250x339.png -i iconCert.ico  -w tclexecomp_v.1.0.4_win$1.exe -forcewrap  -o CAFL63_win$1.exe
chmod 755 CAFL63_win$1.exe
rm -f tclpkcs11.dll
