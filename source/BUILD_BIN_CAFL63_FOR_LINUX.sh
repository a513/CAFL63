echo "./BUILD_BIN_CAFL63_FOR_LIN_COPY.sh 32|64"
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

rm -f lirssl_static
cp -f lirssl_static_x$1 ./lirssl_static
rm -f tclpkcs11.p11
cp -f tclpkcs11_$1.so ./tclpkcs11.p11
echo $a

../WRAP_MAC/tclexecomp64_v.1.0.4 CAFL63_PACK_STYLE.tcl tkfe.tcl breeze.tcl cert2text.tcl alloids.tcl ascii.enc lirssl_static tclpkcs11.p11 orlov_250x339.png -forcewrap  -w ../WRAP_MAC/tclexecomp_v.1.0.4.linux$1 -o CAFL63_linux$1
chmod 755 CAFL63_linux$1
rm -f lirssl_static
rm -f tclpkcs11.p11


