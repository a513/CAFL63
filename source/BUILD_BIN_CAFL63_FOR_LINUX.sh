echo "./BUILD_BIN_CAFL63_FOR_LIN_COPY.sh 32|64"
if [ $1 -ne 64  -a $1 -ne 32 ]
    then 
	echo "Bad type 32|64"
	exit 1
fi
rm -f tclpkcs11.p11
cp -f tclpkcs11_$1.so ./tclpkcs11.p11
echo $a
./tclexecomp_v.1.0.4.linux64 CAFL63_PACK_STYLE.tcl tkfe.tcl breeze.tcl cert2text.tcl alloids.tcl ascii.enc tclpkcs11.p11 orlov_250x339.png -forcewrap  -w ./tclexecomp_v.1.0.4.linux$1 -o CAFL63_linux$1_v1.0.4
chmod 755 CAFL63_linux$1_v1.0.4
rm -f tclpkcs11.p11


