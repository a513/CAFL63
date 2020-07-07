rm -f tclpkcs11.p11
cp -f tclpkcs11.dylib ./tclpkcs11.p11
cp lirssl_static_mac lirssl_static
../WRAP_MAC/tclexecomp64_v.1.0.4.linux CAFL63_PACK_STYLE.tcl tkfe.tcl breeze.tcl cert2text.tcl alloids.tcl ascii.enc tclpkcs11.p11 lirssl_static orlov_250x339.png ascii.enc -forcewrap -w ../WRAP_MAC/tclexecomp64_v.1.0.4.mac -o CAFL63_mac
rm -f lirssl_static
rm -f tclpkcs11.p11