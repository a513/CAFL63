msgcat::mclocale ru
namespace import ::msgcat::mc
rename ::pki::x509::parse_cert ::pki::x509::parse_cert_old
switch -- $::tcl_platform(platform) {
  "windows"        {
    set myfont [font configure TkDefaultFont]
    set myfont [lreplace $myfont 5 5 bold]
    set com "font create TkDefaultFontBold $myfont"
    set com [subst $com]
    eval $com
    font configure TkDefaultFontBold -size 8
  }
  "unix" - default {
    set myfont [font configure TkDefaultFont]
    #puts "myfont=$myfont"
    set myfont [lreplace $myfont 5 5 bold]
    set com "font create TkDefaultFontBold $myfont"
    set com [subst $com]
    eval $com
    font configure TkDefaultFontBold -size 8
  }
}

proc ::pki::x509::parse_cert {cert} {
  array set parsed_cert [::pki::_parse_pem $cert "-----BEGIN CERTIFICATE-----" "-----END CERTIFICATE-----"]
  set cert_seq $parsed_cert(data)

  array set ret [list]

  # Decode X.509 certificate, which is an ASN.1 sequence
  ::asn::asnGetSequence cert_seq wholething
  ::asn::asnGetSequence wholething cert

  set ret(cert) $cert
  set ret(cert) [::asn::asnSequence $ret(cert)]
  binary scan $ret(cert) H* ret(cert)

  ::asn::asnPeekByte cert peek_tag
  if {$peek_tag != 0x02} {
    # Version number is optional, if missing assumed to be value of 0
    ::asn::asnGetContext cert - asn_version
    ::asn::asnGetInteger asn_version ret(version)
    incr ret(version)
  } else {
    set ret(version) 1
  }

  ::asn::asnGetBigInteger cert ret(serial_number)
  ::asn::asnGetSequence cert data_signature_algo_seq
  ::asn::asnGetObjectIdentifier data_signature_algo_seq ret(data_signature_algo)
  ::asn::asnGetSequence cert issuer
  binary scan [::asn::asnSequence $issuer] H* ret(issuer_hex)

  ::asn::asnGetSequence cert validity
  ::asn::asnGetUTCTime validity ret(notBefore)
  ::asn::asnGetUTCTime validity ret(notAfter)
  ::asn::asnGetSequence cert subject
  binary scan [::asn::asnSequence $subject] H* ret(subject_hex)

  ::asn::asnGetSequence cert pubkeyinfo
  binary scan $pubkeyinfo H* ret(pubkeyinfo_hex)

  ::asn::asnGetSequence pubkeyinfo pubkey_algoid
  ::asn::asnGetObjectIdentifier pubkey_algoid ret(pubkey_algo)
  ::asn::asnGetBitString pubkeyinfo pubkey

  set extensions_list [list]
  while {$cert != ""} {
    ::asn::asnPeekByte cert peek_tag

    #add		"0x81"
    #add		"0x82"
    switch -- [format {0x%02x} $peek_tag] {
      "0x81" {
        ::asn::asnGetContext cert - issuerUniqueID
        binary scan $issuerUniqueID H* ret(issuerUniqueID)
      }
      "0x82" {
        ::asn::asnGetContext cert - subjectUniqueID
        binary scan $issuerUniqueID H* ret(subjectUniqueID)
      }
      "0xa1" {
        ::asn::asnGetContext cert - issuerUniqID
        binary scan $issuerUniqueID H* ret(issuerUniqueID)
      }
      "0xa2" {
        ::asn::asnGetContext cert - subjectUniqID
        binary scan $issuerUniqueID H* ret(subjectUniqueID)
      }
      "0xa3" {
        ::asn::asnGetContext cert - extensions_ctx
        ::asn::asnGetSequence extensions_ctx extensions
        while {$extensions != ""} {
          ::asn::asnGetSequence extensions extension
          ::asn::asnGetObjectIdentifier extension ext_oid

          ::asn::asnPeekByte extension peek_tag
          if {$peek_tag == 0x1} {
            ::asn::asnGetBoolean extension ext_critical
          } else {
            set ext_critical false
          }

          ::asn::asnGetOctetString extension ext_value_seq

          set ext_oid [::pki::_oid_number_to_name $ext_oid]

          set ext_value [list $ext_critical]

          switch -- $ext_oid {
            id-ce-basicConstraints {
              ::asn::asnGetSequence ext_value_seq ext_value_bin

              if {$ext_value_bin != ""} {
                ::asn::asnGetBoolean ext_value_bin allowCA
              } else {
                set allowCA "false"
              }

              if {$ext_value_bin != ""} {
                ::asn::asnGetInteger ext_value_bin caDepth
              } else {
                set caDepth -1
              }
                            						
              lappend ext_value $allowCA $caDepth
            }
            default {
              binary scan $ext_value_seq H* ext_value_seq_hex
              lappend ext_value $ext_value_seq_hex
            }
          }

          lappend extensions_list $ext_oid $ext_value
        }
      }
    }
  }
  set ret(extensions) $extensions_list

  ::asn::asnGetSequence wholething signature_algo_seq
  ::asn::asnGetObjectIdentifier signature_algo_seq ret(signature_algo)
  ::asn::asnGetBitString wholething ret(signature)

  # Convert values from ASN.1 decoder to usable values if needed
  set ret(notBefore) [::pki::x509::_utctime_to_native $ret(notBefore)]
  set ret(notAfter) [::pki::x509::_utctime_to_native $ret(notAfter)]
  set ret(serial_number) [::math::bignum::tostr $ret(serial_number)]
  set snstr [::asn::asnBigInteger [math::bignum::fromstr $ret(serial_number)]]
  binary scan $snstr H* ret(serial_number_hex)

  set ret(data_signature_algo) [::pki::_oid_number_to_name $ret(data_signature_algo)]
  set ret(signature_algo) [::pki::_oid_number_to_name $ret(signature_algo)]
  set ret(pubkey_algo) [::pki::_oid_number_to_name $ret(pubkey_algo)]
  set ret(issuer) [_dn_to_string $issuer]
  set ret(subject) [_dn_to_string $subject]
  #My
  #  set ret(issuer_bin) $issuer
  #  set ret(subject_bin) $subject

  set ret(signature) [binary format B* $ret(signature)]
  binary scan $ret(signature) H* ret(signature)

  # Handle RSA public keys by extracting N and E
  switch -- $ret(pubkey_algo) {
    "rsaEncryption" {
      set pubkey [binary format B* $pubkey]
      binary scan $pubkey H* ret(pubkey)

      ::asn::asnGetSequence pubkey pubkey_parts
      ::asn::asnGetBigInteger pubkey_parts ret(n)
      ::asn::asnGetBigInteger pubkey_parts ret(e)

      set ret(n) [::math::bignum::tostr $ret(n)]
      set ret(e) [::math::bignum::tostr $ret(e)]
      set ret(l) [expr {int([::pki::_bits $ret(n)] / 8.0000 + 0.5) * 8}]
      set ret(type) rsa
    }
  }
  return [array get ret]
}

array set ::payoid1 {
  1.2.643.6.3.1.2.2 "МЭТС"
  1.2.643.6.7 "B2B и B2G"
  1.2.643.6.15 "Фабрикант"
  1.2.643.6.14 "Центр реализации"
  1.2.643.100.2.1 "Росреестр"
  1.2.643.3.8.100.1.113 "Росреестр"
  1.2.643.2.2.34.25 "Росреестр"
  1.2.643.2.2.34.26 "Росреестр"
  1.3.6.1.5.5.7.3.1 "TLS Web Server Autentication Certificate"
  1.3.6.1.5.5.7.3.2 "TLS Web Client Autentication Certificate"
  1.3.6.1.5.5.7.3.3 "Code Signing Certificate"
  1.3.6.1.5.5.7.3.4 "Email Protection Certificate"
  1.3.6.1.5.5.7.3.8 "Time Stamping Certificate"
  1.3.6.1.5.5.7.3.9 "OCSP Responder Certificate"
}
#---------------------------------------------------------------------------
# asnT61String: encode tcl string as UTF8 String
#----------------------------------------------------------------------------
proc asn::asnT61String {string} {
  return [asnEncodeString 14 [encoding convertto utf-8 $string]]
}
#------------------------------------------------------------------------
# asnGetT61String: Decode T61 string from data
#------------------------------------------------------------------------
proc asn::asnGetT61String {data_var print_var} {
  upvar 1 $data_var data $print_var print
  asnGetByte data tag
  if {$tag != 0x14} {
    return -code error \
    [format "Expected T61 String (0x14), but got %02x" $tag]
  }
  asnGetLength data length
  asnGetBytes data $length string
  #there should be some error checking to see if input is
  #properly-formatted utf8
  set print [encoding convertfrom utf-8 $string]
        	
  return
}	


#set ::pki::oids(2.5.4.42)  "givenName"
set ::pki::oids(1.2.643.100.1)  "OGRN"
set ::pki::oids(1.2.643.100.5)  "OGRNIP"
set ::pki::oids(1.2.643.3.131.1.1) "INN"
set ::pki::oids(1.2.643.100.4) "INNLE"
set ::pki::oids(1.2.643.100.3) "SNILS"
#Для КПП ЕГАИС
set ::pki::oids(1.2.840.113549.1.9.2) "UN"
#set ::pki::oids(1.2.840.113549.1.9.2) "unstructuredName"
#Алгоритмы подписи
#    set ::pki::oids(1.2.643.2.2.19) "ГОСТ Р 34.10-2001"
set ::pki::oids(1.2.643.2.2.3) "GOST R 34.10-2001 with GOST R 34.11-94"
set ::pki::oids(1.2.643.2.2.19) "GOST R 34.10-2001"
set ::pki::oids(1.2.643.7.1.1.1.1) "GOST R 34.10-2012-256"
set ::pki::oids(1.2.643.7.1.1.1.2) "GOST R 34.10-2012-512"
set ::pki::oids(1.2.643.7.1.1.3.2) "GOST R 34.10-2012-256 with GOSTR 34.11-2012-256"
set ::pki::oids(1.2.643.7.1.1.3.3) "GOST R 34.10-2012-512 with GOSTR 34.11-2012-512"
set ::pki::oids(1.2.643.100.113.1) "KC1 Class Sign Tool"
set ::pki::oids(1.2.643.100.113.2) "KC2 Class Sign Tool"

set ::listkind [list "0 - personal (Личное присутствие)" "1 - remote_cert (Электронная подпись)" "2 - remote_passport(Биометрический загранпаспорт)" "3 - remote_system (ЕСИА и ЕБС)" "Не включать в сертификат"]


proc showTextMenu {w x y rootx rooty} {
  catch {destroy .contextMenu}
  menu .contextMenu -tearoff false
  .contextMenu add command -label "Копировать в буфер обмена выделенное" -command {clipboard clear;clipboard append [selection get]}
#  .contextMenu add command -label "Просмотреть выделенный блок" -command {::viewasn1 2;}

  tk_popup .contextMenu $rootx $rooty
  .contextMenu configure -activebackground #39b5da
  .contextMenu configure -background #e0e0da
}


proc cert2der {data} {
  if {[string first "-----BEGIN CERTIFICATE-----" $data] != -1} {
    #	set data [string map {"\015\012" "\n"} $data]
    set data [string map {"\r\n" "\n"} $data]
  }
  array set parsed_cert [::pki::_parse_pem $data "-----BEGIN CERTIFICATE-----" "-----END CERTIFICATE-----"]
  set asnblock $parsed_cert(data)
  return $asnblock
}

proc chainocsp {chain_hex} {
  set chain [binary format H* $chain_hex]
  set ret {}
  ::asn::asnGetSequence chain c_par_first
  while {[string length $c_par_first] > 0 } {
    #Выбираем очередную последовательность (sequence)
    ::asn::asnGetSequence c_par_first c_par
    #Выбираем oid из последовательности
    ::asn::asnGetObjectIdentifier c_par c_type
    set tas1 [::pki::_oid_number_to_name $c_type]
    #Выбираем установленное значение
    ::asn::asnGetContext c_par c_par_two
    #Ищем oid с адресом корневого сертификата
    if {$tas1 == "1.3.6.1.5.5.7.48.2" } {
      #Читаем очередной корневой сертификат
      lappend ret "CA Issuers"
      lappend ret $c_par
      #	    puts "CA (oid=$tas1)=$c_par"
    } elseif {$tas1 == "1.3.6.1.5.5.7.48.1" } {
      lappend ret "OCSP"
      lappend ret $c_par
      #	    puts "OCSP server (oid=$tas1)=$c_par"
    }
  }
  # Цепочка закончилась
  return $ret
}

proc idkind {idkind_hex} {
  set ret ""
  set kind [binary format H* $idkind_hex]
  ::asn::asnGetInteger kind idk
  switch $idk {
    0 { set ret [lindex $::listkind 0]}
    1 { set ret [lindex $::listkind 1]}
    2 { set ret [lindex $::listkind 2]}
    3 { set ret [lindex $::listkind 3]}
    default {
	set ret "$idk - неизвестный тип идентификации"
    }
  }
  return $ret
}

proc crlpoints {crl_hex} {
  set crl [binary format H* $crl_hex]
  set ret {}
  ::asn::asnGetSequence crl p_crl_first
  set lencontspec 4
  while {[string length $p_crl_first] > 0 } {
    #Выбираем очередную последовательность (sequence)
    ::asn::asnGetSequence p_crl_first c_par
    #Пропускаем contextspecific - 0xA0
    ::asn::asnGetContext c_par context_0xa0
    ::asn::asnPeekByte c_par peek_tag
    while {$peek_tag == 0xA0} {
	::asn::asnGetContext c_par context_0xa0
	::asn::asnPeekByte c_par peek_tag
    }
    ::asn::asnGetContext c_par ux
    #	puts $c_par
    lappend ret $c_par
  }
  return $ret
}

proc altname {alt_hex} {
  set ret {}
  set listname [binary format H* $alt_hex]
  ::asn::asnGetSequence listname names
  while {[string length $names] > 0 } {
    ::asn::asnGetByte names tag
    if {$tag == 0x82 || $tag == 0x81 || $tag == 0x87} {
      #0x82 DNS Name ; 0x81 - RFC 822
      #	    puts "0x82"
      ########################
      ::asn::asnGetByte names taglen
      set len82 [format "%i" $taglen]
      #	    puts $len82
      incr len82 -1
      if {$tag == 0x82 } {
        #Читаем очередной корневой сертификат
        lappend ret "DNS Name"
      } elseif {$tag == 0x81 } {
        #		lappend ret "RFC822 Name"
        lappend ret "Email"
      } elseif {$tag == 0x87 } {
        lappend ret "IP-Address"
      } else {
        lappend ret [format "0x%2x" $tag]
      }
      if {$tag != 0x87 } {
        lappend ret [string range $names 0 $len82]
      } else {
        set ip_b [string range $names 0 $len82]
        lappend ret [ip::ToString $ip_b]
      }
      #	    puts $ret
      incr len82
      set a [string range $names $len82 end]
      set names $a
    }
  }
  return $ret
}

proc keyperiod {per_hex} {
  set per [binary format H* $per_hex]
  array set ret [list]
  ::asn::asnGetSequence per validaty
  ::asn::asnGetByte validaty tag
  if {$tag == 0x80} {
    ::asn::asnGetByte validaty tag
    set len80 [format "%i" $tag]
    incr len80 -1
    set ret(notBefore) [string range $validaty 0 $len80]
    incr len80
    set a [string range $validaty $len80 end]
    set validaty $a
    ::asn::asnGetByte validaty tag
  } else {
    set ret(notBefore) ""
  }
  if {$tag != 0x81} {
    set ret(After) ""
    return [array get ret]
  }
  ::asn::asnGetByte validaty tag
  set len81 [format "%i" $tag]
  incr len81 -1
  set ret(notAfter) [string range $validaty 0 $len81]
  incr len81
  return [array get ret]
}


proc autkeyid {autkey_hex} {
  set autkey [binary format H* $autkey_hex]
  array set ret [list]
  #########################################
  set autkey [binary format H* $autkey_hex]
  array set ret [list]
  ::asn::asnGetSequence autkey fullkey
  #Чтение KEY ID
  ::asn::asnGetContext fullkey - cont
  #    puts "LEN=[string length $fullkey]"
  binary scan $cont H* ret(authKeyID)
  while {[string length $fullkey]} {
    ::asn::asnGetByte fullkey tag1
    ::asn::asnGetLength fullkey tag
    set len80 [format "0x%x" $tag]
    set ee [string range $fullkey 0 0]
    if { $ee == 0} {
      ::asn::asnGetSequence fullkey autdn
      set ret(issuer) [::pki::x509::_dn_to_string $autdn]
      ::asn::asnGetContext fullkey - sernum
      binary scan $sernum H* ret(sernum)
      break
    }
  }

  return [array get ret]
}

proc parse_key_gost {pubkeyinfo_hex} {
  array set ret [list]

  set pubkeyinfo [binary format H* $pubkeyinfo_hex]

  ::asn::asnGetSequence pubkeyinfo pubkey_algoid
  ::asn::asnGetObjectIdentifier pubkey_algoid ret(pubkey_algo)
  ::asn::asnGetBitString pubkeyinfo pubkey

  #		"1.2.643.2.2.19" -
  #		"1.2.643.7.1.1.1.1" -
  #		"1.2.643.7.1.1.1.2"
  #	gost2001, gost2012-256,gost2012-512
  set pubkey [binary format B* $pubkey]
  binary scan $pubkey H* ret(pubkey)
  ::asn::asnGetSequence pubkey_algoid pubalgost
  #OID - параметра
  ::asn::asnGetObjectIdentifier pubalgost ret(paramkey)
  #OID - Функция хэша
  if {$pubalgost != ""} {
    ::asn::asnGetObjectIdentifier pubalgost ret(hashkey)
  } else {
    set ret(hashkey) ""
  }
  #puts "ret(paramkey)=$ret(paramkey)\n"
  #puts "ret(hashkey)=$ret(hashkey)\n"
  #parray ret
  return [array get ret]

}
proc parse_anykey_gost {fullasnkey} {
  array set ret [list]
  ::asn::asnGetSequence fullasnkey prkey
  #У закрытого? ключа есть/может быть версия
  ::asn::asnPeekByte prkey peek_tag
  if {$peek_tag == 0x02} {
    # Version number is optional, if missing assumed to be value of 0
    ::asn::asnGetInteger prkey version
  }

  ::asn::asnGetSequence prkey pubkey_algoid
  ::asn::asnGetObjectIdentifier pubkey_algoid ret(pubkey_algo)
  if {[string first "1 2 643 " $ret(pubkey_algo)] == -1} {
    return [array get ret]
  }
  ::asn::asnGetSequence pubkey_algoid key_param
  ::asn::asnGetObjectIdentifier key_param ret(par_sign)
  ::asn::asnGetObjectIdentifier key_param ret(par_hash)
  #У открытого ключа может быть еще bitstring
  ::asn::asnPeekByte prkey peek_tag
  if {$peek_tag == 0x03} {
    # Version number is optional, if missing assumed to be value of 0
    ::asn::asnGetBitString prkey ret(key_value)
    set ret(key_value) [binary format B* $ret(key_value)]
  } else {
    ::asn::asnGetOctetString prkey ret(key_value)
  }
  ::asn::asnGetOctetString ret(key_value) ret(key_value)
  binary scan $ret(key_value) H* ret(key_value_hex)
  return [array get ret]
}


proc issuerpol {iss_hex} {
  array set ret [list]
  set iss [binary format H* $iss_hex]
  ::asn::asnGetSequence iss iss_pol
  for {set i 1} {[string length $iss_pol] > 0}  {incr i} {
    ::asn::asnGetUTF8String iss_pol ret(isspol$i)
  }
  return [array get ret]
}
proc subjectpol {iss_hex} {
  puts "SUBJECTPOL=$iss_hex"
  set iss [binary format H* $iss_hex]
  array set ret [list]
  #    ::asn::asnGetSequence iss iss_pol
  #Из-за того, что длина раньше попадала не в байтах, а в символах, то обрабатывалось не все
  set i 1
  #set ret(isspol$i) [encoding convertfrom utf-8 [string range $iss 2 end]]
  #    for {set i 1} {[string length $iss] > 0}  {incr i} {
  ::asn::asnGetUTF8String iss ret(isspol$i)
  #    }
  return [array get ret]
}

proc extku {ku_hex} {
  #set ::ku_options {"Digital signature" "Non-Repudiation" "Key encipherment" "Data encipherment" "Key agreement" "Certificate signature" "CRL signature" "Encipher Only" "Decipher Only" "Revocation list signature"}
  #puts "KU_hex=$ku_hex"
  set ku [binary format H* $ku_hex]
  ::asn::asnGetBitString ku ku_bin
  set ret {}
  #puts "KU=$ku_bin"
  #puts "KU len=[string length $ku_bin]"
  for {set i 0} {$i < [string length $ku_bin]}  {incr i} {
    #	puts "I=$i"
    if {[string range $ku_bin $i $i] > 0 } {
      lappend ret [lindex $::ku_options $i]
    }
  }
  #    puts $ret
  return $ret
}

proc extpol {pol_hex} {
  set pol [binary format H* $pol_hex]
  set ret {}
  ::asn::asnGetSequence pol oid_pol
  for {set i 1} {[string length $oid_pol] > 0}  {incr i} {
    ::asn::asnGetSequence oid_pol oid_pol1
    ::asn::asnGetObjectIdentifier oid_pol1 ret1
    lappend ret $ret1
  }
  #    puts $ret
  return $ret
}

proc extkeyuse {keyuse_hex} {
  set use [binary format H* $keyuse_hex]
  set ret {}
  ::asn::asnGetSequence use oid_use
  for {set i 1} {[string length $oid_use] > 0}  {incr i} {
    ::asn::asnGetObjectIdentifier oid_use ret1
    lappend ret $ret1
  }
  #    puts "EXTKEYUSE=$ret"
  return $ret
}

proc edithex {hex} {
  set c ""
  set l [string length $hex]
  #    puts $l
  for {set j 0 } { $j < $l} {incr j +2} {
    set c "$c[string range $hex $j $j+1] "
  }
  return [string toupper [string trimright $c]]
}


proc del_comma {ldn} {
  set lret {}
  set ff ""
  foreach el $ldn {
    if {[string first "=" $el] != -1} {
      if {$ff != ""} {
        lappend lret $ff
      }
      set ff $el
    } else {
      set ff "$ff,$el"
    }
  }
  lappend lret $ff
  return $lret
}


#Если mick == "", то в cert_hex имя файла с сертификатом
# в противном случае в cert_hex сертификат в DER-кодировке завернутый в hex (шестнадцатеричную) - кодировку
#В cert_hex может находиться сертификат в PEN-кодировке или в DER-кодировке, завернутой в hex.
#w - text-widget
proc cert2text {wfr nick cert_hex} {
    array set dn_fields {
	C "Country" ST "State" L "Locality" STREET "Adress" TITLE "Title"
	O "Organization" OU "Organizational Unit"
	CN "Common Name" SN "Surname" GN "Given Name" INN "INN" INNLE "INNLE" OGRN "OGRN" OGRNIP "OGRNIP" SNILS "SNILS" EMAIL "Email Address"
	UN "KPP"
    }
    array set dn_fields_ru {
	C "Страна" ST "Регион" L "Местность" STREET "Адрес" TITLE "Название"
	O "Организация" OU "Подразделение"
	CN "Общепринятое имя" SN "Фамилия" GN "Имя, отчество" GIVENNAME "Имя,отчество" INN "ИНН" INNLE "ИННЮЛ" OGRN "ОГРН" OGRNIP "ОГРНИП" SNILS "СНИЛС" EMAILADDRESS "Адрес эл.почты" 
	UN "unstructuredName"
	}
    set ::ku_options {"Цифровая подпись" "Неотрекаемость" "Шифрование ключа" "Шифрование данных" "Согласование ключа" "Подпись сертификата" "Подпись СОС/CRL" "Только шифровать" "Только расшифровать" "Аннулирование списка подписей"}
  global home
  global loadfile
#  global dn_fields_ru
  set ::dercert ""
  set ::parsecert ""
  catch {font delete TkFixedMe}
  set a [font actual TkFixedFont]
  eval "font create TkFixedMe $a"
  font configure TkFixedMe -size 8
  if {$cert_hex == "" } {
    tk_messageBox -title "Просмотр сертификатаINFO" -icon info -message "Не задан сертификат\nnick=$nick\n"
    return "" 
  }

  array set cert_parse []
  if { [string range "$cert_hex" 0 9 ] == "-----BEGIN" } {
    set asndata [cert2der $cert_hex]
    if {$asndata == "" } {
      tk_messageBox -title "Просмотр сертификата" -icon error -message "$file" -detail "Выбранная строка не содержит сертификат"
      return ""
    }

    if {[catch {array set cert_parse [::pki::x509::parse_cert $asndata]} rc]} {
      tk_messageBox -title "Просмотр сертификата" -icon error -message "$file" -detail "Выбранная строка не содержит сертификат"
      return ""
    }
    set ::dercert $asndata
    binary scan  $asndata H*  cert_hex
    array set infopk [pki::pkcs11::pubkeyinfo $cert_hex]
    set cert_parse(pubkeyinfo) $infopk(pubkeyinfo)

  } elseif {$cert_hex != "" } {
    set asndata [binary  format H* $cert_hex]
    if {[catch {array set cert_parse [::pki::x509::parse_cert $asndata]} rc]} {
      tk_messageBox -title "Просмотр сертификата" -icon error -message "$file" -detail "Выбранный файл не содержит сертификат"
      return ""
    }
    set ::dercert $asndata
    array set cert_parse [pki::x509::parse_cert $asndata]
    #Читаем публичный ключ
    #puts "CERT_PARSE_filewith=$certinfo_list"
    array set infopk [pki::pkcs11::pubkeyinfo $cert_hex ]

    set cert_parse(pubkeyinfo) $infopk(pubkeyinfo)
  } else {
    unset -nocomplain cert_parse
    set file $cert_hex
    set fd [open $file]
    chan configure $fd -translation binary
    set data [read $fd]
    close $fd
    set asndata [cert2der $data]
    if {$asndata == "" } {
      tk_messageBox -title "Просмотр сертификата" -icon error -message "$file" -detail "Выбранный файл не содержит сертификат"
      return ""
    }

    if {[catch {array set cert_parse [::pki::x509::parse_cert $asndata]} rc]} {
      tk_messageBox -title "Просмотр сертификата" -icon error -message "$file" -detail "Выбранный файл не содержит сертификат"
      return ""
    }
    set ::dercert $asndata
    binary scan  $asndata H*  cert_hex
    array set infopk [pki::pkcs11::pubkeyinfo $cert_hex]
    set cert_parse(pubkeyinfo) $infopk(pubkeyinfo)
  }
  text $wfr.text -autosep 1 -width 60 -height 20 -wrap word -relief flat -bd 0 -bg #fcfefc
# -setgrid true -autosep 1
  set w $wfr.text
  $w delete 0.0 end
  font configure TkDefaultFontBold -size 10
    $w tag configure bold -font TkDefaultFontBold
    $w tag configure super -offset 4p -font TkDefaultFont
    $w tag configure sub -offset -2p -font TkDefaultFont
    $w tag configure margins -lmargin1 4m -lmargin2 12m -rmargin 10m
    $w tag configure margins1 -lmargin1 2m -lmargin2 2.2i -rmargin 2m -spacing1 1p -spacing2 1p -spacing3 1p
    $w tag configure margins11 -lmargin1 2m -lmargin2 2.2i -rmargin 2m -spacing1 1p -spacing2 1p -spacing3 1p -font TkFixedMe
#    TkFixedFont
    $w tag configure margins2 -lmargin1 6m -lmargin2 2.2i -rmargin 2m -spacing1 1p -spacing2 1p -spacing3 1p
    $w tag configure spacing -spacing1 10p -spacing2 2p -lmargin1 12m -lmargin2 6m -rmargin 10m
    $w configure -tabs {1m 2.2i}
  bind $w <ButtonPress-3> {showTextMenu %W %x %y %X %Y}

  ttk::scrollbar $wfr.vsb -orient vertical -command [list $w yview]
  pack $wfr.vsb -side right -fill y  -in $wfr
  pack $w -padx {1 1} -pady {2 0} -side left -fill both -expand 1
  $w configure -yscrollcommand [list $wfr.vsb set]

  $w tag configure tagAbout -foreground blue -font {Times 10 bold italic}
#############Cert2Text###################################
#  parray cert_parse
  $w insert end [mc "Issued Certificate"] bold
  $w insert end "\n"
  $w insert end "\t[mc "Version"]:\t$cert_parse(version)\n"  margins1
  set ::sncert "$cert_parse(serial_number)"
  set sn_bin [::asn::asnBigInteger [math::bignum::fromstr $cert_parse(serial_number)]]
  set sn_bin [string range $sn_bin 2 end]
  binary scan $sn_bin H* sn_hex

  $w insert end "\t[mc "Serial Number"] (hex):\t[edithex $sn_hex]\n"  margins1
  $w insert end "\t[mc "Serial Number"] (dec):\t$cert_parse(serial_number)\n"  margins1
  set ::notafter  $cert_parse(notAfter)
  set t $cert_parse(notAfter)
  #puts "T=$t"
  set notafter [clock format $t -format "%d/%m/%Y %R %Z"]
  set ::notbefore $cert_parse(notBefore)
  set t $cert_parse(notBefore)
  #puts "T=$t"

#  $w insert end [mc "Validity"] bold
#  $w insert end "\n"
  set notbefore [clock format $t -format "%d/%m/%Y %R %Z"]
  $w insert end "\t[mc "Not Valid Before"]:\t$notbefore\n"  margins1
  $w insert end "\t[mc "Not Valid After"]:\t$notafter\n"  margins1
  set ver [mc "Expires"]
  #    puts  $cert_parse(subject)
  set ::subjectcert "$cert_parse(subject)"
  set lsub [split $cert_parse(subject) ","]
  set lsub [del_comma $lsub]
  #    puts $lsub

  $w insert end [mc "Subject Name"] bold
  $w insert end "\n"
  foreach a $lsub {
    set ind [string first "=" $a]
    if {$ind == -1 } { continue }
                    	
    set oidsub [string trim [string range $a 0 $ind-1]]
    if {[info exists dn_fields_ru($oidsub)]} {
      set nameoid "$dn_fields_ru($oidsub)"
    } else {
      set nameoid ""
    }

    #	puts $nameoid
    set oidval "[mc [string trim [string range $a $ind+1 end]]]"
    if {$oidsub == "CN"} {
      set ::cn_subject  $oidval
    }

    if {$oidsub == "GIVENNAME"} {
      set oidsub "GV"
    }
    if {$oidsub == "EMAILADDRESS"} {
      set oidsub "EMAIL"
    }
    set oidsub "$nameoid ($oidsub)"
    #	set oidsub "$oidsub$nameoid"
    $w insert end "\t$oidsub\t$oidval\n"  margins1
  }
  $w insert end [mc "Issuer Name"] bold
  $w insert end "\n"
  #    puts  $cert_parse(issuer)
  set ::issuercert "$cert_parse(issuer)"
  set liss [split $cert_parse(issuer) ","]
  set liss [del_comma $liss]
  #    puts $liss

  foreach a $liss {
    set ind [string first "=" $a]
    if {$ind == -1 } { continue }
    set oidsub [string trim [string range $a 0 $ind-1]]
    if {[info exists dn_fields_ru($oidsub)]} {
      set nameoid "$dn_fields_ru($oidsub)"
    } else {
      set nameoid ""
    }

    set oidval "[mc [string trim [string range $a $ind+1 end]]]"
    if {$oidsub == "CN"} {
      set ::cn_issuer  $oidval
    }
    if {$oidsub == "GIVENNAME"} {
      set oidsub "GV"
    }
    if {$oidsub == "EMAILADDRESS"} {
      set oidsub "EMAIL"
    }

    set oidsub "$nameoid ($oidsub)"
    #	set oidsub "$oidsub$nameoid"
    $w insert end "\t$oidsub\t$oidval\n"  margins1
  }
  $w insert end [mc "Public Key Info"] bold
  $w insert end "\n"
  if {[string range $cert_parse(pubkey_algo) 0 7] == "1.2.643." || [string range $cert_parse(pubkey_algo) 0 7] == "ГОСТ Р 3" || [string range $cert_parse(pubkey_algo) 0 7] == "GOST R 3"} {
    $w insert end "\t[mc "Key Algorithm"]:\t[mc $cert_parse(pubkey_algo)]\n"  margins1
    $w insert end "\t[mc "Key Parameters"]:\n"  margins1
    array set ret [parse_key_gost $cert_parse(pubkeyinfo)]
    #	parray ret
    $w insert end "\t[mc "sign param"]:\t[mc $ret(paramkey)]\n"  margins2
    if {$ret(hashkey) != ""} {
      $w insert end "\t[mc "hash param"]:\t[mc $ret(hashkey)]\n"  margins2
    }
    set sek 4
    if {[string range $ret(pubkey) 2 3] != 40} {
      set sek 6
    }
    set pk [edithex [string range $ret(pubkey) $sek end]]
    $w insert end "\t[mc "Public Key"]:\t$pk\n"  margins11
    #Идентификатор ключа получателя
    set pk_bin [binary format H* $ret(pubkey)]
    set ::pkcs11id [::sha1::sha1  $pk_bin]
  } else {
    if {[string range $cert_parse(pubkey_algo) 0 2] == "rsa" } {
      set pkcs11id_bin [binary format H* $cert_parse(pubkey)]
      set ::pkcs11id [::sha1::sha1 $pkcs11id_bin]
      $w insert end "\t[mc "Key Algorithm"]:\tRSA\n"  margins1
      $w insert end "\t[mc "Key Size"]:\t$cert_parse(l)\n"  margins2
      $w insert end "\t[mc "Public Key"]:\t[edithex $cert_parse(pubkey)]\n"  margins11
    } else {
      $w insert end "\t[mc "Key Algorithm"]:\t$cert_parse(pubkey_algo)\n"  margins1
      $w insert end "\t[mc "Key Info"]:\t[edithex $cert_parse(pubkeyinfo)]\n" margins11
    }
  }
#UniqueID
  if {[info exists cert_parse(subjectUniqueID)]} {
	$w insert end [mc "Subject Unique ID:"] bold
	$w insert end "\t\t$cert_parse(subjectUniqueID)\n"  margins1
  }
  if {[info exists cert_parse(issuerUniqueID)]} {
	$w insert end [mc "Issuer Unique ID:"] bold
	$w insert end "\t\t$cert_parse(issuerUniqueID)\n"  margins1
  }
  array set extcert $cert_parse(extensions)
    $w insert end [mc "          Расширения сертификата (Extensions)\n"] bold
  #    parray extcert
  if {[info exists extcert(id-ce-basicConstraints)]} {
    $w insert end [mc "Basic Constraints (2.5.29.19)"] bold
    $w insert end "\n"
    set basic $extcert(id-ce-basicConstraints)
    #	puts $basic
    if {[lindex $basic 1] == 1} {
      set typecert [mc "Yes"]
    } else {
      set typecert [mc "No"]
    }
    $w insert end "\t[mc "Certificate Authority"]:\t$typecert\n"  margins1
    if {[lindex $basic 2] == -1} {
      set lencert [mc "Unlimited"]
    } else {
      set lencert [lindex $basic 2]
    }
    $w insert end "\t[mc "Max Path Length"]:\t$lencert\n"  margins1
    if {[lindex $basic 0] == 1} {
      set critcert [mc "Yes"]
    } else {
      set critcert [mc "No"]
    }
    $w insert end "\t[mc "Critical"]:\t$critcert\n"  margins1
    unset extcert(id-ce-basicConstraints)
  }
  #  1 false -1
  # первое поле критичность 1 - Да, false - нет
  # второе поле УЦ 1 - Да, false - нет
  #Третье поле - длина пути : -1 - неограниченный, или значение 0 и т.д.
  if {[info exists extcert(1.2.643.100.112)]} {
    #issuerSignTools
    array set pol [issuerpol [lindex $extcert(1.2.643.100.112) 1]]
    $w insert end [mc "issuerSignTool (1.2.643.100.112)"] bold
    $w insert end "\n"
    $w insert end "\t[mc "Name CKZI"]:\t$pol(isspol1)\n"  margins1
    $w insert end "\t[mc "Name CA"]:\t$pol(isspol2)\n"  margins1
    $w insert end "\t[mc "Certificate SKZI CA"]:\t$pol(isspol3)\n"  margins1
    $w insert end "\t[mc "Certificate CA"]:\t$pol(isspol4)\n"  margins1
    #	parray pol
    unset extcert(1.2.643.100.112)
  }
  if {[info exists extcert(1.2.643.100.111)]} {
    #subjectSignTools
    array set pol [subjectpol [lindex $extcert(1.2.643.100.111) 1]]
    $w insert end [mc "subjectSignTool (1.2.643.100.111)"] bold
    $w insert end "\n"
    $w insert end "\t[mc "User CKZI"]:\t$pol(isspol1)\n"  margins1
    #	parray pol
    unset extcert(1.2.643.100.111)
  }
  if {[info exists extcert(id-ce-keyUsage)]} {
    $w insert end [mc "Key Usage (2.5.29.15)"] bold
    $w insert end "\n"

    set ku [extku [lindex $extcert(id-ce-keyUsage) 1]]
    $w insert end "\t[mc "Usages"]:\t[mc [lindex $ku 0]]\n"  margins1
    for {set i 1 } { $i < [llength $ku] } {incr i} {
      $w insert end "\t\t[lindex $ku $i]\n"  margins1
    }
    #	puts $ku
    if {[lindex $extcert(id-ce-keyUsage) 0] == 1} {
      set critcert [mc "Yes"]
    } else {
      set critcert [mc "No"]
    }
    $w insert end "\t[mc "Critical"]:\t$critcert\n"  margins1
    unset extcert(id-ce-keyUsage)
  }
  if {[info exists extcert(id-ce-certificatePolicies)]} {
    $w insert end [mc "Certificate Policies (2.5.29.32)"] bold
    $w insert end "\n"
    set lpol [extpol [lindex $extcert(id-ce-certificatePolicies) 1]]
    $w insert end "\t[mc "Policy Name"]:\t[mc [::pki::_oid_number_to_name [lindex $lpol 0]]]\n"  margins1
    for {set i 1 } { $i < [llength $lpol] } {incr i} {
      $w insert end "\t\t[mc [::pki::_oid_number_to_name [lindex $lpol $i]]]\n"  margins1
    }
    #	puts $ku
    if {[lindex $extcert(id-ce-certificatePolicies) 0] == 1} {
      set critcert [mc "Yes"]
    } else {
      set critcert [mc "No"]
    }
    $w insert end "\t[mc "Critical"]:\t$critcert\n"  margins1
    unset extcert(id-ce-certificatePolicies)
  }
  if {[info exists extcert(id-ce-subjectKeyIdentifier)]} {
    $w insert end [mc "Subject Key Identifier (2.5.29.14)"] bold
    $w insert end "\n"
    $w insert end "\t[mc "Key ID"]:\t[edithex [string range [lindex $extcert(id-ce-subjectKeyIdentifier) 1] 4 end]]\n"  margins1
    #	set ::pkcs11id [string range [lindex $extcert(id-ce-subjectKeyIdentifier) 1] 4 end]
    unset extcert(id-ce-subjectKeyIdentifier)
  }
  if {[info exists extcert(id-ce-privateKeyUsagePeriod) ]} {
    $w insert end [mc "Key Usage Period (2.5.29.16)"] bold
    $w insert end "\n"
    array set keyperiod [keyperiod [lindex $extcert(id-ce-privateKeyUsagePeriod) 1]]
    #	parray keyperiod
    set t $keyperiod(notBefore)
    set year [string range $t 0 3]
    set month [string range $t 4 5]
    set day [string range $t 6 7]
    set hour [string range $t 8 9]
    set minute [string range $t 10 11]

    #	puts  "$day $month $year $hour $minute"
    set notbefore "$day/$month/$year $hour:$minute"

    set t $keyperiod(notAfter)
    set notafter "[string range $t 6 7]/[string range $t 4 5]/[string range $t 0 3] [string range $t 8 9]:[string range $t 10 11]"
    $w insert end "\t[mc "Not Valid Before"]:\t$notbefore\n"  margins1
    $w insert end "\t[mc "Not Valid After"]:\t$notafter\n"  margins1

    if {[lindex $extcert(id-ce-privateKeyUsagePeriod) 0] == 1} {
      set critcert [mc "Yes"]
    } else {
      set critcert [mc "No"]
    }
    $w insert end "\t[mc "Critical"]:\t$critcert\n"  margins1
    unset extcert(id-ce-privateKeyUsagePeriod)
  }
  if {[info exists extcert(id-ce-authorityKeyIdentifier) ]} {
    $w insert end [mc "Certificate Authority Key Identifier (2.5.29.35)"] bold
    $w insert end "\n"
    array set autkey [autkeyid [lindex $extcert(id-ce-authorityKeyIdentifier) 1]]
    $w insert end "\t[mc "Key ID"]:\t[edithex $autkey(authKeyID)]\n"  margins1
    if {[info exists autkey(issuer) ] } {
      $w insert end "\t[mc "Directory Name"]:\t$autkey(issuer)\n"  margins1
    }
    if {[info exists autkey(sernum) ]} {
      $w insert end "\t[mc "Serial Number"]:\t[edithex $autkey(sernum)]\n"  margins1
    }
    unset extcert(id-ce-authorityKeyIdentifier)
  }
  if {[info exists extcert(2.5.29.37) ]} {
    $w insert end [mc "Extended Key Usage (2.5.29.37)"] bold
    $w insert end "\n"
    set listusage [extkeyuse [lindex $extcert(2.5.29.37) 1]]
    set oidt [string map {" " "."} [lindex $listusage 0]]
    if {[info exists ::payoid($oidt) ]} {
      set poid " ($::payoid($oidt))"
    } else {
      set poid ""
    }
    $w insert end "\t[mc "Allowed Purposes"]:\t$oidt$poid\n"  margins1
    for {set i 1 } { $i < [llength $listusage] } {incr i} {
      set oidt [string map {" " "."} [lindex $listusage $i]]
      if {[info exists ::payoid($oidt) ]} {
        set poid " ($::payoid($oidt))"
      } else {
        set poid ""
      }
      $w insert end "\t\t$oidt$poid\n"  margins1
    }
    if {[lindex $extcert(2.5.29.37) 0] == 1} {
      set critcert [mc "Yes"]
    } else {
      set critcert [mc "No"]
    }
    $w insert end "\t[mc "Critical"]:\t$critcert\n"  margins1
    unset extcert(2.5.29.37)
  }
  set ::chaincert ""
  if {[info exists extcert(1.3.6.1.5.5.7.1.1)]} {
    $w insert end [mc "Authority information Accesss (1.3.6.1.5.5.7.1.1)"] bold
    $w insert end "\n"
    set listchain [chainocsp [lindex $extcert(1.3.6.1.5.5.7.1.1) 1]]
    #	puts $listchain
    foreach {a b} $listchain {
      $w insert end "\t[mc $a]:\tURI:$b\n"  margins1
    }
    set ::chaincert [lindex $extcert(1.3.6.1.5.5.7.1.1) 1]
    #	puts "CHAIN=[lindex $extcert(1.3.6.1.5.5.7.1.1) 1]"
    unset extcert(1.3.6.1.5.5.7.1.1)
  }

  set ::crlfile ""
  if {[info exists extcert(2.5.29.31)]} {
    $w insert end "CRL Distribution Points (2.5.29.31)" bold
    $w insert end "\n"
    #	puts "CRL=$extcert(2.5.29.31)"
    set listcrl [crlpoints [lindex $extcert(2.5.29.31) 1]]
    #	puts $listcrl
    foreach {crlp} $listcrl {
      $w insert end "\tDistribution Point:\tURI:$crlp\n"  margins1
    }
    set ::crlfile  $listcrl
    unset extcert(2.5.29.31)
  }
  #extcert(id-ce-issuerAltName)          = false 3000
  #extcert(id-ce-subjectAltName)
  if {[info exists extcert(id-ce-issuerAltName)]} {
    $w insert end [mc "Issuer Alt Name (2.5.29.18)"] bold
    $w insert end "\n"
    #	puts "ALT ISSUER=$extcert(id-ce-issuerAltName)"
    set listalt [altname [lindex $extcert(id-ce-issuerAltName) 1]]
    foreach {a b} $listalt {
      $w insert end "\t[mc $a]:\tURI:$b\n"  margins1
    }
    unset extcert(id-ce-issuerAltName)
  }
  if {[info exists extcert(id-ce-subjectAltName)]} {
    $w insert end [mc "Subject Alt Name (2.5.29.17)"] bold
    $w insert end "\n"
    #	puts "ALT=$extcert(id-ce-subjectAltName)"
    set listalt [altname [lindex $extcert(id-ce-subjectAltName) 1]]
    foreach {a b} $listalt {
      $w insert end "\t[mc $a]:\tURI:$b\n"  margins1
    }
    unset extcert(id-ce-subjectAltName)
  }
  if {[info exists extcert(1.2.643.100.114)]} {
#IdentificationKind - как выдавался сертификат
    $w insert end "Identification Kind (1.2.643.100.114)" bold
    $w insert end "\n"
    #	puts "CRL=$extcert(2.5.29.31)"
    set ikind [idkind [lindex $extcert(1.2.643.100.114) 1]]
#    set crit [lindex $extcert(1.2.643.100.114) 0]
    if {[lindex $extcert(1.2.643.100.114) 0] == 1} {
      set crit [mc "Yes"]
    } else {
      set crit [mc "No"]
    }
    $w insert end "\tType Identification Kind:\t$ikind\n"  margins1
    $w insert end "\t[mc "Critical"]:\t$crit\n"  margins1
    unset extcert(1.2.643.100.114)
  }

  set listext [array get extcert]
  foreach {a b} $listext {
    $w insert end [mc "Extension ($a)"] bold
    $w insert end "\n"
#    $w insert end "\t[mc "Identifier"]:\t$a\n"  margins1
    $w insert end "\t[mc "Value"]:\t[edithex [lindex $b 1]]\n"  margins1
    if {[lindex $b 0] == 1} {
      set critcert [mc "Yes"]
    } else {
      set critcert [mc "No"]
    }
#    set critcert [lindex $b 0]
    $w insert end "\t[mc "Critical"]:\t$critcert\n"  margins1
  }
  $w insert end [mc "          Расширения сертификата (Extensions) исчерпаны\n"] bold

  $w insert end [mc "Signature"] bold
  $w insert end "\n"
  $w insert end "\t[mc "Signature Algorithm"]\t[mc "$cert_parse(signature_algo)"]\n"  margins1
  $w insert end "\t[mc "Signature"]:\t[edithex $cert_parse(signature)]\n"  margins11

  $w insert end [mc "Certificate Fingerprints"] bold
  $w insert end "\n"

  set fingerprint_sha256 [::sha2::sha256 $::dercert]
  set fingerprint_sha1 [::sha1::sha1  $::dercert]

  $w insert end "\t[mc "SHA1"]:\t[edithex $fingerprint_sha1]\n"  margins11
  $w insert end "\t[mc "SHA256"]:\t[edithex $fingerprint_sha256]\n"  margins11

}
