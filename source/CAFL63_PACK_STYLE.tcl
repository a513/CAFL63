package require Tk
package require sqlite3
package require pki
package require cmdline
package require csv
package require base64
package require http
package require msgcat


global typesys
set typesys [tk windowingsystem]
#Главное окно
if {$typesys == "win32" } {
    wm geometry . 850x595+300+105
} else {
    wm geometry . 850x575+300+105
}
global home
set ::yearcert 1
set home $env(HOME) 
global macos
set macos 0
    package require tls
switch $typesys {
  win32        {
#Перекодируем путь из кодировки ОС
#Для MS Win это скорей всего cp1251
    set tekdir1 [encoding convertfrom cp1251 $home ]
#Заменяем обратную косую в пути на нормальную косую
    set home [string map {"\\" "/"} $tekdir1]
  }
  classic - aqua {
    set macos 1
  }
}

image create photo iconCert_32x32 -data {
R0lGODlhIAAgAMZqANYOANcRC9gTDNoWDtsYF9wbGNklF9omGNomH90rKdszKe0xKwB2rt5BOt5JQuRQTeFUTeFVU9lzbo6JiN53ctaFg5yXlZqbmOOJhOOQjuaTkeOX
kumcl+idnq2vrNumprGzr7K0seeppby+u73CxMDCvr7DxcfCwcDFyMPFwuq7ucHGycLHyuS/v8PIy8bIxcTJzMXKzefCw8bMzuPFxMfNz9fKy8nO0MrP0cvQ0ujJyMzR
1M3S1dDSz87T1s/U19LU0dDV2NHX2ebS1NLY2tbY1dTZ29Xa3Nbb3dnb19fc39rc2ebZ2tjd4Oja29ne4drf4unc3Nvg4+Te3d7g3dzi5OPh5d3j5efi4OXi5uHk4N/k
5ujj4uDl6OHm6erk4+Ln6uPo6+Tp7Ofp5uro7OXq7ebs7uft7+nu8Orv8v//////////////////////////////////////////////////////////////////////
/////////////////yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAH8ALAAAAAAgACAAAAf+gH9/DISFhoeIiYKCiY2OhouDDAuUlZaXmJWEkYSUZwufoaCjoqJmC5uL
naesC62vrrGnqAyckwtlZmW7u2ZfUWS5vL2xqYyTZbhpaGNPZWIQBTJYZmlnSV5mR8m0tpQTPkBdZWBZDwIFAh1dL2FpT1IXC2PdqpNCCyNGYfw66A5fwnjYwi/MlhBF
KBmTRAlECh5gIjpBUMCAiDAlnkQE48XCgjT1ji0As+CIliRmiIDhIMCAAA1namwRs6MMCi8Ka9mj5KVLFzNStgypaMClCixlpBjssmBLSIZOt0iVyiRBywIKdGDocsXI
lR5KcnpbcKVs2SpXstCIkKHFBgH+U34g8XJiAZWnnaosqNLER44dO3L4aFCgAAAKPoxAyUFQ7M4FUqQ02YEDh5AgOWxUkPCBMo4bP6BAxjtJNBQlOW7cCBJEdWUcP3zI
FvJENGlKT54g2aG6huobn33kHv5kQfGFnZosaIIkyI8fQp77eH6kyZHnQpoov71AiRIiM2LE2FEjRvgYP66Hz4Gk++0jJcGLFz9DyA0YMWDMCBIDx5H23B1hRBAwuFCg
gfm5YOAPRAhBBHxG3BbhgDm8VlkOFeKQQxBEGEHEh46JtMCHP8DAgguUuYBeDC7ccJkL+414WxALBOGDCyugGMMKK8RwAwsswPAXD0Lgwx1rPLBbgAILP6IAIw8zFIgD
azTSiNwkPyzwww5KooACjzzE9tyYY4bI0AI+LMDDAjEsUAObC+AA55s3qInmbWuuaQKce5KwAAwL9LmAC3Zyl8mhmVz5yKKH2MLoozoFAgA7
} -gamma 1.0 -height 0 -width 0

wm iconphoto . iconCert_32x32

set raca 0
if {$argc > 0 } {
    if {[lindex $argv 0] == "ra"} {
	set raca 1
    }
}
option add *Dialog.msg.wrapLength 6i
option add *Dialog.dtl.wrapLength 6i

global myDir
set mydir [file dirname [info script]]
set dd [encoding dirs]
encoding dirs [list $dd $mydir]
msgcat::mclocale ru
if {$typesys == "x11" } {
    ::msgcat::mcload [file join [file dirname [info script]] $mydir]
    catch {tk_getOpenFile foo bar}
    set ::tk::dialog::file::showHiddenVar 0
    set ::tk::dialog::file::showHiddenBtn 1
}

set myDir $mydir
set ::aquamenu ""
###############
if {1} {
#  set ::typetlf 1
  package provide ttk::theme::Breeze
  source [file join $myDir breeze.tcl]
  ttk::style theme use Breeze
  ttk::style configure TEntry  -padding -3
#ttk::style configure TCombobox  -padding {0 2 0 0}
  ttk::style configure TCombobox  -padding -3
  ttk::style configure . -font "Helvetica 10"
}

ttk::style map MyBorder.TButton -background [list disabled white pressed gray64 active skyblue !active #e2e2e1]
ttk::style configure MyBorder.TButton -background #e2e2e1  -borderwidth 1
ttk::style configure MyBorder.TButton  -font TkFixedFont -padding 2


ttk::style configure white.TEntry  -foreground black
ttk::style configure blue.TEntry  -foreground blue
ttk::style configure red.TEntry  -foreground red
ttk::style configure cyan.TEntry  -foreground blue

# openURL:
#    Sends a command to the user's web browser to view a webpage given
#    its URL.
#
proc openURL {url} {
  global typesys
  global macos
  #  global windowsOS
  set windowsOS 0
  if {$typesys == "win32"} {
    set windowsOS 1
  }
  #  busyCursor .
  if {$windowsOS} {
    # On Windows, use the "start" command:
    regsub -all " " $url "%20" url
    if {[string match $::tcl_platform(os) "Windows NT"]} {
      catch {exec $::env(COMSPEC) /c start $url &}
    } else {
      catch {exec start $url &}
    }
  } elseif {$macos} {
    # On Mac OS X use the "open" command:
    catch {exec open $url &}
  } else {
    # First, check if xdg-open works:
    if {! [catch {exec xdg-open $url &}] } {
      #lauch default browser seems ok, nothing more to do
    } elseif {[file executable [auto_execok firefox]]} {
      # Mozilla seems to be available:
      # First, try -remote mode:
      if {[catch {exec /bin/sh -c "$::auto_execs(firefox) -remote 'openURL($url)'"}]} {
        # Now try a new Mozilla process:
        catch {exec /bin/sh -c "$::auto_execs(firefox) '$url'" &}
      }
    } elseif {[file executable [auto_execok iceweasel]]} {
      # First, try -remote mode:
      if {[catch {exec /bin/sh -c "$::auto_execs(iceweasel) -remote 'openURL($url)'"}]} {
        # Now try a new Mozilla process:
        catch {exec /bin/sh -c "$::auto_execs(iceweasel) '$url'" &}
      }
    } elseif {[file executable [auto_execok mozilla]]} {
      # First, try -remote mode:
      if {[catch {exec /bin/sh -c "$::auto_execs(mozilla) -remote 'openURL($url)'"}]} {
        # Now try a new Mozilla process:
        catch {exec /bin/sh -c "$::auto_execs(mozilla) '$url'" &}
      }
    } elseif {[file executable [auto_execok www-browser]]} {
      # Now try a new Mozilla process:
      catch {exec /bin/sh -c "$::auto_execs(www-browser) '$url'" &}
    } elseif {[file executable [auto_execok netscape]]} {
      # OK, no Mozilla (poor user) so try Netscape (yuck):
      # First, try -remote mode to avoid starting a new netscape process:
      if {[catch {exec /bin/sh -c "$::auto_execs(netscape) -raise -remote 'openURL($url)'"}]} {
        # Now just try starting a new netscape process:
        catch {exec /bin/sh -c "$::auto_execs(netscape) '$url'" &}
      }
    } else {
      foreach executable {iexplorer opera lynx w3m links epiphan galeon
      konqueror mosaic amaya browsex elinks} {
        set executable [auto_execok $executable]
        if [string length $executable] {
          # Is there any need to give options to these browsers? how?
          set command [list $executable $url &]
          catch {exec /bin/sh -c "$executable '$url'" &}
          break
        }
      }
    }
  }
  #  unbusyCursor .
}

#Чтение файла по URL
proc readca {url} {
  set cer ""
  #Проверяем тип протокола
  if { "https://" == [string range $url 0 7]} {
    puts "HTTPS=$url"
    http::register https 443 ::tls::socket
  }
  #Читаем сертификат в бинарном виде
  if {[catch {set token [http::geturl $url -binary 1]
    #получаем статус выполнения функции
    #	http::wait $token
    set ere [http::status $token]
    if {$ere == "ok"} {
      #Получаем код возврата с которым был прочитан сертификат
      set code [http::ncode $token]
      if {$code == 200} {
        #Сертификат успешно прочитан и будет созвращен
        set cer [http::data $token]
      } elseif {$code == 301 || $code == 302} {
        #Сертификат перемещен в другое место, получаем его
        set newURL [dict get [http::meta $token] location]
        #puts "newURL=$newURL"
        #Читаем сертификат с другого сервера
        set cer [readca $newURL]
      } else {
        #Сертификат не удалось прочитать
        set cer ""
      }
    }
  } error]} {
    #Сертификат не удалось прочитать, нет узла в сети
    set cer ""
  }
  return $cer
}
proc waitevent {w {interval 20}} {
  global typesys
#  set w ".topwait"
  catch {destroy $w}
  labelframe $w -text "Идет процесс подписания" -bg white -relief groove -bd 0 -bg white  -highlightbackground chocolate -highlightthickness 3 -font {Times 11 bold}
  label $w.lwait -text "Начался процесс подписания\n\nдокумента из файла\n\nXAXAXA\n\nПодождите некоторое время!" -bg snow  -fg blue
  pack $w.lwait -pady 5 -padx 5 -fill x
  ttk::progressbar $w.fwait -mode indeterminate
  pack $w.fwait -fill x -expand 1
  $w.fwait start $interval
}
#Загрузка дистрибутива
proc readdistr {urldistr w} {
  global typesys
  global home
  set dir [tk_chooseDirectory -initialdir $home -title "Каталог для дистрибутива" -parent $w]
  if {$typesys == "win32" } {
    if { "after#" == [string range $dir 0 5] } {
      set dir ""
    }
  }
  if {$dir == ""} {
    return
  }
  waitevent .about.topwait
  .about.topwait configure -text "Идет процесс загрузки"
  .about.topwait.lwait configure -text "Начался процесс загрузки дистрибутива\n[file tail $urldistr]\n\nПридется подождать!"
    place .about.topwait -in $w.text  -relx 0.2 -rely 0.0 -relwidth 0.6
#    tk busy hold ".st.fr1"
#    tk busy hold ".st.fr3"

  set filedistr [readca $urldistr]
  if {$filedistr != ""} {
    set f [file join $dir [file tail $urldistr]]
    set fd [open $f w]
    chan configure $fd -translation binary
    puts -nonewline $fd $filedistr
    close $fd
    tk_messageBox -title "Загрузить дистрибутив" -icon info -message "Дистрибутив сохранен в файле\n$f"  -parent $w
  } else {
    tk_messageBox -title "Загрузить дистрибутив" -icon info -message "Не удалось загрузить дистрибутив \n$urldistr"  -parent $w
  }
destroy .about.topwait
#    tk busy forget ".st.fr1"
#    tk busy forget ".st.fr3"
#    place forget .topclock
}

#Список токенов со слотами
proc listts {handle} {
  if {[catch {set slots [pki::pkcs11::listslots $handle]} result]} {
	set cm [string first "TOKEN_NOT_RECOGNIZED" $result]
	if { $cm != -1} {
#У Токена отсутствует лицензия
	    set ::pkcs11_status 3
	    tk_messageBox -title "Токен" -icon info -message "Отсутствует лицензия на программный токен\n$::pkcs11_module" -detail "Обратитесь к вкладке \"Создать токены\"" -parent .
	    return ""
	}
	set cm [string first "CRYPTOKI_NOT_INITIALIZED" $result]
	if { $cm != -1} {
#У Токена отсутствует лицензия
	    set ::pkcs11_status 2
	    tk_messageBox -title "Токен" -icon info -message "Токен не проинициализирован" -detail "$result" -parent .
	    return ""
	}
	set ::pkcs11_status -1
	tk_messageBox -title "Библиотека PKCS#11" -icon error -message "Проблемы с библиотекой или токеном" -detail "$::pkcs11_module\n$result" -parent .
	return ""
  }

  set listtok {}
  foreach slotinfo $slots {
    set slotid [lindex $slotinfo 0]
    set slotlabel [lindex $slotinfo 1]
    set slotflags [lindex $slotinfo 2]
    set tokeninfo [lindex $slotinfo 3]

    if {[lsearch -exact $slotflags TOKEN_PRESENT] != -1} {
      lappend listtok $slotlabel
      lappend listtok $slotid
      lappend listtok $tokeninfo
      lappend listtok $slotflags
    }
  }
  #Список найденных токенов в слотах
  #    puts $listtok
  return $listtok
}

# Generate a PKCS#10 Certificate Signing Request

proc list_to_dn_tc26 {name} {
  set ret ""
  foreach {oid_name value} $name {
#puts "list_to_dn_tc26: oid_name=$oid_name value=$value"
    if {$oid_name == "INN" || $oid_name == "OGRN" || $oid_name == "OGRNIP" || $oid_name == "SNILS" } {
      set asnValue [::asn::asnNumericString $value]
    } elseif {[string tolower $oid_name] == "email"} {
      set value_em [string map {"@" "A"} $value]
      set ll [string is graph $value_em]
      if {$ll == 1} {
        set asnValue [::asn::asnEncodeString 16 $value]
      } else {
        set asnValue [::asn::asnUTF8String $value]
      }
    } elseif {![regexp {[^ A-Za-z0-9'()+,.:/?=-]} $value]} {
      set asnValue [::asn::asnPrintableString $value]
    } else {
      set asnValue [::asn::asnUTF8String $value]
    }

    append ret [::asn::asnSet \
    [::asn::asnSequence \
    [::asn::asnObjectIdentifier [::pki::_oid_name_to_number $oid_name]] \
    $asnValue \
    ] \
    ] \
  }

  return $ret
}

proc create_asnextkey {oids} {
  if {[llength $oids] == 0} {
    return ""
  }
  set extkeyuse ""
  foreach oid $oids {
    set oidt [string map {"." " "} $oid]
    append extkeyuse [::asn::asnObjectIdentifier $oidt ]
  }
  set asnextkeyuse  [::asn::asnSequence [::asn::asnObjectIdentifier "2 5 29 37"] \
  [::asn::asnOctetString  \
  [::asn::asnSequence $extkeyuse] \
  ] \
  ]

  return $asnextkeyuse
}
proc ::pki::pkcs::create_csr_OK {profilename typegost userkey_hex namelist subjectsigntool extkeyuse {encodePem 0} aa} {
  global profile_options
  variable certfor
  if {$typegost == "g12_512"} {
    set ckm "CKM_GOSTR3410_512"
    set stribog "stribog512"
    set signkey "1 2 643 7 1 1 3 3"
  } elseif {$typegost == "g12_256"} {
    set ckm "CKM_GOSTR3410"
    set stribog "stribog256"
    set signkey "1 2 643 7 1 1 3 2"
  } elseif {$typegost == "gost2001"} {
    set ckm "CKM_GOSTR3410"
    set stribog "gostr3411"
    set signkey "1 2 643 2 2 3"
  } else {
    return ""
  }

  set extreq "1 2 840 113549 1 9 14"
  set subjectst "1 2 643 100 111"
  #puts "DN=$namelist"
  set userkey [binary format H* $userkey_hex]
  array set ar_aa $aa
  if {[info exists ar_aa(group)]} {
    ::asn::asnGetSequence userkey userkey1
    set userkey $userkey1
  }

  #Идентификатор ключа получателя (CKA_ID)
  binary scan  $userkey H*  userk_hex
  array set infopk [parse_key_gost $userk_hex]
  set pubkeysub  [binary format H* $infopk(pubkey)]

  set pkcs11id_hex [::sha1::sha1  $pubkeysub]
  set pkcs11id_bin  [binary format H* $pkcs11id_hex]  
#Это код для lcc_sha - у негo возврат в бинарном виде. ::sha1::sha1 возвращает в hex
#  set pkcs11id_bin [lcc_sha1 $pubkeysub]
#  binary scan $pkcs11id_bin H* pkcs11id_hex
  
  # "id-ce-subjectKeyIdentifier" = 2 5 29 14
  #tk_messageBox -title "create_csr_OK" -icon info -message "$ckm\n$pkcs11id_hex" -detail "$infopk(pubkey)"
  set idsub [::asn::asnSequence \
  [::asn::asnObjectIdentifier [::pki::_oid_name_to_number "id-ce-subjectKeyIdentifier"]] \
  [::asn::asnOctetString [::asn::asnOctetString $pkcs11id_bin]] \
  ]

  set name [list_to_dn_tc26 $namelist]
  #Creare asn1 keyusage
  set k 0
  set ku_m ""

    # get data from profile
    array set prof [openssl::Profile_GetData $profilename]
    openssl::Profile_Unpack prof
#puts "PROF_UNP="
#parray prof

  array set opts [array get profile_options]
  foreach v $opts(CA_ext.keyUsage.options) {
    append ku_m $prof(CA_ext.keyUsage.$v)
  }
  #puts "KU=$ku_m"
  set one_last [string last "1" $ku_m ]
  set ku_m [string range $ku_m 0 $one_last]
  set asn_ku [::asn::asnBitString $ku_m]
  #binary scan $asn_ku H* ku_hex
  #puts "KU_HEX=$ku_hex"
  set id_ce_bc ""

  set ext_bc ""
  if {$id_ce_bc != "" } {
    set critical [lindex $id_ce_bc 0]
    set allowCA [lindex $id_ce_bc 1]
    set caDepth [lindex $id_ce_bc 2]

    if {$caDepth < 0} {
      set extvalue [::asn::asnSequence [::asn::asnBoolean $allowCA]]
    } else {
      set extvalue [::asn::asnSequence [::asn::asnBoolean $allowCA] [::asn::asnInteger $caDepth]]
    }
    set  ext_bc [::asn::asnSequence \
    [::asn::asnObjectIdentifier [::pki::_oid_name_to_number "id-ce-basicConstraints"]] \
    [::asn::asnBoolean $critical] \
    [::asn::asnOctetString $extvalue] \
    ]	
  }
  set extsubsigntool ""
  if {$subjectsigntool != ""} {
    set extsubsigntool [::asn::asnSequence [::asn::asnObjectIdentifier $subjectst] \
    [::asn::asnOctetString [::asn::asnUTF8String $subjectsigntool]] \
    ]
  }

  set cert_req_info [::asn::asnSequence \
  [::asn::asnInteger 0] \
  [::asn::asnSequence $name] \
  [::asn::asnSequence $userkey ] \
  [::asn::asnContextConstr 0 \
  [::asn::asnSequence [::asn::asnObjectIdentifier $extreq] \
  [::asn::asnSet \
  [::asn::asnSequence \
  $ext_bc \
  [::asn::asnSequence [::asn::asnObjectIdentifier "2 5 29 15"] \
  [::asn::asnOctetString $asn_ku] \
  ] \
  $extkeyuse \
  $extsubsigntool \
  $idsub \
  ] \
  ] \
  ] \
  ] \
  ]

  #Посчитать хэш от tbs-сертификата!!!!
  binary scan $cert_req_info H* tbs_csr_hex
  #puts "AA=$aa"
  #puts "TBS_CSR=$tbs_csr_hex"
  #Оригинал для Хэш передается в оригигальном виде
  if {$typegost == "gost2001"} {
    set digest_hex    [pki::pkcs11::digest $stribog $cert_req_info  $aa]
  } else {
    set digest_hex    [pki::pkcs11::dgst $stribog $cert_req_info]
  }
  #puts "DIGEST=$digest_hex"
  #Определяем на каком ключе токен или LCC создается запрос
  if {![info exists ar_aa(group)]} {
    set sign_csr_hex  [pki::pkcs11::sign $ckm $digest_hex  $aa]
    if {[catch {set verify [pki::pkcs11::verify $digest_hex $sign_csr_hex $aa]} res] } {
      #	puts "BEDA=$res"
      return ""
    }
  } else {
    # generate random bytes for signature
    set lenkey [string length $ar_aa(privkey)]
#    puts "LENKEY=$lenkey"
    set rnd_ctx [lrnd_random_ctx_create ""]
    set rnd_bytes [lrnd_random_ctx_get_bytes $rnd_ctx $lenkey]
    set digest_bin [binary format H* $digest_hex]
                	
    if { $lenkey == 32 } {
      set sign_csr [lcc_gost3410_2012_256_sign $ar_aa(group) $ar_aa(privkey) $digest_bin $rnd_bytes]
    } elseif {$lenkey == 64 } {
      set sign_csr [lcc_gost3410_2012_512_sign $ar_aa(group) $ar_aa(privkey) $digest_bin $rnd_bytes]
    } else {
      puts "BAD key=$lenkey"
      return ""
    }
    binary scan  $sign_csr H*  sign_csr_hex
    set verify 1
    set len_sign [string length $sign_csr]
#    puts "::pki::pkcs::create_csr_OK for LCC=$len_sign"
    if { $len_sign != 128 && $len_sign != 64} {
      puts "BAD signature=$len_sign"
      return ""
    }
  }
  if {$verify != 1} {
    puts "BAD SIGNATURE=$verify"
    return ""
  } else {
    puts "SIGNATURE OK=$verify"
  }

  set signature [binary format H* $sign_csr_hex]

  binary scan $signature B* signature_bitstring
        	
  set cert_req [::asn::asnSequence \
  $cert_req_info \
  [::asn::asnSequence [::asn::asnObjectIdentifier $signkey] [::asn::asnNull]] \
  [::asn::asnBitString $signature_bitstring] \
  ]

  if {$encodePem} {
    set cert_req [::pki::_encode_pem $cert_req "-----BEGIN CERTIFICATE REQUEST-----" "-----END CERTIFICATE REQUEST-----"]
  }
  return $cert_req
}

proc CreateRequestTCL {profilename attributes} {
  global env
  global typeCert

  upvar $attributes attr
  array set tkey {gost2001 gost2001 gost2012_512 gost3410-2012-512 gost2012_256 gost3410-2012-256}
  set oidtype ""
#puts "profilename=$profilename "
#parray attr

  set temp ""

  #Тип ключа
  set typegost ""
  switch -- $attr(default_key) {
    "gost2001" {
      set typegost gost2001
      set stribog gostr3411
    }
    "gost2012_256" {
      set typegost g12_256
      set stribog stribog256
    }
    "gost2012_512" {
      set typegost g12_512
      set stribog stribog512
    }
    default {
	tk_messageBox -title "Токен PKCS#11" -icon error -message "Неподдерживаемый тип ключа: $attr(default_key)" -parent .
	return
    }
  }
########### ЗАГРУЖАЕМ БИБЛИОТЕКУ PKCS#11 ###################################
  catch {set ::handle [pki::pkcs11::unloadmodule $::handle]}
  if {[catch {set ::handle [pki::pkcs11::loadmodule "$attr(libp11)"]} result]} {
	tk_messageBox -title "Токен PKCS#11" -icon error -message "Проблемы с токеном.\nПроверьте библиотеку:\n$attr(libp11)\nи сам токен" -detail "Ошибка:$result"
	return ""
  }
  set lists [listts $::handle]
  if {[llength $lists] == 0} {
#Отсутствует подключенный потен
	tk_messageBox -title "Токен PKCS#11" -icon error -message "Нет подключенного токена.\nВставьте токен" -detail "Библиотека:$attr(libp11)"
	return
  }
  set i 0
  set ::tokeninfo ""
  foreach {lab slotid tokeninfo slotflags} $lists {
#puts "FLAGS=$slotflags"
    #	    puts "Токен \"$lab\" находится в слоте \"$slotid\""
    lappend ::listtok $lab
    
    if {$i == 0} {
      set ::tokeninfo "Информация о токене:\nМетка: [lindex $tokeninfo 0]\nПроизводитель: [lindex $tokeninfo 1]\nТип: [lindex $tokeninfo 2]\nСерийный номер: [lindex $tokeninfo 3]\nНомер слота: $slotid"
    }
      set ::slotid_tek $slotid
      set ::slotid_teklab $lab
      set ::sflags $slotflags
#    set cm [string first "CKF_USER_PIN_INITIALIZED" $slotflags]
if {1} {
    set cm [string first "USER_PIN_INITIALIZED" $slotflags]
    if { $cm == -1} {
#Токен не инициализирован
	set ::pkcs11_status 2
	tk_messageBox -title "Токен PKCS#11" -icon error -message "Токен не проинициализирован\nБиблиотека:$attr(libp11)" -detail "Информация о токене:\n$::tokeninfo"
	return $slotflags
    }
}
    incr i
  }
 
  set token_slotid $::slotid_tek
#  puts "token_slotid=$token_slotid"
  if { [pki::pkcs11::login $::handle $token_slotid $attr(keypassword)] == 0 } {
    tk_messageBox -title "Запрос на сертификат" -message "Не смогли залогиниться на токене\nПроверьте PIN-код." -detail "Информация о токене:\n$::tokeninfo" -icon error  -parent .
    return ""
  }
  set aa [list "pkcs11_handle" $::handle "pkcs11_slotid" $token_slotid]
tk_messageBox -title "Запрос на сертификат" -message "type=$typegost tpkey=$attr(default_param)" -detail "$aa" -icon error  -parent .
  array set genkey [::pki::pkcs11::keypair $typegost $attr(default_param) $aa ]
  #puts "Ключевая пара $typegost создана"
#parray genkey
#puts "pkcs11_id=\"$genkey(pkcs11_id)\""
  lappend aa "pkcs11_id"
  lappend aa $genkey(pkcs11_id)
  #Установить метку ключевой пары
  lappend aa "pkcs11_label"
  set ::egais 0
  if {$::egais == 1 && $attr(type) != "Физическое лицо"} {
    set tekt [clock format [clock seconds] -format {%y%m%d%H%M}]
    if {$attr(type) == "Индивидуальный предприниматель"} {
      set lenkpp 0
      set inn $attr(INN)
    } else {
      set lenkpp [string length $attr(UN)]
      set inn [string trimleft $attr(INN) "0"]
    }
    if {$lenkpp != 0 && $lenkpp != 9 } {
      tk_messageBox -title "Запрос на сертификат" -message "Ошибка в поле КПП." -detail "Поле должно быть пустым или содеожать 9 цифр" -icon error  -parent .
      return ""
    }
    if {$lenkpp == 9} {
      set labkey "$tekt-$inn-$attr(UN)"
    } else {
      set labkey "$tekt-$inn"
    }
  } else {
    set labkey $attr(CN)
  }
#  puts "labkey=$labkey"
  lappend aa $labkey
  pki::pkcs11::rename key $aa

  lappend aa "pubkeyinfo"
  lappend aa $genkey(pubkeyinfo)

  #####################
  #puts "PUBKEYINFO=$genkey(pubkeyinfo)"
  set   userkey_hex  $genkey(pubkeyinfo)

  set ekeyuse ""
  set oids ""
if {0} {
  if {$attr(type) == "Юридическое лицо" && $::egais == 1 } {
    set oids $::oidegais
    if {$::lisalko == 1} {
      #	    lappend oids $::oidalko
      lappend oids $::oidlizfsrar

    }
  } elseif {$attr(type) == "Индивидуальный предприниматель" && $::egais == 1 } {
    set oids $::oidegais
    if {$::lisalko == 1} {
      #	    lappend oids $::oidalko
      lappend oids $::oidlizfsrar
    }
  }
}
  set ekeyuse [create_asnextkey $oids]

  set usercsr [ pki::pkcs::create_csr_OK $profilename $typegost $userkey_hex  $attr(dncsr) "" $ekeyuse 1 $aa]
#puts $usercsr
  return [list $usercsr $labkey]
}

proc feselect {tdialog c typew titul tekdir var msk } {
  global wizDatacsr;
  #rdialog - open|save|dir
#Из-за массивов ставим catch
  catch {  variable $var}
#  pack forget $c.fratext

  switch -- $tdialog {
    "open"        {
      set vrr [FE::fe_getopenfile $typew "$c.sfile" $tekdir $msk]
    }
    "save" {
    }
    "dir" {
      set vrr [FE::fe_choosedir $typew "$c.sfile" $tekdir]
    }
    default {
      tk_messageBox -title "Файловый проводник" -icon info -message "Неизвестная операция=$tdialog"
      return
    }
  }

  set fm "$c.sfile"
  $fm.titul.lab configure -text $titul

#  puts "vrr=$vrr"
  if {$typew == "frame"} {
    tk busy hold ".cm.opendb"

    place $c.sfile -in .cm.mainfr.who  -relx 0.12 -rely 4.0  -relwidth 0.75
    $c.sfile configure -relief flat -bd 0 -bg white  -highlightbackground #c0bab4 -highlightthickness 5
    raise $c.sfile
  } else {
       wm minsize "$c.sfile" 400  400
  }
#  puts "wait ::otv"
  vwait $vrr
  ###################
#  puts "var=$var"
#  puts "subst=[subst $$vrr]"
  set $var [subst $$vrr]
  if {$typew == "frame"} {
    tk busy forget ".cm.opendb"
  }
  return [subst $$vrr]
}

proc menu_disable {} {
    set w ".cm.menunew"
    $w.database entryconfigure 0 -state disabled
    $w.database entryconfigure 4 -state disabled
    set i 0
    while {$i < 7} {
	$w.certificates entryconfigure $i -state disabled
	incr i 2
    }
    
    $w.options entryconfigure 0 -state disabled
}
proc menu_enable {} {
    set w ".cm.menunew"
    $w.database entryconfigure 0 -state normal
    $w.database entryconfigure 2 -state normal
    $w.database entryconfigure 4 -state normal
    set i 0
    while {$i < 13} {
	$w.certificates entryconfigure $i -state normal
	incr i 2
    }
    $w.options entryconfigure 0 -state normal
    $w.options entryconfigure 2 -state normal
}

proc setTempDir {} {
  global myDir
  global lirssl_static
  set ::calog "ca.log"
  switch -- $::tcl_platform(platform) {
    "windows"        { 
	set tempDir $::env(TEMP) 
	set lirssl_static [file join $tempDir lirssl_static.exe]
	if {[file exists $lirssl_static]} {
	    file delete -force  $lirssl_static
	}
	::freewrap::unpack [file join $myDir "lirssl_static.exe"] $tempDir
        set tclpkcs11 [file join $myDir tclpkcs11.dll]
    }
    "unix" - default { 
	set tempDir "/tmp" 
	set lirssl_static [file join $tempDir lirssl_static]
	if {[file exists $lirssl_static]} {
	    file delete -force  $lirssl_static
	}
	::freewrap::unpack [file join $myDir "lirssl_static"] $tempDir
        set tclpkcs11 [file join $myDir tclpkcs11.p11]
    }
  }
  set ::calog [file join $tempDir $::calog]
  set alloids [file join $myDir alloids.tcl]
  source $alloids
  load $tclpkcs11 Tclpkcs11
  source [file join $myDir "cert2text.tcl"]
  source [file join $myDir "tkfe.tcl"]
  return $tempDir
}

set pathutil [setTempDir]
if { $::tcl_platform(platform) eq "unix" &&
                [catch {file attribute $lirssl_static -permissions +x} rc]} {
    tk_messageBox -title "Выбор утилиты lirssl_static"   -icon error -message "Нет полномочий на смену атрибутов\n$lirssl_static"  -parent .
}

font configure TkDefaultFont -size 10
font configure TkFixedFont -size 10

option add *Entry.background white
#Для tk_message
ttk::style configure TFrame -background white
ttk::style configure TLabel -background #eff0f1
# CAFL63 Logo
ttk::style configure ClientArea.TFrame -background #e0e0da -borderwidth 2 -relief groove -padx 0
ttk::style configure basic.TFrame -background #eff0f1 -borderwidth 2 -relief groove -padx 0 -pady 2

ttk::style configure Label.TLabel -background #e0e0da -bd 8 -relief flat -font {Times 10 bold italic}  -padx 15
ttk::style configure labTit.TLabel -background #e0e0da -anchor center -bd 8 -relief flat -font {Times 10 bold italic}  -padx 15   -width 40 -height 2 
ttk::style configure sep1.TSeparator -height 2 -borderwidthd 2 -relief groove
ttk::style configure sep.TFrame -background #c0bab4 -borderwidth 8 -relief groove
ttk::style configure title.TFrame -background #eff0f1  -relief flat 
ttk::style configure butFr.TFrame      -background #eff0f1 -borderwidth 2 -relief groove -padx 4
ttk::style configure area.TFrame      -background white -borderwidth 2 -relief groove -padx 0
ttk::style map TButton -background [list disabled #d9d9d9 pressed #a3a3a3  active #ff6a00] -foreground [list disabled #a3a3a3] -relief [list {pressed !disabled} sunken]
ttk::style configure My.TButton -borderwidth 3
ttk::style configure TButton -borderwidth 3  -background #cdc7c2
ttk::style map My.TButton -background [list disabled #d9d9d9  active red] -foreground [list disabled #a3a3a3] -relief [list {pressed !disabled} sunken]
ttk::style configure MenuAqua.TButton -borderwidth 0 -background #e0dfde -relief flat
ttk::style map MenuAqua.TButton -background [list disabled #d9d9d9  active #ffffff  pressed #a3a3a3] -foreground [list disabled #a3a3a3] 
ttk::style configure Menu.TButton -borderwidth 0 -background #red -relief flat
################
#catch {font configure TkDefaultFont -size  10}
#catch {font configure TkFixedFont -size  10}
image create photo upArrow -data {
    R0lGODlhDgAOAJEAANnZ2YCAgPz8/P///yH5BAEAAAAALAAAAAAOAA4AAAImhI+
    py+1LIsJHiBAh+BgmiEAJQITgW6DgUQIAECH4JN8IPqYuNxUAOw==}
image create photo downArrow -data {
    R0lGODlhDgAOAJEAANnZ2YCAgPz8/P///yH5BAEAAAAALAAAAAAOAA4AAAInhI+
    py+1I4ocQ/IgDEYIPgYJICUCE4F+YIBolEoKPEJKZmVJK6ZACADs=}
image create photo noArrow -height 14 -width 14

image create photo icon_openfile_18x16 -data {
  iVBORw0KGgoAAAANSUhEUgAAABIAAAAQCAYAAAAbBi9cAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAB3RJTUUH4wYXCDgNebfI9AAAAgZJ
  REFUOMuNkz9PFUEUxX/3zuxbQAlSkGhhaWEwRhNbY6Extmhi7Kz5CH4P/RZY2FnYEG20sKOSaExEBNTn44+P3Tdzr8U8Hw8k4G0mszvn5PzO7MrrO/PcfLXCSfPm3pXr
  9bnwLtQS8SMvFZqttCwAbxeuznY/9BfcCQcnisL3SDPzE4/mF8/f7cxViEp5bg6tE6ciK0/XiADd1f7Da08uPtOACoK7I5WgAFGQCZE4HQ6Fsex4MthLuHkxcqeuJlVj
  LSK1IB1BRJApxRsjnlXcIXrA1BGHrJABQkkYAVK3az64gHcEiQEUpFLUgQ5IE1B1jIRkcBfwDA4SO2AQt148eD59+fYNjb8LvgqFCeRIqYfqc8j9lv7Hl0gUos7N3a8v
  LY6dEP53rPeN9v3SAVqZ3eFWjokwFgMbWw0VGTfKuPdAAhBOSZYYadgGP2S0A/KjiD2AnIDnBmLFUH7hB7dmwAbwtRhJOAZr1ApIGqZNwC4iERgQsQxs4qwNseQELB8Z
  iifE+5AFHCJmwHfUNgDFVE8xy6g5WAJaDMXxv2hdaDYhhvIRov/6+BANIDlYhpRHNUSJWjaxLSVbUbkabo7j5Uc1QV2LLghEJ2TDg2KND+L+6pfl9fWlW4PeLm030/40
  9rcb0p7R9MCahJ6pqCedaiZQz1R0ZiOdWSVMKe3nwafBjj3+A1B95HRZw8dhAAAAAElFTkSuQmCC
}

image create photo CertStampBad_71x100 -data {
R0lGODlhRwBkAOf/AEYqLEwvMFM1NtoXDlw5N1k7PNsaGFw+QD5IVGU/Pl9BQmJDRABcgXo/O9omGNonIGxFRGVHSA5dfr0yLABjgnBJSN4sKRRggGtMTdgxJ9AzLck1
L3FMT3pKShhignRNS64+Oh9ifQpoh2pSU4ZLS3FSU3hRT8k+NVJdaTVkeuA5M3xUUiFrhXtVWMVDNS1phYZUUH5WVXdYWcZEPM1CPyRtiIVXV4FZVzJsiMVIQt9CPMVK
PbNQSYVcWotbWYNdYM5LQjtwh8tOPIhfXaRYUn5jYsxQQsdSQctQTkhxieBLRMVTSYtiYM1RSYBmZYpjZk1zhuJNS4dmZ1dyiJVkY95SS8tYUbdfUtVXTpJpaGV1hoxs
bdBbTsxfW89gStJeVs5gUNVfTNldWNddY89hVplvbcdkVHN4h6xraNhhVNhiWppydeVfWH95hZZ0dXp7hNNlYIh4hc5oX9doXJB7gpt6e9lqZKB5g5p7g9ZuX9lsa+hq
ZNVva9dvZshzbtJxZa95gdJya9ByceVvZrV7fqp+gs52bMF5d7p7eZmEi7B/f9x0cMh5eqSDiqOEhN51bNd3cOlybtd4dtR6cNN6dtt5bNx7dM9+fdh9beF6e9l+dLiG
iMGFfMCFgr+GiLGLjM2Ef8iFhdeDdtmDcauOjeCAfuKAedyCeOGCc9KGfd2DfuiAfNiFftuEhNeGheCFe92JfN6Kg+iHh+OJhOmIf9WNit6MituOhOOPh+2RjdWYlcic
mbihn+SXhuqWkOWZjuSZlM+ppNunprm0s/KopMq0trm7uOiutcW5ue2vq+q0suS2tMq9vr/Bvta+vsTFwve4tMfJxsXKzc7Ix/W/v8rMydbJys3Oy/HGw+XLydDSz9TV
0t/S0tPY29fZ1t3Y1tvd2vDY1ffX1t7g3fPc2eHj4OTm4/nh3uvm5Obo5ejq5/Tn5/7n4+zu6/jr6/Lt7Orv8e/y7u/09/L08f/z8/T38/j2+vv29PT5/Pf59fz6/v/6
+fr8+fn///3//P///yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAP8ALAAAAABHAGQAAAj+AP8JHEiwoMGDCBMqXIgQRxxQndrg+PdiYpCHgLQIDMLiXxI6oRRp/Dfl
xb+LlwidYcFiZJA2lzyd2ShwCp1LhaCwrPHPISiZQQrSMTVL1KlXpVLxsaOKlSpNp1SpcpUHUqtTsUQ5bQVpTiBVR09piqVqKSVXUsW+0mTITqhQrE6pVdWHD9hYp0S9
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
}
image create photo CertStamp_71x100 -data {
R0lGODlhRwBkAOf/AHAFCGgKCXwKEXcQD3USFIkOEo8PD4QTEIMTFn8YFH8YGocXGJcTGpIZGIocG5IaHn8gIZ0ZF4seIY8gHp0cHlQwNqUbHK8ZG5ggIpkhHaIiIpsk
JKIiJ5QnJ4crK7QfHq0iIZ4mJtoXDq4kKKgnJdsaGKgoK7gkJ48wMbIoJaQtLZ0vM60sKUpHVrUsLbAvKwBcgdomGLkvKsEtLNonIHRCRboxMQ5dfZ06OrsyNwBjg90t
KRRggMA1NLc4N1tRYhhigmVQWQloiKJCQrc9P9M2Mq9DQ8g9NTNjesc+QN45MptLSiBqhcRCNC1ohMZEPKdNTbtJRC1tiMhGQ95BO9BFQMxHOcZJSsZLPsZLRM1KQTtw
h79RT8dSQUhxieBLRNBQRM9SSkxzhuJNS8lVSc5TUVdyiMpXUL1bVsdaUGV1hspcWdhZUeRXULJlYs9gSs9gUNVfTNVfUtRfWNddY3N4h8djZclkXdBjV9ZiX9FkX+Vf
WX95hXp7hIh4hcxoadFqYeNlYNBqZ9lpXpF7gqB5g9lrZtduYNJxZc9xcK95gdZwbNhwZ9Jya59/hrR6fal9gcp1cORvZc52bJqDisp4eaWCg910a+dyb9x1ctl3atd3
cNZ3ddF5dcR8frx/fdN6cLSDgryBhMWAeNh9bbGGid18dNt8e9J/fuB9cdl/ddSBdNiAe+KBeeGBf96DeeiAfN2Df9+EdNyEhcOLituGetKIhNiHhduIgNiKe9KLi+KI
g9mMgrWVleuIgeKMgOOPiOiOieOQju+NituYluOXk+SYjN+ak9SdnO+Zk+Glo9Gtq/Globi6t+exr76/vO+ysMq9vuW2tN27usLEwdfAvdDDw83HxsfJxvW/v8vNyvDG
w9nMzM/RzufMytPV0d/S0tbY1eTX2Nnb2N3f3PfY1+rd3eDi3/Td2ePl4ufp5fXo6P7m4+rs6fDr6enu8O7w7fvt7u7y9fHz7//z8/T38/j2+vv29PP4+/f59vz6/v/6
+fr8+fn///3//P///yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAP8ALAAAAABHAGQAAAj+AP8JHEiwoMGDCBMqdKIQoRQ/tj7xkfLPCcMtfkYpUiNwi0AvhDyF4vjP
zEU/qB7VkSKF5BY+qETV6SjQDCFUkMT8Y7kTokyPBAm12rVK1atTvBYZioUrltFYsW4d2jRLFa5aTWdtGtSIlVFVVlkp7XQLKthXqiYZ+uQJ1yu0r1gxWuQVl6pVr1LN
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
}
image create photo iconCertKey_71x100 -data {
R0lGODlhRwBkAOf/AFAyFTU8QwpGYdoWDgBPbxZNWtsaGBROZC1KR2w+E1ZILwBcgdomGNonIA5dfWxKJgBjgt4sKRRggAhoiN03MKJKKMo/NUhkSyhphJFVF6VQGsZE
NStsiMlGPdBFQMZLPshKRd5FPjtwh8JQQnxoPUhwiXNqTdBQRFBwiqxcTExzhrRgFc9TTKtdVbVjDeNQSspXUFt0h45qY6dpKmd0htBbTq9sIkqCdc5fT7lpM9NeV85g
VcJmRI13Os1iXOBdVr1vGcVuD3Z6hrZuTYJ5hLt2I9ZoYuJlYt1nXddqXdJrYpF7h8tuZrp5Md5pZs92E6F5g9Rtaph/g2qPc9Jya7J6fp9/httyadV0aNpybrGBVs9+
IdF/FdV1bqmBg7SERrt9e7GAgsyCIdV3ddF5dMWELsF/b9yAGdx5Z8t9dM2GFuV2b9p5ctR7cLyBhNx6ba6MQ8t+fOF+cdqLB9iAfM2IXeZ+euKAed6CctyCeOGBf+eK
HrKPkN2Ef9yEhciKiNiQI9uHetmHhuGGfNuIgdSKh+KQJtiLgdWVKOKIg7SZc+KXEr2dUtWTe+6Lh9CeLOSQieCcJ+WShOqQjNydQt+YjOOiI+SXj+GhO8qmTtyala6o
lfmiAN+mYOCoVs+ppNmvTvetC7azq+ulnfKjn++tR+iyOeyyMeixR+CyZuSzUfayMeqzVc27ke6wrvq4Q9XAYuizscm8vPm+HdXAdr7AveS2tOLAWdq6uPO/Pfu/SPzB
NcPFwtfAvfXDUvbESs3Gsu7HU9LFxcfJxuTNWdjIr/zKOvvKR8vNytjLzPbPUNnOsPLFwubRdPbNcOTOpOTLyM/RzfPRZ/7SQf7TTfrSY+PVltPV0d/S0v7YSNvWxefa
hv7ZUdbY1f/aWtnb2P/cY9/bzP7ebN3f3Pnhg+3gs/ba2OHk4O7qs/frnObp5f7m4+3s4+vs6ffvqvbp6eju8Pvt7u/x7u3y9f/z9fT38/v29Pn2+/P5+/f59v/+zf/6
+f36//r8+f3//P///yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAP8ALAAAAABHAGQAAAj+AP8JFIhhoMGDCBMqXJiwIMOEHIjEAUOEwz8OFkUsiVOFhkARBUtsDOPx
X4yMGztiwBDjo0Q3JUUIRCEljhcVKy1y2OhGiEyDS+4kCpRnkJ5DWYz0IdQnT54+fQQl6eInD6FATP10SUKFTlGnhOgkJSMIqtNBedoYAROHkFOndK5k8eo20KA3QgZi
6MNGT6A7bJyySBKoi6QrkKIMylJjR2FCiKkEYjPCh542iaJI6sKXhY7FdJRAGtPZSKIsiXxconoFRiDSbBJ1ySNoIBE7lWCc6KD60I4uhSCN6NABy6VEILIUusTiQwcq
x0FcOSRp+IcumvSA6ELoEowO0i/+ERqR51AlEBtY4IHUJgqh3M6VXOrT8l+VPFRYbDihwwiWK1gYkcQJLPBnBB47XKFEEjU0V4MSb+yQhRJGsFBDBzv4VwMWAZ5Qwwc6
KJFFEgoacQIOHeBgxBUAGqHDBx5sGEgVAhGRByQsFGfLjjz26GMsPv7YI5BBFimkLUC6QsYHO0ySBxEf9dFFF3gwUY8/WGap5ZZcdunll1/iY08UgUTRhh8GuZHHJW20
UQ8+YMYp55xcwmmPZJDcsYRBYOhwRR5kXEnnoIR+aQ+VLoahVxQ4fADDGPbIOY46lKpzjqWXYtpOpu2M88039ZwTzTXjeHrpN+rIA+ahIICAQxb+BoWRhR6ARhqnqOOc
c84110TTzTejfkrqNZieI8843eSq6znjIKNOO6t2wUYfWew50FXsjZEPl/18U+o3yX7DbLi65toOsed86u2nzHbqbbufIqvuOP1oeWggieThxUAqNOXDFVRsu2U+0Yx6
DTLRDJMwqQbz2qs6nrYDbMHXdCOPw+Ncky6yo44zar1Z3nmFD4P0YdE/VqyngwVU2EpoP8zmWmqmzC47s66F3mlBEonoKVAYhV3YhsuD9nNwsN1Egwwy1/DiMTK8RMPL
N8iATOehHdTQxiBQCBQDVDsgEXChWNZT7KWZWvqsuO2oY/XVVCQBQ1g//SPIevgJWqj+PFDLIkstyNTSzTDCRFPqMLUMw4vecEviViF8tkFUoFj2w7g/VvejucCW98NM
IvhYno85pGjeTz75yCMwoYfikQgWUhiUhQ4gGEHGPVjKE00tvNTi+zCf8sIL4r4nHk0/pDAQT5YvHLEP2VweCgMIOozBpw87YEGGrWbL86w87bQjj9nq1BM++PXUs88a
A9iBpSMG/AB99F0oocMONA4UBiGCZAEplu1InOKGcTFkDAMZ0OISPSLAgAiQYg0GYID85mevLozhEHeAEkH6oAdCVElQZuOU+cJXvsqZrh92GAADGDAAAzRAghS0FxUS
0QY7HGIgQujDJXZwgrH542L+SuMFMqjWjYMhTHdKg8YPIrjCJjLgBc+LoT/udAIlTCIQJalCmfTTBVvlQx3v0hSmLPYsaESAiU5s4iTWYY99uPF5UezS27DEKhYoYUYC
CQokYPCBluWOV+K6xro0lipwxeKFaUzjACLwAiSswRGJSMQkZuaxXyVrVOeQIYYOoQcNckAQbLCDHJhgq3YY7lQ2o1Q95mELNCbylU0cwA/wIT61bUpX4pNhILKAh9ro
70ZtElg9DpZJLzHDhbBM5gsbsA7WZaEPkMgDH9LkAyPIgQzC/MY1VNWleFAgmco0gAGYkbM2oEEJO4iDQciggw48Cnf+6J485jnP9MkDHyn+BGciI8hIc8xjnsai5xwr
6IEUKeFk/yACFu6Qh//FM2kHVJrGPNYLV+pTnD+4BDQkNowi1kJpo+Jmlw5FKyMoaiCFGES2uNeO9Lm0Hvl40yRUqE8GuNAJ0HhH+VCXvnwM1Ev3oAIhCHGHPwykBH24
w4JImbthDFBhw3NqCGq6QkdAQ5vnWNrSCpbAOd3pDT4ghB5OBgW71GADfoxnS2OKuvHV4x0UQCQ4B2CO0/k0pvVQXT1MN8+29ZWEgrJHFjqQhDwEomv2IUQWuGgreRwQ
ccOrxTcIF9eaGuAFwkucEJ2aMN8ZDmHfEOLBEDcOOnbBAxLCo0n6EAgfcEWYLc3+q2wtB1e5gtMAdqjnS2N6S/GRMHx4BdmdjOCDv6jgWoGIZlrVUbzAFY93HrBoMg1A
CKcKsXjtOGDSEjZEXs3xTpBIRB+MOhAvXCEs2yvbOcSX11TNEx6uGIBt52qHd8zDr3qFKUzHd7rLTbELdBjEFU4qkDZ8KAkOVYcoeNGr0B4wqiGQ7nR/QLScdSFHNYiC
Q1CmhCu8AZvqraX3wneObrTDHN+k6goHEAJzZElzgzqUgtKZJmBqq2zXCF/iRnuOj17jExIGJwVskbSMFaxgyBAp/QIhiDtYYSAiOERg5JDWfqjOe5RiFpYhxgwVO3EA
sUhVpdDW1eiNYRBdaIP+LxN6lB08h3u54kU35ixIE4cPS8nzMgNe6IqcZeEDShBEHvJin0E4AT1dzN2lTFUqiI2jpf6gByTmS1UDuDjGXWiVEySRPyHcoRI46KGg5PGu
c+Sjbc/KciwoQFM9r7AB5lCWpUrrpTsRFhJYJAgnm+LDUClLHrrqleE0YVNXO9EAR/DUNbDhKUNRQcp6gNy1ysOGMcAT2PTMdjvmwYxWG7uJsMYzOQ1lQQxqsMD3u4JD
L3YNpyJsGAfDRoS/nUYDOAJLx7z0SMfgoh2AwSBtoJ0PHGo+vMZUHqczRwMobezL4gMf5hgABezh0piGLAsj+EANrFdeLExOUNlNmML+KrYrXCyc3semQOGS0YABRGF4
TCOgafOghyyc2243CgRTf2hqmKLu5/aYKsqbeFl/iOmFEajr5kI2hvAGgryrzYNr0+pY4gVOeMLThLfpbQBSYIkeLzQAJEYahZEFQg8OCcMd2pCjRPvj1OCj525nynCq
tvwFFPeHOSJoAArsY54+tVMXNlADNhxWIF64AyHOSoVRWz2zvRucMApRd8v+QBgBHEYfaArm4i37vx8o7OH/0a8+uDYKAoN7X7OduoebYxIvYKE4YSnOFlIACbaAh7Hw
4Qq5DsAJ2MgUPKYYNx8kYqwD8YNK6ZDWAPZOeJDtXbNgLgxcaEIHIYhAy8H+3YAQ/IAOn5DFOx4rjDXsmeghkEXFmFaPOwWiKQS2GxUYmt63ozp8bdtUSxf9jvfOAx7v
AA3MsHCj8A7vAA8ICFwBmAgRIF/H9gL9N0/30A/2MAZtkAdXcG4cEAU7sAHV01hHszQK0w3dBVIFMw4HZEDDkAj8ZAe4kAwwiA3MAHtnhExf5jxbcijD8Sp84gRdEAj1
90UbYyn4tyndkGrPoiuW0gvat2cGsEgUEFcDsHWK1Gdbcg9dIAcBglgC8QeBMAnMN2q+UjHeUjFF5C65ok3aJEiQYFHiNHuVZwAREEchMxt5Yi3/IAJ+gAVscAeNhyX5
EDPL4i2lYkpswyz+pMIsSBBkVKUJ4aANGiNckmEEbXBDNXIHe/QBUQAnPFcpaqOE7aI2lvIp8GAHjPhKEUQBPNAJ29AMxEAMt0ALz8AOQcUbeUJoVTAIWJAjQ1M22jQp
4AJISUMs0RBImKIOx1R59dYAjYAO7pAO5EAOzjCN1WAMv9AKY5AiTDAInaZDNdBDjWUx9ZRt9NQOqaNt8wQJxVZTFvAM+lAOqUAJmcAIX9AENtAEqeALu1AGI2AEl5AH
9cEBVdEUUTBqTOMp6kAxBjQqzjKCGWNAFWMLTtCATLRwJydOI5AO7pAKXMAKm/AN8PB/4wAMWgAEnrALiNACdyBtAqEmhNAGlBP+T4+WhOb4UvqVKj11OuWTPubgCkdA
AQzURBFAAUkQjZRgCICgCuigDXiVPvMgCivQCauACEzwZAMRBxlyBfXXDsiALBCFZI/FKyJYRKmigglTjMggDOYADWzZC8NgDeKgCpFgCXR5C9awCbKAMAzmD8KgAZ4Q
CjmgTgPhBrRjBA6lOarjUy11Qox5QpjTmKfzmPUCDOCgCpZwCqeQC7lwCr6QDsDgmPaQAhrACovQAgYhBFlAFA4lMTE3DOOwOlLkD/DQDL5gCpmZC8eQm7sgDdugDRVU
AU2wCiRgEIWAifgBWzwFU5gTT/XCmI8pmZ1jOs+pDb/gC7h5DNSQndn+aQzVsA3AgA/88F9poAGvgAgDQQOsBQNcAXKZVQvXwDu94zvxGZ8C5DGa9VzDcA5ONQytoAy+
YAzTQA3ZwA0Eyg3UYAzO4J10RAVGUAGYEAoF8DNnBwMW4HapA1joiH/Z1lPmkz7u5VbPMg/WIA3KMA0DWqAoyp3NsAz4QA9d0AEVQAm7YAKIdweBgARoZSvq0DvIEJvc
Yg3kQA0o6g1ESqQGSg3VIA7LcA9ZYAE8IKM0Snp+MXVe9D1SNFD9YA3gcKJFCg7gUKQGegy+cAvFMAZJ4KCzcAEDcQjQ1FClZF0R9Vi8sCsj126i4lTC9m5UozTwNgzN
wKVE6qWCSqT+2XkMvxAMQ5AIQ4AJxoAA5TUrgMI5x5hlmXIs6bJexpJlokgp3oMqEEMLJkqggQoO4iAOXmqk1HAMuWAKpmAGM3AKxhChAsFOLKBusOmjW1IPzTANocoN
o1qqpkqoqbqZloAIW2AMj2AQVnBetYKrXlIO2QCgymAKvuoNXlqqp+oNhbqZkcAFjDqcA1EW7OFDzrol7bCrqFAEgCCq1jqo3nCkqnoKkQAIp2AJMsAvfPEvLfNGb8QP
/NCv/Mqv/7oPA0uwBetG/NAKwQAEQYAJBRqoRfqu22oJgLAKs/AFY0BWeQBqFUoIh+AHghCyfhAVfsA/ggCyhOAHKjuyKtv+B4UwslFxsisrCI1wCyvQsASqDMFQrUZ6
pNTAraEQCo8ABnlgLVrEBmdlAT5gB3mwImzwBhZgAR+QB31YA3kwG8TRAXLQBniAA1QrBx8QtWmBByxQB7fAsJiQDdmgDEVQBL+AogSaqr9gCpYQtI/QAmMwejHgFjCg
AzUwAh4LA9wRBQyCA0J1Wm9ACAJSAzjgHlcAAmxACOh0P1hwGjywsA17DGtrAy6wBYDwtgWaDapqCovACZzwCCkwN31wXAKRVJCgB0txB1fAAlGQB3dwCVFwCX2YBDvg
BE6hCbnbBneQBCoyCG0AvLqbB3UACkDwBJhwDLugDJwbBEHABYD+oLlriwiAoAZzwAmW8AUtwBRFZRAi8Ad2EAh2UQhCUAVjwAeCdgeDIAhCEAMTwQcYhBZ+ML9usARL
QAh2gAcrqQjBsAXO+7O+ML1B8ATVq7ncIAZioAZqUAYkIAOG9xd/sGEDwQFhIAV1MxAxAAWsexAlcBMJoQJeUAI3cLYFbI1F4AJPoMAr8ASnwKs9EAAIgAAFIAAfscEd
/BA+/MNTcAsEXArHMA2+0MIv/AQKIAA9YKI9cAA/HMVSvBDSEARnQMS78AtI/MIJMBCZAAdTHMZi/A9CfMXQq8UJ/MIZMMZsHMawIA1bYMZZXARBYANtfMdhrApxXAre
IKZ0fAaVdozHgswQoIAKe6wMfhzHe9AEg9zICJEJhrwHpQAO1BAMdLwHRQAAjrzJA4EKYiDJlFwNZfAEZ/AEM8DJnJwJhmAIpfAL3lANRbAFexDIqLzJRcDKuvAL4FAG
srzItczJYlAKr/AKvsDLhpABGfAAv7zJoPAKq6ALZSAGhiAGy4zKjIAKqNAETVAGRTADAVDN4AzOAQEAOw==
}

image create photo db_ca_40x40 -data {
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
}

image create photo db_build_40x40 -data {
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
4P3/AdTdUsZ4F77kAAAAAElFTkSuQmCC
}

image create photo keypair_40x39 -data {
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
}

image create photo validcert -data {
R0lGODlhKAATAOf/AJAFAHYOE5AICIkOErEGDGcdJKESE6wTGIQfI64WE4gkK4ImKZghIrkYGpIkJrMcF6ofILYhJbciIK4kKL8gHrAlI6cnK5stLLklKMIkJrsnI8sj
JcQmIZ4wNJgyMpM1NrUsLYY5QpU4PcAtLbgvNdEpKIM9SNknLNEqLp04QQ1dfZE8Q602N9QtK80wLcwwM7A5P88yLxZhgdcxM4hIUMk3OcM6PR1lhpFJTt44OCNpit85
PolQWtg8QRlvjyltjm9catxAP5RTWtVDSChwitdEQyBzk4daXzVvi69QWJJYYi9ylGlmdid4mKlYYLVVXTZ3mWBvdSx8nIplbZ1hZsdWWjB+n91SVoZpdDl9mZpmbTt/
mzOBocddY7phalt9haxob7Nna5VweJhwc218gr9mb3Z7fkuHnlOFnbltcaxwel+GlLJwfMJtbkmMp6V2e1OOpdJub06QrKx4hYGGicJ1ecF1fnSLj2iPnV2SpFOVsYeL
msJ8g3qRlaCIkniTnViatmOYqqmIj8KDh26arWKdtGChvmahuW6fuIGcppyVoXigrriRmWWmw9mJjWSpvsuRk3Opum+qwYOmrsaVmqqcqYqlr46lqp2ipHqrxICtwI+q
tIWtu3C0yqOoq3izypWtscqfop6qt7+kqIayxoC2yJayvIm1yY21w8imrXu7y7ets4y5zIW7zaqyuqS0upu3wb+utrGzr6m0wq+0tpq5yYi+0MuwtJa+zJK/043C1ba7
vsm4wKzAzJHH2by+u9u2t57G1JfI1arG0K7Gy77ExsXCx5jO4aDN4aTN28vFxKzM3LDM15zS5LvL0sTJzMfJxqHS36nR4LvP263W5KfY5bXV5b/T38PT2szR1LPY4LrW
4LLa6cbW3c/U18HZ3r7a5Lbe7brf59TZ3Mvc4rni8MPg6r7i68/f5sni57zl9Mfj7sLn8NXm7Mzp89/l59Ps8drq8cvw+dbv9N3t9NXy/dny9unu8ODx+Nrz+OT1/Oj1
9u/09/P4+/f9/////yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAP8ALAAAAAAoABMAAAj+AP8JHEiwoMGC9RImtMeQ4cGHCa2tq9dwnj10dWwMuZIKHr159EKG1HcQ
UDB381LSi5fOFQwvbGLFW0mumzMwGVDkgLRv37t+/cb5G1pQjxsjZ8yJZARChJA3NC7cuvfO2y5P98ZkOBFE2a9s0DA966eP5MBGjQzJWYLEHL9+H0TwE8TH3yoBjvi9
MyOrGJ0jGXK0KdYO26tt7tjJIyjHjeOB+4BZMOZPCQFKg3DE8TeO1rti2P6kaFHkEjNLprSxU/xwIL4wLEJluMDAw4AVXfDhm0cMlDlYTCjk0JJo07Bz7M61/vdtWK1R
IKgoEOMgzTQaXtwxg0Umiqk+eCz+tOjRS1w4ab6qGcx0alo7csM0YQHw5NqsKX7UGOAl7o4pS7CAc04wPAhXhi66NHOQFT/coAMh4CRDCiJ7LGCDHXMkgUAI2CSXXDnh
cKMLGhBwMEMVBJWAwkBNLKGDDCrAkcwpiFCzTAEFBGDCMuWIAyI31BzjSyufFALEARRs0MKSLeSAAgf/cAGFFE38ACMruUgiDTvSJIOLNNJMgoswi+BRSie2BENQAgk0
sMEMM3DQgEBWSGFnEzqocEgphyTzIzXRcPIFHmvkEQkqijhBQg1BDNTAA4/OORAXdkoBhQ8qFCJJIcgAKqQugRhqiyhadGDBBBVUoIELOyz3T6VdUhAhwxZNZOGLL7q0
0kknutRSyUMYYKBBDMvVSaUROvywhB66oomMOq4KhEEEGRR7JxRQWPGIKs2UE21BGqiaQQwuLFgpF59Q821rFUAwwgsPcSGvJOtGK0EFBAUEADs=
}
image create photo shieldbuild_40x40 -data {
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
9Db4fx/ez+7OrmsgAAAAAElFTkSuQmCC
}

image create photo subjectDN_40x33 -data {
iVBORw0KGgoAAAANSUhEUgAAACgAAAAhCAYAAACr8emlAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAB3RJTUUH4wECEiwdjvhS3gAAAB1p
VFh0Q29tbWVudAAAAAAAQ3JlYXRlZCB3aXRoIEdJTVBkLmUHAAAJh0lEQVRYw72Xf4xc1XXHP+fe997Ozk+zi38ANmt7HXuJMW4cu22ACmjSpmCKQ9QoqqwgfogmlBao
itI2VZWqbSJVTUkgVFaaqKGqWkqSyoWQIBpC6wQCBYsCNsJr7AS7thevvTszO7/fu/ee/jFjE9c4rJHCk670pHfmns98z697hbN4nn/+eTZt2gTAgw8+uKRer9953333
jY2Njf22c469e/c+dMMNN0weP378K9u2bTtyxRVXsGPHDt6V58iRI6gqALfccsunRkdHZ40xCpyyRETz+fzMXXfdtQ1gcnLy3QHcsmULAHffffcfFgoFFREVkdMAT0Ba
a3Xr1q2fB7j99tvfHcj777//9yqVigL6VuqdWMaYk5D33HPPve8KnKpG5XJ5z5mgzrSGh4ePbtu2bfHOnTvfkV8zH6Pp6WkRkeXOuTVn68A5t6hard60cePGn6+C27dv
r75daN8q1MYYXbt27b/83EN82WWX7T9RAPMFPGG7efNmfad+zXwN9+3bJ4NcPJu8PdmiToZcZ97S1rvp/m+6r58doKYtAMbHJ1wEYAWIQAxGZGAlp22Vjy2/dfVVAKxc
seIE3EQko/339j75aXsbLcK7o3dKbjm11lkKrr3a2icff6SfVxJrRD90Q7lYK+WiFgt5/cC6Ffqv939Way8/otnkdg2v/rPq/gd02bkLdOXS1X+nqvGJ/Xrdwxv1URXt
HHg+3TGq7ulxdT9avQcgdJ8+3+lUSdURmpNE8wE8/OLDX4qndgFw6ftW8MFLL2HJ6AiXb7qEiTWriHIxWAO9jG63Ta/r8F5wTeHzn/4Y5+Ts704/88BVwHvTmuZ5/cbH
0wttt3cgiQqugYYUiYrl5mvX/7W+/IXf717y2XXF3HkN+rGaR6L2pqtjyxbxk0c/xzkLF6Jq0DgmskNkaZvMWaxEaHCE4PA4QujivfAbv7SOnstIabQATO1zrTD1byAZ
xdTiozzG9pBe9bzckSc/DR1yexbtG+TN/IqkMn5VxaZtkmKBXreNCw4JnuBdfzmHdynOZwTvUefQoEShRyqA71JaMFED0MZT28XHOF3Kobnf5LUXV/39j1/Y8NVD1evo
tTvg82h7D+3egZtV1b6tgtnsPuKRVR8+/KOvK2mVEDyiMcF7LB7vMsR6VAXVgIYAwaEhEHyKUXBRicrK9V/3tckvuOa3Jkz9fzj6k40s/ehnHk8K6z85rQ2zkOIdu//4
ot0T1x4dt5XrXomHxv6hFo6NyXwLZWbyu1dJsJ/oHnrppijJY+IIsTHGGDC2nwoKIQTwKZl66DZIzn/f0871vjG6Mv6a27H1oCSN0VY0Qv17ySMX/tWBLanuJ5Hxvhi7
v/Fo/aVPbC6XY6xbjll0/Yp598HRNdf858hFH77ZLrwgddrBZYq6FO8ygktRn+FcCj6lpwGfpqSFCpU1H/q1cy++9j5fzRWC5lIJw2i3QW7iUgFOwgGw/Fcym1xJEEPW
bVXTrOnN2Xb2ZHT9R4MxBNfBhYzgU4JzOJcSfEbmUpzLSKySFMevrbE/7ehMbIojSTzy669oftNMIQocPbj3F1T1FP+HH/j4hUNLSsTd0gFTWLnLL/vgcHQ2cPVGnUqp
8p25Xf/+QmN6zwbvwItgTSAEwRglaIakQsfYl5au/dB3OjqNgjeVdYc72rg198IffaTXevaLy8Z3LZt+4i+9qm4AFhz7ymUb7JrVG3JT3yJ7/xfnkrEtf9qzoSrvZD7W
9j97b2P/D+8wkfLmLDGDEQytXsax9JydH9hy26ZTxpnqYv/YR97Q408Rl5Xa8Vk6nSKJydErjrIk38TPKSa1RJ86+N6jvPG/5p0AapIbLxWK9FJBiVAMCAQs9Yan2lJi
9afNq0DtGCu2/nISL6PZXtwplSdaixfGnLtAuUA6DVrllvOe1q/e+xkReVWU1hkVTOv7SCqr+tWV+i3Rs1eO+dlnrE7ccg/ZFDPuNoa1TqNZJ0u7dLuOVivFhQhrDevW
p0jzif9KGpM/9OffVOU9f/FoJPIaQLrz4dv9+68bj5/7m+t117bl3ivJBRvn0s3fvDs8dmsuf83XvnxUlcUivG2Iw5Hvp77+35bpHxhpv0Jw00TxMjrFKrncRiQaAh/w
+H7LwdBsv0i51sLHggYh+EDky2l60R88OfyeO68GaPjqBW7Pk3OF5/5MnBcZPv9iJ9c81Pr//k8DbL/6TfIXfQw/tfvmcPThv3Xp8cqQGRY1Ga7zHHF1Lz1bY0hLONNF
RFEJGLGogqjFqpLaiDhTyAwBRZ1BXBNX3ohd/Sd3xONXfxngKVUulzPrdMoXddNItKif0D+4Uz0BEY8Yj5AhYnA08TPPMiRVghhEgEG3ULRfJ2LAK6IG9YIGEN9XUzOL
6U2jNze/2zON24py7sGfFUF5i0NmufP0n7+QzE2txHZFJIA4vFVscKh1iI3Q5utIOkVQT9/mZBEjKqgHwgA+CBIUvCV4pUeBXNbdZ289eLGI9H4WYHSagiJzzW9/vCke
8ZIhKBiP4AniQBwqDiigyVIka6FpFVWH6ctHwCB+sKcfAAdLcH3IxHlMacl49uOHVgO75g0o0SLUNUvZt28q+2wW4/uBEwJqPeABB+JRPEbotxgWYEIbCQ4JjoBAEHRw
O1Ev4AUJdnBb8WiviXntMdXZKWTkvPkBzjVqNI69urJAvKLbnSPGIhpQDQTNQDwygOuDZ0DA4AkKKoqqQVQgKIogrv8nJAg6SAUroL2W2mf+sfvM2CdRVeQMhRIBNBq1
UpalE912Mz8U7I3SOoT05hAgqCMEjzEROEfQQP/mCW9OctN3oNoXKChi+vmmKlgRvA7gjJBiSMSZ2tYd/7FmwYU3VqvTnUZ9Zn+pMjo7V5+lXBl5E7BWnfnFXqf7Tz5L
V6UuNa7bq5eXrGfYNfrHWWvACGD7xyoREAsSwEagP1UdyKBYPDgFDYMZN6iYEMB7IhXwgRBKKzqd7o44UReiMFOrHttarox8/xQFRWR3ZKOviuq1qmFtmiwqv7L0d6Bt
aPZqNOpztFpN2s0W7VaddqtJu92i0+nQ63TIshTnPSKCESEZShjKDTE8XKQwXGS4WKJQKpLPlykM3ktDZYYqCYmNSaw5JMa2xURPGGP2nLHNzDVn8z71CzSEQnCuiJEl
6sOV3ru89z4SI5f7EJZqCHn1LvE+oKoEDf1CoJ9HfVCDtRaxFmPMGyJyEOVla203spHHmu8R9EgU2RCMOTycS1rD+QUdgMbcLKXymyH+P6m9V6OaosEkAAAAAElFTkSu
QmCC
}
image create photo logobook_60x41 -data {
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
}


image create photo logobuild_60x40 -data {
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
}

image create photo validcert_new -data {
R0lGODlhKAATAOf/AJAFAHYOE5AICIkOErEGDGcdJKESE6wTGIQfI64WE4gkK4ImKZghIrkYGpIkJrMcF6ofILYhJbciIK4kKL8gHrAlI6cnK5stLLklKMIkJrsnI8sj
JcQmIZ4wNJgyMpM1NrUsLYY5QpU4PcAtLbgvNdEpKIM9SNknLNEqLp04QQ1dfZE8Q602N9QtK80wLcwwM7A5P88yLxZhgdcxM4hIUMk3OcM6PR1lhpFJTt44OCNpit85
PolQWtg8QRlvjyltjm9catxAP5RTWtVDSChwitdEQyBzk4daXzVvi69QWJJYYi9ylGlmdid4mKlYYLVVXTZ3mWBvdSx8nIplbZ1hZsdWWjB+n91SVoZpdDl9mZpmbTt/
mzOBocddY7phalt9haxob7Nna5VweJhwc218gr9mb3Z7fkuHnlOFnbltcaxwel+GlLJwfMJtbkmMp6V2e1OOpdJub06QrKx4hYGGicJ1ecF1fnSLj2iPnV2SpFOVsYeL
msJ8g3qRlaCIkniTnViatmOYqqmIj8KDh26arWKdtGChvmahuW6fuIGcppyVoXigrriRmWWmw9mJjWSpvsuRk3Opum+qwYOmrsaVmqqcqYqlr46lqp2ipHqrxICtwI+q
tIWtu3C0yqOoq3izypWtscqfop6qt7+kqIayxoC2yJayvIm1yY21w8imrXu7y7ets4y5zIW7zaqyuqS0upu3wb+utrGzr6m0wq+0tpq5yYi+0MuwtJa+zJK/043C1ba7
vsm4wKzAzJHH2by+u9u2t57G1JfI1arG0K7Gy77ExsXCx5jO4aDN4aTN28vFxKzM3LDM15zS5LvL0sTJzMfJxqHS36nR4LvP263W5KfY5bXV5b/T38PT2szR1LPY4LrW
4LLa6cbW3c/U18HZ3r7a5Lbe7brf59TZ3Mvc4rni8MPg6r7i68/f5sni57zl9Mfj7sLn8NXm7Mzp89/l59Ps8drq8cvw+dbv9N3t9NXy/dny9unu8ODx+Nrz+OT1/Oj1
9u/09/P4+/f9/////yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAP8ALAAAAAAoABMAAAj+AP8JHEiwoMGC9RImtMeQ4cGHCa2tq9dwnj10dWwMuZIKHr159EKG1HcQ
UDB381LSi5fOFQwvbGLFW0mumzMwGVDkgLRv37t+/cb5G1pQjxsjZ8yJZARChJA3NC7cuvfO2y5P98ZkOBFE2a9s0DA966eP5MBGjQzJWYLEHL9+H0TwE8TH3yoBjvi9
MyOrGJ0jGXK0KdYO26tt7tjJIyjHjeOB+4BZMOZPCQFKg3DE8TeO1rti2P6kaFHkEjNLprSxU/xwIL4wLEJluMDAw4AVXfDhm0cMlDlYTCjk0JJo07Bz7M61/vdtWK1R
IKgoEOMgzTQaXtwxg0Umiqk+eCz+tOjRS1w4ab6qGcx0alo7csM0YQHw5NqsKX7UGOAl7o4pS7CAc04wPAhXhi66NHOQFT/coAMh4CRDCiJ7LGCDHXMkgUAI2CSXXDnh
cKMLGhBwMEMVBJWAwkBNLKGDDCrAkcwpiFCzTAEFBGDCMuWIAyI31BzjSyufFALEARRs0MKSLeSAAgf/cAGFFE38ACMruUgiDTvSJIOLNNJMgoswi+BRSie2BENQAgk0
sMEMM3DQgEBWSGFnEzqocEgphyTzIzXRcPIFHmvkEQkqijhBQg1BDNTAA4/OORAXdkoBhQ8qFCJJIcgAKqQugRhqiyhadGDBBBVUoIELOyz3T6VdUhAhwxZNZOGLL7q0
0kknutRSyUMYYKBBDMvVSaUROvywhB66oomMOq4KhEEEGRR7JxRQWPGIKs2UE21BGqiaQQwuLFgpF59Q821rFUAwwgsPcSGvJOtGK0EFBAUEADs=
}
image create photo invalidcert -data {
R0lGODlhKAATAOf/AJAFAHYOE5AICAAtpGcdJAA3pqwTGBMzo4QfIyIyjwQ5p64WE7cTGBk3kgA9qjQyfws6qUYvdVwrX4gkK4ImKagcHj8zcD4yg7oZGrMcFxY+oH8q
SF8yXxxBnABIrR1AqQ5Fpg5FrKYlKrciIL8gHposKwBNrLckLLInJYsvVcIkJo8yOXU2ZEFDfssjJcQmIZ4wNB1NobYsLqUxQiNOsMAtLSRPq4M9SBhTtNIqKdEqLsgs
Ng1dfa02N2BIdMwwM84xLtYvLC1UsdYvMrA5PxZhgUBUhyBboSVatUxSlIlIUMM6PZFJTrM/Ux9mh902N9w3PDVgoiJkuCNpiolQWtg8Qdo9PeI8OhtwkCltjm9catVD
SChwijVviy5ykztrurJSWiZ3l0dquzJ0lj9wuT9ytUJwwDd0vCx7nDd5moplbZ1hZsdWWi99nt1SVoZpdJplbTKAoDt/m7lgaUp4w8ddY0l6vqxob7Nna06AqpVweJhw
c79mb3Z7fpNxj0uHnlOFnVqFql+GlLJwfEmMp6V2e9FtblOOpU6QrKx4hYGGicJ1ecF1flCQxWeOnFyRo1yNy16TpWmRnoeLmlaYtKCIkmGcs26arWWgt3eZznCcz26f
uIGcpmOkwXagx9mJjcePl3GmuGynvoqhv42kqaqcqXWqvHGrw4KmyJ2ipIynsXqrxHC0yqOoq4Oww8qfop6qt6envXm0y7+kqJeyvMimrYq2yrassqiwuIS6zIq42KS0
uq6ztb+utrGzr6m0wpm5yZC64Zq6yorA0suwtJPA1I3D1ba7vqzAzJHH2ZzF07a/x9u2t6nFz6rG0L7DxZ/M4KTN26zM3LDM15zS5LvL0sTJzMfJxqnR4KzV46fY5b7S
3rXV5bPY4LrW4MTU27Ha6cbW3cHZ3r/c5tLY2rre57bf7svc4rri8b/j7M/g5sbi7b3m9cPn8M3p9ODl6Nnq8NPs8cvw+d3u9Nfw9NXy/Nny9+nu8ODx+Ojw+eT1/Oj1
9vD1+PX6/fj+/////yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAP8ALAAAAAAoABMAAAj+AP8JHKhAgYOBCBMmrMeQ4YeC9OgpRIikYAgaDLmtqxexo7pFS7a4qRVv
nhgcBTPN0zeRkjJ39Og4KPgFF5E5g3rBmwfvXLhqd1TouALKTEEHdMj189cvISVCYf6MmzdPSEEIPgopKUHs3jtyx1rd26MiBYSCNq6lstZPH8uBneIiGtNlHb98Kwoa
7HdLwCd+7/r4eqZoZsFl6r7t8uaunTyEiAhJHriPmYhYRhUc8MPEUD9yvN6NOlDwQhNS01TR6tbO8USE+PD0eKWCg94GdfDho2dDrxEST+BwUtUsXevXAsU5EzZLxpoJ
eixouBoM1VkFHqJIEhGkCrJy5rD+JdOmcJWtbT2duXoDAMy2X2oqJdGrt8y4dMqoAOdjzBi1iW1k4cQUl4wTjSubTELBEowkAgYCLdAHCTrmgGMMIBW88AQbCOWgw0Bh
eDFFETwcEo0tm2QjDQEEBHCDHfQVZEcyuchiiRYGkOBCDkH0+IQOL/wTRxpohJEFibYUIwo27WATzRkeXOVJINd5QAZCCyyAgQtDDPECBgLFgcaYYTjBAya5YBINhZro
1YEjgkRiigl6sWDFQBhkwEAGYA4k5phpYMGDJadYAo0uUigAwQF5PBLKMLDAAcMGpCnwwAxQICfQmGNyUYQcYaRRzFUOsGIMMKUoZJgCJ+yg6Z9EaGAxRRZegHBVI9Cw
o+k/1yWggqZtkDlGDIZJgc6uCNEXgQpAAAHgmEcURAMNyCo0gF4S1PDDa3HEcVS1yBk2AgoIBQQAOw==
}
image create photo csr_40x19 -data {
R0lGODlhKAATAOf/ALMNFa8XFIAkKLEaFpghJ7oZGrIcFqAgJqsgIKQjI70dHL4eHbUgJa4kKMAhH7cjJ7InJcohJMMkIaMtMMMlJ7woJMUnIos2PcUnKLYsLr4qKwlb
e8grKtApKNooLA5dfRBefs0wLdUuK684PnNJUxZhgdYwMsA3O9gxM9A0NtozLxtkhNo0NR5mh9w2NpdIUHVTYCFoid44OCVqixpwkOI9QStvkN9CQC1xkiN1lWJnaTdx
jSZ3l3hkcih4mLVVXSp6mjZ3meFNSit7my18nC59nT16kDl6nFR2fi9+njF/n25ygNpXVzyAnNxZXkaCmEGEoLRobGx7jXV6fUWIpHGAkot7g0mMp3eGjGmMlKV+h1KU
sISJjFSWslqWrIqMiVeZtb2AiniTnYOSmF+gvWWgt3KesWuhsoWcoJeYopWanGmku2Slwm6ktoSfqXaitmaoxGWqv3KnuW6pwXOpunqnupKiqHmqw32qvZWlq56jpXKt
xHCvv3+rv3muwJGprW2yyG6zyXaxyJypqoSwxHizyoiwvnG2zJyssqWqremYm9GfpIuzwYG3yZeyvJOzwo21w6Gxt3650a2vrKW1u467zoe9z7K0sZ25w9Srs4q/0ovB
096ssaq6wLO4u5jAzo3D1ba7vpDF2KLC0ZzE0ri+wJnG2qjDzp/H1rPDybzBw5XK3ZbL3r/Exr3FzafM1K7K1JnP4aTN28TFz8PIy7HN2MTJzLzM06LT4KnS4MbMzqvT
4qXW48nO0K7W5b/T37nV38zR1K/Y5sfU1bDZ6LTZ4c7T1rzY48fX3tDV2LTd67nd5rre58rb4bjg77zg6dfc39rc2bvj8tDg573m9MHm79Li6b7n9sLn8Nfk5crn8cTp
8d7j5tXm7Mbq883q9d7m79Hq78Tt/Mjt9uLn6tnq8NPs8dHt+NTt8tvr8tzs89fv9N3u9N7v9uvw8+bz9OT0++7z9uj19ub3/fjz8fD1+Or3+Oj5//L3+fP5++/8/fb7
/uv///f9//j+/////yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAP8ALAAAAAAoABMAAAj+AP8JHEiwoMGDCBMqLBhuVhQMKphkMlduncV16dQhLFPJHDtzIC+qq5iO
XbqS3Vxp0eDhBqd5797Jk4evpkEyXaBQAcZOHbtyyJA1m3eL3bB7+nTtqxcpTQYRNej569dvX7589grCgcMGzJEd0+rh0xVvCjRuiULZokVrkqovnpBZoaBCEb958Nid
++Zt4b99/txF0wFNzyU1iVT1IsetVbZyhl50EKLNGzZq2DL7/dcPH7RkwYy5KxV3UCdEqY5p+7SkAotF4rxZluZs4aM61vTps8aFUiQ7Y/6cquXoWbVqsrxM6ODklzNh
rDQhRAauG7JReEhNy4MFjRtMwLz+Ya62zDI2YW1gLPAQxtIhhEFmlLBBCBiqPoRgnSqGTbb5aswwQ80uueRChxEHLCDCDwWZMBAPOMQAwgZlmEJIH874lxk21VDzihiQ
MJKFHJbM8cQ/ABQQQQcmuOCCCRIs8E8SRQzhwwwf2GBKI3cogxk1tCkjDC+MICEHH3HQUVAAARTggAUOLFCAQEVUWUQOK6zQyBxrCOOMkL7gwooooJyxhxk9XDDCCSks
GcAAAxBEY5U+tEBDF01ckQsusawiiiaS+PFGFSQIQEACDTxAQQgOLmQlEDOsUMIKW7ACiiWSHCLIGVIkxEAFHHCg0JxA4GBDDkMUkqkggGwm0KcsFChk5RBDAAFGIK26
ShACDFBgggwsHKSElVsEoutBCCAAgQYaHOusQQgQFBAAOw==
}
image create photo csr_ok_40x19 -data {
R0lGODlhKAATAOf/ALMNFYAkKLAZFZghJ6AgJrsbG6sgIKQjI74eHbUgJa4kKLcjJ8EiH7InJcohJKMtMMMlJ7woJMUnIos2PbYsLr4qK8grKtApKNooLA5dfc0wLdUu
K684PnNJU9YwMhdigsA3OwN1AtA0NtgyNNozLx1lhtw2NpdIUBN1GnVTYN44OCRqiyF2JACFABpwkOI9QRuAEyN7L99CQCxwkWJnaRmEKACPByV2liV7cXhkcrVVXSp6
mjZ3mQuUAOFNSi18nCOLLj16kC99ngCbAFR2fiGKVQCdDR+RLG5ygNpXVzyAnACiANxZXhabGTCQQUaCmACmBz6LY0GEoLRobGx7jXV6fQCrABSkFxukBieeMEeKpnGA
kgyrEot7gwCxBk+SaymlJhuuAkGYbw2zAGmMlBW1AAC7A6V+h02ZiHmMi1aZcjmpM1OVsQDAAFScblqWrIqMiVOZrmSbbwDEAL2AiniTnViatgDHGmCeolaqWmCkfF+g
vQDQAGWgt3KesWuhsi3DJWaojJeYommkuwDWBQDXAHaitmWmw2Wuf3GmuGWqvzrGPALdAHOpum+qwoGtfCbTGwDhAW61c3Cvv2C9aoGxhXGwwADlAHmuwJGprW2yyHax
yZypqgbpAISwxHG2zHi2uumYmwDtAtGfpIqywADvAJ6utYK3r4C2yJeyvI21w4K4yjbeNn650a2vrAXzAADzE4e8zgD5AI67ztSrs569oYq/0onHkRr3AIrGnd6ssaq6
wLO4u4zC1JXByJjAzrK8t5DG2JnG2qnFz7PDyZbL3r3Cxb3FzafM1KTN28TFz5/R3bHN2KjR0sXKzanR4KrT4aXW463Zs8nO0MHSy7/T36/Y5rrW4MjV1rzY48fX3rTc
67rf58rb4bfg79fc39rc2cbj4bzl89Hh6MHm777n9cLn8MTo8dfk5cvo8tXm7ODl6N7m78Tt/Nnq8NPs8NHt+NXu8tzs897v9d/19Ozy9Ob09OT0++b3/fjz8er3+PD2
+PP5++v///f8/////yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAP8ALAAAAAAoABMAAAj+AP8JHEiw4EAoWAwqXMhQ4ZVFYN4pmwKBRBJa79y925hR3sI+s97N4/gu
Xjx57sJRYsUl1zx1x85UwCBDFz57OPXt28fP4B42UrRcmydvnjtt2rrdy3MHUhZ6zvztMyWIwoYX+fxp9cePn76Ch8LGKYJj3E5n9ap8k1QGl5dKzlwZg8NLW5eKofrh
uzcPXrpzDI0M6SHNXz1wNB4twRXpCLBp69YZQ+eO1IkLPv6eE3euc0MjgMKsuUWtFhRRr5bIwcZplyli2dL9QhLBxKh2nTd7a4joCqxLZprY4COKD5A0mYYxS8Wtc7I3
Dy4wqebNWjFbC7WxU6fNjRdRshj+Mep0aYmec+U6N+9sLVEKBBjoxPq0kMeKDzM8XfMlZkipS5EwMkcNzeTGDTfiQAPNM40EQQACG+hQ0AgD3TDDChlk0IcwnsRQRiGF
ENKDGueQIw4ydahCChmNxOLIE/8AUIADF3hgggkeMFDAP0L0eAOGMwizCh5OWMFHGyw0s4010ZBCRCOTKNJIQQIIUAADEui4I489CnHDBx+g4sggp8BQRgtfLFNMML38
4YgfOUzAAQgiUFmlAAR1KcQOJbjAhhJaLBNICCiAYksrmBiyRQcBDHCAAgtAoAGFDXG5530flMBGMb1EgcYnm/xBBUMJRGCBBQ11ucMMM9wgxCYxrXxiiSaVElQqBKnq
uYMdmtBaq0EGJACBBypQWpCebPj6q0IGGNBABRUsK21DBhAUEAA7
}
image create photo csr_refuze_40x19 -data {
R0lGODlhKAATAOf/ALMNFfwAA/8AAK8YFIAkKJghJ7oZGrIcFqAgJqsgIKQjI74eHbUgJa4kKMAhH7cjJ7InJcohJMIkIKMtMIY0RcMlJ7woJMUnIos2PcUnKII4SrYs
Lr4qK3c8TcgrKtApKAxcfNooLMotMYg+UJY7ShBefs0wLdUuK684PnNJUxZhgdcwM5VBUcA3O4hFWNA0NtozL3lNYx1lhtw1NohLXJdIUJVJW3VTYN44OHJUayNpiiVr
jLxFTrZHTOI9QStvkN9CQCxwkWJnabNSVSR2lp1XZXhkcih4mLVVXfRFS8NTXDZ3meFNSit7my18nD16kC99nlR2fq9fa25ygNpXVzyAnLJibtxZXq9lbrpicUaCmKtp
dbRobHV6fcdlbM1kbtNmZnGAkrJwfIt7g0mMp89sc9RvcGmMlNtvc6V+h1GTr9twetdyc+puc1SWsuBzd+5wb1qWrIqMiep0duN2euV2db2AiniTnViattl7foOSmNF9
iN96ge13efl5eF+gvd2AieCBhNmDiWqgsXKesWahuIWcoGOkwZeYopWanGmku26ktoSfqXaituqEiviBguCIiGanxGWqv3Koum6pwZKiqHKtxHCvv36rvnmuwJGprW6y
yJypquaVmIOvw3eyyoiwvnG2zJyssqWqremYm9GfpIuzwZeyvJOzwqGwt421w3650KKxuK2vrP2bnqW1u4e9z525w9Srs4vB096ssaq6wLO4u5jAzo3D1ZDG2KLC0bi+
wJrH25/H1qnFz7PDybzBw5XL3r/Exr3FzafM1JnP4aTN28TFz7HN2MTJy6rS4cbMzqTV4snO0LjU3r/T36/Y5rvY4sfX3rTc67be7bne58rb4bzg6bjh79fc39rc2b3l
9MHm777n9sLn8MTo8dfk5crn8d3j5dXm7M3q9cfs9d7m79Hq78Tt/Nnp8OLn6trr8dHt+NTt8tzs89fv9N7v9evw8+b09OT0++7z9vjz8ef3/vD1+Or3+PL3+fP5++77
/Ov///b8/vj+/////yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAP8ALAAAAAAoABMAAAj+AP8JHEiwoMGDCA8KSEgwiQBH545xyQCDiqx2695pfLfOHUIeAtrAa0dy
o7uMcwR0Wgdv3LA0HEIAoTVPnk18+XIa/OPGhoA18NzBSydNmjV7aAS8sbdvWb97qRBtOOGjnr9+WPXpw1cwUqRDblgIgHQv3zJ6XbL1EWAmmdtWwOTYkjamAgxS/OzN
g8eO3DeG/wT48RdPmxA4AsAkGgWsmTpxwsClA1XjA5Nw375ty/wXsABX+bLVEUAn3q65nGqJ+hUt3K0pFmaUQsd5GzbAqKwIeORHwJBXrCrp0eQL2alrmY3FmfDhyjNs
0ILNQijN3DhpujB9ESCghyFGsZz+feuWuRpnaItuLAhhB1YohEt2qPjhyVkvTEq4s/lWjnP5atsoI+AkTyCwwAlIFLTCQEQEoUMJIBTCSxYC5MGHAIFwxs02xNyhiiln
TAILJVr8A4ABEXywAg44rCDBAv9AAUUTR+wAwg/bbTFNN4AIIAg200DDjClRTHKJJJMUNMAABjhwwYsGCCSjjETIQIEAUigCDZB7CFBGMLngMoglhBiBAQotvKDkkgMQ
NCUUR2ggQBFVkKEMM8UE44UAYmTSSBgpEFCAAg08UIEJCwI2JQkCdKCCDG4Egwssq4SChQAiJMSABR54wJCMLggwQhBENPFJpZ9sIlAACzG0aQUrDOUgQAxN1IrHJqoa
1GpCCTBQwYozHETDlGrkChivCUDAAQfHNutsAgQFBAA7
}

set label "current"

# make sure this is set to correct revision if not the case
#set revision [lindex {$Rev: 36 $} 1]
# this needs WCREV
set revision 2.0
set version "$label, rev. $revision"

    global db
    array set db {
	certCA	""
	keyCA ""
	pasDB ""
	serNumCert 4096
	serNumReq 256
	serNumCRL 16
	dateCreateDB ""
	filedb ""
    }

#
# CA-Federal Law 63 (CA-FL63)
#
# CA-FL63 utility to manage X.509 Certificates
# 
# Copyright 2018-2020 Vladimir Orlov 
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

namespace eval ::scrolledframe {
    # beginning of ::scrolledframe namespace definition
    
    namespace export scrolledframe
    
    # ==============================
    #
    # scrolledframe
    #
    # a scrolled frame
    #
    # (C) 2003, ulis
    #
    # NOL licence (No Obligation Licence)
    #
    # ==============================
    
    package provide Scrolledframe 0.9
    
    # --------------
    #
    # create a scrolled frame
    #
    # --------------
    # parm1: widget name
    # parm2: options key/value list
    # --------------
    proc scrolledframe {w args} {
        variable {}
        # create a scrolled frame
        frame $w
        # trap the reference
        rename $w ::scrolledframe:w:$w
        # redirect to dispatch
        interp alias {} $w {} ::scrolledframe::dispatch $w
        frame $w.scrolled -borderwidth 2 -relief groove  -background white 
        # place it
        place $w.scrolled -in $w -x 0 -y 0 -relwidth 1.0
        # init internal data
        set ($w:vheight) 0
        set ($w:vwidth) 0
        set ($w:vtop) 0
        set ($w:vleft) 0
        set ($w:xscroll) ""
        set ($w:yscroll) ""
        # configure
        if {$args != ""} { eval dispatch $w config $args }
        # bind <Configure>
        bind $w <Configure> [namespace code [list vresize $w]]
        bind $w.scrolled <Configure> [namespace code [list resize $w]]
        # return widget ref
        return $w
    }
    
    # --------------
    #
    # dispatch the trapped command
    #
    # --------------
    # parm1: widget name
    # parm2: operation
    # parm2: operation args
    # --------------
    proc dispatch {w cmd args} {
        variable {}
        switch -glob -- $cmd {
            con*    {
                # config
                eval [linsert $args 0 config $w]
            }
            xvi*    {
                # new xview operation
                eval [linsert $args 0 xview $w]
            }
            yvi*    {
                # new yview operation
                eval [linsert $args 0 yview $w]
            }
            default {
                # other operations
                eval [linsert $args 0 w:$w $cmd]
            }
        }
    }
    
    # --------------
    # configure operation
    #
    # configure the widget
    # --------------
    # parm1: widget name
    # parm2: options
    # --------------
    proc config {w args} {
        variable {}
        set options {}
        set flag 0
        foreach {key value} $args {
            switch -glob -- $key {
                -xsc*   {
                    # new xscroll option
                    set ($w:xscroll) $value
                    set flag 1
                }
                -ysc*   {
                    # new yscroll option
                    set ($w:yscroll) $value
                    set flag 1
                }
                default { lappend options $key $value }
            }
        }
        # check if needed
        if {!$flag || $options != ""} {
            # call frame config
            eval [linsert $options 0 ::scrolledframe:w:$w config]
        }
    }
    
    # --------------
    # resize proc
    #
    # resize the scrolled part
    # --------------
    # parm1: widget name
    # --------------
    proc resize {w} {
        variable {}
        # compute new height & width
        set ($w:vheight) [winfo reqheight $w.scrolled]
        set ($w:vwidth) [winfo reqwidth $w.scrolled]
        # resize the scroll bars
        vresize $w
    }
    
    # --------------
    # vresize proc
    #
    # resize the visible part
    # --------------
    # parm1: widget name
    # --------------
    proc vresize {w} { xset $w; yset $w }
    
    # --------------
    # xset proc
    #
    # resize the visible part
    # --------------
    # parm1: widget name
    # --------------
    proc xset {w} {
        variable {}
        # call the xscroll command
        set cmd $($w:xscroll)
        if {$cmd != ""} { catch { eval $cmd [xview $w] } }
    }
    
    # --------------
    # yset proc
    #
    # resize the visible part
    # --------------
    # parm1: widget name
    # --------------
    proc yset {w} {
        variable {}
        # call the yscroll command
        set cmd $($w:yscroll)
        if {$cmd != ""} { catch { eval $cmd [yview $w] } }
    }
    
    # -------------
    # xview
    #
    # called on horizontal scrolling
    # -------------
    # parm1: widget path
    # parm2: optional moveto or scroll
    # parm3: fraction if parm2 == moveto, count unit if parm2 == scroll
    # -------------
    # return: scrolling info if parm2 is empty
    # -------------
    
    proc xview {w {cmd ""} args} {
        variable {}
        # check args
        set len [llength $args]
        switch -glob -- $cmd {
            ""      {}
            mov*    {
                if {$len != 1} {
                    error "wrong # args: should be \"$w xview moveto fraction\""
                }
            }
            scr*    {
                if {$len != 2} {
                    error "wrong # args: should be \"$w xview scroll count unit\""
                }
            }
            default {
                error "unknown operation \"$cmd\": should be empty, moveto or scroll"
            }
        }
        # save old values
        set _vleft $($w:vleft)
        set _vwidth $($w:vwidth)
        set _width [winfo width $w]
        # compute new vleft
        switch $len {
            0       {
                # return fractions
                if {$_vwidth == 0} { return {0 1} }
                set first [expr {double($_vleft) / $_vwidth}]
                set last [expr {double($_vleft + $_width) / $_vwidth}]
                if {$last > 1.0} { return {0 1} }
                return [list [format %g $first] [format %g $last]]
            }
            1       {
                # absolute movement
                set vleft [expr {int(double($args) * $_vwidth)}]
            }
            2       {
                # relative movement
                foreach {count unit} $args break
                if {[string match p* $unit]} { set count [expr {$count * 9}] }
                set vleft [expr {$_vleft + $count * 0.1 * $_width}]
            }
        }
        if {$vleft < 0} {
            set vleft 0
        }
        if {$vleft + $_width > $_vwidth} {
            set vleft [expr {$_vwidth - $_width}]
        }
        if {$vleft != $_vleft} {
            set ($w:vleft) $vleft
            xset $w
            place $w.scrolled -in $w -x [expr {-$vleft}]
        }
    }
    
    # -------------
    # yview
    #
    # called on vertical scrolling
    # -------------
    # parm1: widget path
    # parm2: optional moveto or scroll
    # parm3: fraction if parm2 == moveto, count unit if parm2 == scroll
    # -------------
    # return: scrolling info if parm2 is empty
    # -------------
    
    proc yview {w {cmd ""} args} {
        variable {}
        # check args
        set len [llength $args]
        switch -glob -- $cmd {
            ""      {}
            mov*    {
                if {$len != 1} {
                    error "wrong # args: should be \"$w yview moveto fraction\""
                }
            }
            scr*    {
                if {$len != 2} {
                    error "wrong # args: should be \"$w yview scroll count unit\""
                }
            }
            default {
                error "unknown operation \"$cmd\": should be empty, moveto or scroll"
            }
        }
        # save old values
        set _vtop $($w:vtop)
        set _vheight $($w:vheight)
        set _height [winfo height $w]
        # compute new vtop
        switch $len {
            0       {
                # return fractions
                if {$_vheight == 0} { return {0 1} }
                set first [expr {double($_vtop) / $_vheight}]
                set last [expr {double($_vtop + $_height) / $_vheight}]
                if {$last > 1.0} { return {0 1} }
                return [list [format %g $first] [format %g $last]]
            }
            1       {
                # absolute movement
                set vtop [expr {int(double($args) * $_vheight)}]
            }
            2       {
                # relative movement
                foreach {count unit} $args break
                if {[string match p* $unit]} { set count [expr {$count * 9}] }
                set vtop [expr {$_vtop + $count * 0.1 * $_height}]
            }
        }
        if {$vtop < 0} { set vtop 0 }
        if {$vtop + $_height > $_vheight} { set vtop [expr {$_vheight - $_height}] }
        if {$vtop != $_vtop} {
            set ($w:vtop) $vtop
            yset $w
            place $w.scrolled -in $w -y [expr {-$vtop}]
        }
    }
    
    # end of ::scrolledframe namespace definition
}


#
# package config
# provides configuration options
#
package provide Config 1.0

namespace eval Config {

    variable config_default
    variable config

    array set config_default {
        export.folder ""
        export.cacert "0"
        export.key ""
        export.keyfolder ""
        web.infolder "csr"
        web.outfolder "certificates"
        web.mailhost "localhost"
        web.mailfrom "flca63@localhost"
        web.webserver "localhost"
        folder.folderlist {
            "Каталог для запросов:" folder.requests
            "Каталог для ключей:" folder.keys
            "Каталог сертификатов:" folder.certificates
            "Каталог для PKCS#12:" folder.p12
            "Каталог для CRL:" folder.crls
        }
        folder.setupdefault "certificates"
        folder.requests ""
        folder.keys ""
        folder.crls ""
        folder.certificates ""
        folder.p12 ""
        filetype.cert_default_ext .crt
        filetype.csr_default_ext .csr
        filetype.certificate {
            {{Certificates (PEM Format)} {.crt .pem}}
            {{Certificates (DER Format)} {.cer .der}}
            {{All Files} *}
        }
        filetype.request {
            {{Certificate Signing Requests (PEM)} {.csr}}
            {{Certificate Signing Requests (DER)} {.p10}}
            {{All Files} *}
        }
        filetype.key {
            {{Private Key Files} {.key}}
            {{All Files} *}
        }
        filetype.p12 {
            {{Certificate Export Files (PKCS#12)} {.p12}}
            {{All Files} *}
        }
        filetype.crl {
            {{Certificate Revocation List} {.crl}} \
            {{Certificate Revocation List} {.der}} \
            {{Certificate Revocation List} {.pem}} \
            {{All Files} *} \
        }
#for PKCS#11
    	filetype.libwin32_default .dll
    	filetype.libwin32 {
    	    {{Library PKCS#11} {.dll}}
    	    {{All Files} *}
    	}
    	filetype.liblinux_default .so
    	filetype.liblinux {
    	    {{Library PKCS#11} {.so}}
    	    {{All Files} *}
    	}
	library.pkcs11	""

        system.caname {CAFL63 Demo CA}
        system.tools {
            "Модуль OpenSSL:" system.openssl
	    "СКЗИ пользователя:" system.ckzi
	    "Класс защищенности:" system.kc12
	    "Наименование УЦ:" system.cafl63
	    "Сертификат СКЗИ УЦ:" system.certckzi
	    "Сертификат УЦ:"	system.certca
        }
        system.openssl_locations {
            openssl/openssl.exe
            openssl.exe
            "env(SystemRoot)/Program Files/OpenSSL/bin/openssl.exe"
            openssl/openssl
            openssl
            /usr/bin/openssl
            /bin/openssl
        }
        system.openssl "openssl/openssl"
	system.ckzi "Наименование СКЗИ пользователя"
	system.kc12 "KC1ClassSignTool, KC2ClassSignTool"
	system.cafl63 "Наименование УЦ"
	system.certckzi "Сертификат СКЗИ УЦ"
	system.certca "Сертификат УЦ"
    }
    array set config [array get config_default]


}


proc Config::LoadConfig {} {
    global certdb
    global db

    variable config

    set conf [certdb eval {select mainDB.configReq from mainDB where mainDB.dateCreateDB=$db(dateCreateDB)}]
#    puts "CONF_LOAD=$conf"
    if {[lindex $conf 0] != "" } {
	set conf [string range $conf 1 end-1]
#    puts "CONF_LOAD1=$prof"
        array unset profiles
	array set config $conf
    } 
}

proc Config::SaveConfig {} {
    global certdb
    global db

    variable config
    set db(configReq) [array get config]
#puts "Config_Save=$db(configReq)"
    certdb eval {begin transaction}
    certdb eval {update mainDB set configReq=$db(configReq) where dateCreateDB=$db(dateCreateDB)}
    certdb eval {end transaction} 
}

proc Config::Get {var} {

    variable config

    return $config($var)

}

proc Config::Set {var value} {

    variable config

    return [set config($var) $value]

}

proc Config::GetDefault {var} {

    variable config_default

    return $config_default($var)

}

proc Config::GetAll {} {

    variable config

    return [array get config]

}

proc Config::GetAllDefault {} {

    variable config_default
    
    return [array get config_default]
    
}

# load config if exists
# При открытии БД
#Config::LoadConfig


package provide openssl 1.0

set oid_roles_bad {
{} {}
{B2B Center} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.6.7} 
{CA Operator} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2} 
{EGAIS} {digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment} 
{LocalOCSP} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.100.2.1, 1.2.643.2.2.34.6, 1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.4, 
1.2.643.5.1.24.2.1.3, 1.2.643.5.1.24.2.2.3, 1.2.643.6.14}
{Mail Server} {clientAuth, serverAuth, msSGC, nsSGC}
{OCSP} {serverAuth, 1.3.6.1.5.5.7.3.9} 
{RA Operator} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2}
{TSP Server} {critical, 1.3.6.1.5.5.7.3.8}
{VPN Server} {serverAuth}
{Web Server} {serverAuth}
{АЭТП} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.6.3}
{Госуслуги} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.100.2.1, 1.2.643.2.2.34.6, 1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.4, 
1.2.643.5.1.24.2.1.3, 1.2.643.6.14, 1.2.643.3.215.4, 1.2.643.3.215.5, 1.2.643.3.215.6, 1.2.643.3.215.7, 1.2.643.3.215.8, 1.2.643.3.215.9, 
1.2.643.3.215.11, 1.2.643.3.215.12, 1.2.643.3.215.13, 1.3.6.1.4.1.40870.1.1.1, 1.2.643.2.64.1.1.1, 1.2.643.3.5.10.2.12, 1.2.643.6.3.2, 1.2.643.5.1.24.2.46, 
1.2.643.6.45.1.1.1, 1.2.643.5.1.24.2.30, 1.2.643.5.1.28.2, 1.2.643.5.1.28.3, 1.2.643.3.202.1.8}
{ЕФРСФДЮЛ} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.100.2.1, 1.2.643.2.2.34.6, 1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.4, 
1.2.643.5.1.24.2.1.3, 1.2.643.5.1.24.2.2.3, 1.2.643.6.14, 1.2.643.3.215.4, 1.2.643.3.215.5, 1.2.643.3.215.6, 1.2.643.3.215.7, 1.2.643.3.215.8, 
1.2.643.3.215.9, 1.2.643.3.215.11, 1.2.643.3.215.12, 1.2.643.3.215.13, 1.3.6.1.4.1.40870.1.1.1, 1.2.643.2.64.1.1.1, 1.2.643.3.5.10.2.12, 1.2.643.6.3.2}
{Лицензиат розницы} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.5.1.28.2, 1.2.643.5.1.28.3, 1.2.643.5.1.28.4}
{Лицензиат ФСРАР} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.5.1.28.2, 1.2.643.5.1.28.3, 1.2.643.5.1.28.4}
{МЭТС} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.3.202.1.8}
{Оператор TSA} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.2.63.3.1.1, 1.3.6.1.5.5.7.3.8}
{отчетность в ФНС} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.100.2.1, 1.2.643.2.2.34.6, 1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.4, 
1.2.643.5.1.24.2.1.3, 1.2.643.5.1.24.2.2.3}
{Площадка Газпромбанк} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.6.17.1}
{Потребитель спирта} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.5.1.28.2, 1.2.643.5.1.28.3}
{Росреестр} {1.3.6.1.5.5.7.3.4, 1.3.6.1.5.5.7.3.2, 1.3.6.1.4.1.311.20.2.2, 1.2.643.5.1.24.2.30, 1.2.643.2.2.34.6, 1.2.643.2.2.34.6, 
1.2.643.5.1.24.2.1.3.1, 1.2.643.5.1.24.2.1.3, 1.2.643.5.1.24.2.4, 1.2.643.5.1.24.2.44, 1.2.643.5.1.24.2.45, 1.2.643.5.1.24.2.5, 1.2.643.5.1.24.2.6, 
1.2.643.5.1.24.2.19, 1.2.643.5.1.24.2.20, 1.2.643.5.1.24.2.43, 1.2.643.100.2.1, 1.2.643.5.1.24.2.1.3.1}
{РосреестрРОМС} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.5.1.24.2.19, 1.2.643.100.2.1, 1.2.643.2.2.34.6}
{Росреестр ССП} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.5.1.24.2.9, 1.2.643.5.1.24.2.10, 1.2.643.5.1.24.2.11, 
1.2.643.5.1.24.2.12, 1.2.643.5.1.24.2.13, 1.2.643.5.1.24.2.14}
{Росфинмониторинг} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.100.2.1}
{РУССИА ОнЛайн} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.3.202.1.8}
{СКПЭП 63 ФЗ} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2}
{СМЭВ ОГВ} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.100.2.2, 1.2.643.3.5.10.2.12}
{СМЭВРосреестрУЛОГВ} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.100.2.1, 1.2.643.5.1.24.2.44, 1.2.643.5.1.24.2.45, 1.2.643.5.1.24.2.5}
{СМЭВ УЛ ОГВ} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.100.2.1}
{Торговля пивом} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.5.1.28.2, 1.2.643.5.1.28.3}
{ФТС} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.3.215.4, 1.2.643.3.215.5, 1.2.643.3.215.6, 1.2.643.3.215.7, 1.2.643.3.215.8, 
1.2.643.3.215.9, 1.2.643.3.215.11, 1.2.643.3.215.12, 1.2.643.3.215.13}
{Центр Реализации} {clientAuth, emailProtection, 1.3.6.1.4.1.311.20.2.2, 1.2.643.100.2.1, 1.2.643.2.2.34.6, 1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.4, 
1.2.643.5.1.24.2.1.3, 1.2.643.5.1.24.2.2.3, 1.2.643.6.14}
}

array set oid_roles [string map {"\n" " "} $oid_roles_bad]
set userroles {}
#parray oid_roles
foreach {label oids} [string map {"\n" " "} $oid_roles_bad] {
    lappend userroles $label
#     puts "\"$label\""
#     puts "\"$oids\""
}
array set atrkval {ИНН 12 ОГРН 13 ОГРНИП 15 СНИЛС 11 {ИНН *} 12 {ОГРН *} 13 {ОГРНИП *} 15 {СНИЛС *} 11}

set g_iso3166_codes {
Австралия AU Австрия AT Азербайджан AZ {Аландские о-ва} AX Албания AL Алжир DZ {Американское Самоа} AS 
Ангилья AI Ангола AO Андорра AD Антарктида AQ {Антигуа и Барбуда} AG Аргентина AR Армения AM Аруба AW 
Афганистан AF {Багамские о-ва} BS Бангладеш BD Барбадос BB Бахрейн BH Беларусь BY Белиз BZ Бельгия BE Бенин BJ 
{Бермудские о-ва} BM Болгария BG Боливия BO {Босния и Герцеговина} BA Ботсвана BW Бразилия BR 
{Британская территория в Индийском океане} IO {Британские Виргинские о-ва} VG {Бруней Даруссалам} BN 
{Буркина Фасо} BF Бурунди BI Бутан BT Вануату VU Ватикан VA Великобритания GB Венгрия HU Венесуэла VE 
{Виргинские о-ва (США)} VI {Внешние малые острова (США)} UM {Внешняя Океания} QO {Восточный Тимор} TL Вьетнам VN 
Габон GA Гаити HT Гайана GY Гамбия GM Гана GH Гваделупа GP Гватемала GT Гвинея GN Гвинея-Бисау GW Германия DE 
Гернси GG Гибралтар GI Гондурас HN {Гонконг (особый район)} HK Гренада GD Гренландия GL Греция GR Грузия GE 
Гуам GU Дания DK {Демократическая Республика Конго} CD Джерси JE Джибути DJ Диего-Гарсия DG Доминика DM 
{Доминиканская Республика} DO {Европейский союз} EU Египет EG Замбия ZM {Западная Сахара} EH Зимбабве ZW 
Израиль IL Индия IN Индонезия ID Иордания JO Ирак IQ Иран IR Ирландия IE Исландия IS Испания ES Италия IT 
Йемен YE Казахстан KZ {Каймановы острова} KY Камбоджа KH Камерун CM Канада CA {Канарские о-ва} IC Катар QA 
Кения KE Кипр CY Киргизия KG Кирибати KI Китай CN {Кокосовые о-ва} CC Колумбия CO {Коморские о-ва} KM Конго CG 
Коста-Рика CR {Кот дИвуар} CI Куба CU Кувейт KW Лаос LA Латвия LV Лесото LS Либерия LR Ливан LB Ливия LY Литва LT 
Лихтенштейн LI Люксембург LU Маврикий MU Мавритания MR Мадагаскар MG Майотта YT {Макао (особый район)} MO 
Македония MK Малави MW Малайзия MY Мали ML {Мальдивские о-ва} MV Мальта MT Марокко MA Мартиника MQ 
{Маршалловы о-ва} MH Мексика MX Мозамбик MZ Молдова MD Монако MC Монголия MN Монтсеррат MS Мьянма MM Намибия NA 
Науру NR Непал NP Нигер NE Нигерия NG {Нидерландские Антильские о-ва} AN Нидерланды NL Никарагуа NI Ниуе NU 
{Новая Зеландия} NZ {Новая Каледония} NC Норвегия NO ОАЭ AE Оман OM {Остров Буве} BV {Остров Вознесения} AC 
{Остров Клиппертон} CP {Остров Мэн} IM {Остров Норфолк} NF {Остров Рождества} CX {Остров Святого Бартоломея} BL 
{Остров Святого Мартина} MF {Остров Святой Елены} SH {Острова Зеленого Мыса} CV {Острова Кука} CK 
{Острова Тёркс и Кайкос} TC {Острова Херд и Макдональд} HM Пакистан PK Палау PW {Палестинские территории} PS 
Панама PA {Папуа Новая Гвинея} PG Парагвай PY Перу PE Питкэрн PN Польша PL Португалия PT Пуэрто-Рико PR 
{Республика Корея} KR Реюньон RE {Российская Федерация} RU Руанда RW Румыния RO Сальвадор SV Самоа WS Сан-Марино SM 
{Сан-Томе и Принсипи} ST {Саудовская Аравия} SA Свазиленд SZ {Свальбард и Ян-Майен} SJ {Северная Корея} KP 
{Северные Марианские о-ва} MP {Сейшельские о-ва} SC {Сен-Пьер и Микелон} PM Сенегал SN {Сент-Винсент и Гренадины} 
VC {Сент-Киттс и Невис} KN Сент-Люсия LC Сербия RS {Сербия и Черногория} CS {Сеута и Мелилья} EA Сингапур SG 
Сирия SY Словакия SK Словения SI {Соломоновы о-ва} SB Сомали SO Судан SD Суринам SR США US Сьерра-Леоне SL 
Таджикистан TJ Таиланд TH Тайвань TW Танзания TZ Того TG Токелау TK Тонга TO {Тринидад и Тобаго} TT 
Тристан-да-Кунья TA Тувалу TV Тунис TN Туркменистан TM Турция TR Уганда UG Узбекистан UZ Украина UA 
{Уоллис и Футуна} WF Уругвай UY {Фарерские о-ва} FO {Федеративные Штаты Микронезии} FM Фиджи FJ Филиппины PH 
Финляндия FI {Фолклендские о-ва} FK Франция FR {Французская Гвиана} GF {Французская Полинезия} PF 
{Французские Южные Территории} TF Хорватия HR ЦАР CF Чад TD Черногория ME Чехия CZ Чили CL Швейцария CH Швеция 
SE Шри-Ланка LK Эквадор EC {Экваториальная Гвинея} GQ Эритрея ER Эстония EE Эфиопия ET ЮАР ZA 
{Южная Джорджия и Южные Сандвичевы Острова} GS Ямайка JM Япония JP
}
set rfregions  {{Республика Адыгея (Адыгея)} {Республика Башкортостан} {Республика Бурятия} {Республика Алтай} 
{Республика Дагестан} {Республика Ингушетия} {Кабардино-Балкарская Республика} {Республика Калмыкия} 
{Карачаево-Черкесская Республика} {Республика Карелия} {Республика Коми} {Республика Марий Эл} 
{Республика Мордовия} {Республика Саха (Якутия)} {Республика Северная Осетия - Алания} 
{Республика Татарстан} {1Республика Тыва} {Удмуртская Республика} {Республика Хакасия} {Чеченская Республика} 
{Чувашская Республика - Чувашия} {Алтайский край} {Краснодарский край} {Красноярский край} {Приморский край} 
{Ставропольский край} {Хабаровский край} {Амурская область} {Архангельская область и Ненецкий автономный округ} 
{Астраханская область} {Белгородская область} {Брянская область} {Владимирская область} {Волгоградская область} 
{Вологодская область} {Воронежская область} {Ивановская область} {Иркутская область} {Калининградская область} 
{Калужская область} {Камчатский край} {Кемеровская область} {Кировская область} {Костромская область} 
{Курганская область} {Курская область} {Ленинградская область} {Липецкая область} {Магаданская область} 
{Московская область} {Мурманская область} {Нижегородская область} {Новгородская область} 
{Новосибирская область} {Омская область} {Оренбургская область} {Орловская область} {Пензенская область} 
{Пермский край} {Псковская область} {Ростовская область} {Рязанская область} {Самарская область} 
{Саратовская область} {Сахалинская область} {Свердловская область} {Смоленская область} {Тамбовская область} 
{Тверская область} {Томская область} {Тульская область} {Тюменская область} {Ульяновская область} 
{Челябинская область} {Забайкальский край} {Ярославская область} {г. Москва} {г. Санкт-Петербург} 
{Еврейская автономная область} {Ханты-Мансийский автономный округ - Югра} {Чукотский автономный округ} 
{Ямало-Ненецкий автономный округ} {Иные территории, включая, г. Байконур}}

#    req.default_key.labels        {"gost2001 1.2.643.2.2.35.1" "gost2012_256 1.2.643.2.2.36.0" "gost2012_512 1.2.643.7.1.21.2.1"}
#Главное поле _DN_Fields
array set profile_options {
    req.default_key.options        {"RSA" "gost2001" "gost2012_256" "gost2012_512"}
    req.default_key.default        "RSA"
    req.default_param.default        ""
    req.default_libp11.default        ""
    req.default_bits.default        {1024}
    req.default_bits.options        {512 1024 2048 4096}
    req.default_bits.labels        {"low grade (512 bits)" "medium grade (1024 bits)" "high grade (2048 bits)" "very high grade(4096 bits)"}
    CA_ext.nsCertType.options {client server email objsign reserved sslCA emailCA objCA}
    CA_ext.keyUsage.options {digitalSignature nonRepudiation keyEncipherment dataEncipherment keyAgreement keyCertSign cRLSign encipherOnly decipherOnly}
    CA_ext.extKeyUsage.options {whois role serverAuth clientAuth codeSigning emailProtection ipsecEndSystem ipsecTunnel ipsecUser timeStamping OCSPSigning msSGC nsSGC }
    CA_ext.extKeyUsageRoles.options {serverAuth1 clientAuth1 codeSigning1 emailProtection1 ipsecEndSystem1 ipsecTunnel1 ipsecUser1 timeStamping1 OCSPSigning1 msSGC1 nsSGC1}
    _DN_Fields {C ST L street O OU CN SN GN INN OGRN OGRNIP SNILS title emailAddress unstructuredName}

    _DN_Fields.labels {"Country" "State or Province" "City" "Organisation" "Organisational Unit" "Common Name" "INN" "Email Address"}
    req.dn_fields_ORIG {
        C "Country" ST "State or Province" L "City" street "Adress" title "Title"
        O "Organisation" OU "Organisational Unit"
        CN "Common Name" SN "SN" GN "GN" INN "INN" OGRN "OGRN" OGRNIP "OGRNIP" SNILS "SNILS" emailAddress "Email Address"
        unstructuredName "KPP"

    }
    req.dn_fields {
        C "Страна" ST "Регион" L "Населенный пункт" street "Улица, дом" title "Должность"
        O "Наименование Организация" OU "Подразделение"
        CN "ФИО" SN "Фамилия" GN "Имя, Отчество" INN "ИНН" OGRN "ОГРН" OGRNIP "ОГРНИП" SNILS "СНИЛС" emailAddress "Электронная почта"
        unstructuredName "KPP"
    }
    req.dn_fieldsCA {
        C "Страна" ST "Регион" L "Населенный пункт" street "Улица, дом"
        O "Наименование организация" OU "Подразделение"
        CN "Организация" INN "ИНН"  OGRN "ОГРН" SNILS "СНИЛС" emailAddress "Электронная почта"
    }
    req.dn_fieldsFL63 {
        C "Страна" ST "Регион" L "Населенный пункт" street "Улица, дом" title "Должность"
        O "Наименование Организация" OU "Подразделение"
        CN "ФИО/Организация" SN "Фамилия" GN "Имя, Отчество" INN "ИНН" OGRN "ОГРН" OGRNIP "ОГРНИП" SNILS "СНИЛС" emailAddress "Электронная почта"
        unstructuredName "КПП"
    }
    CA_ext.basicConstraints.options {
        {}
        {CA:TRUE}
        {CA:FALSE}
        {critical, CA:TRUE}
        {critical, CA:FALSE}
    }
    
    other.suggestfilename.default {Email}
    other.suggestfilename.options {Email "Common Name"}

    other.subjecttype.default {Other}
    other.subjecttype.options {Personal Server Other}
    
}


set profile_template {

    path ""
    CA.dir             {db}
    CA.database        {db/index.txt}
    CA.serial          {db/serial}
    CA.crl_dir         {db/crl}
    CA.certs           {db/certs}
    CA.new_certs_dir   {db/newcerts}
    CA.certificate     {db/certs/rootca.pem}
    CA.private         {db/private}
    CA.private_key     {db/private/rootca.key}
    CA.crl             {db/crl.pem}
    CA.RANDFILE        {db/private/.rand}
    CA.default_md      "default"
    CA.default_days 366
    CA.default_crl_days 30
    CA.x509_extensions CA_ext
    CA.#crl_extensions crl_ext
    CA.preserve        no
    CA.policy          policy_anything
    
    CA_ext.basicConstraints {critical, CA:FALSE}
    CA_ext.keyUsage {digitalSignature, keyEncipherment}
    CA_ext.subjectKeyIdentifier hash
    CA_ext.authorityKeyIdentifier keyid,issuer:always
    CA_ext.subjectAltName email:copy
    CA_ext.issuerAltName issuer:copy
    CA_ext.nsCertType server
    CA_ext.nsCaPolicyUrl http://www.dfn-pca.de/certification/policies/x509policy.html
    CA_ext.nsComment {This certificate was issued by a Server CA}
    CA_ext.authorityInfoAccess caIssuers;URI:http://museum.lissi-crypto.ru/docs/ucfz_63/CAFL63.crt
    CA_ext.crlDistributionPoints URI:http://museum.lissi-crypto.ru/docs/ucfz_63/CAFL63.crl

    CA_ext.nsRevocationUrl cgi/non-CA-rev.cgi?
    CA_ext.nsBaseUrl http://www.dfn-pca.de/
    CA_ext.nsRenewalUrl cgi/check-renw.cgi?
    
    req.default_keyfile     privkey.pem
    req.default_key	    "RSA"
    req.default_param	    ""
    req.default_libp11        ""
    req.default_bits        1024
    req.x509_extensions     v3_ca
    req.string_mask         req.nombstr
    req.attributes          req_attributes
    req.distinguished_name  req_distinguished_name

    req.dn_fields    {CN "" emailAddress ""}
    req.dn_fields.required    "CN emailAddress"
    
    other.suggestfilename {Email}
    other.subjecttype {Other}

    publish.last             {db/lastpub.txt}

    system.ckzi "Наименование СКЗИ ключа пользователя"
    system.kc12 "KC1ClassSignTool"
    system.cafl63 "Наименование УЦ"
    system.certckzi "Сертификат СКЗИ УЦ"
    system.certca "Сертификат УЦ"
    system.smime "GOST 28147-89"
}
#    ckzi "СКЗИ ЛИРССЛ-CSP"
#    kc12 "KC1ClassSignTool"
#    cafl63 "Программно аппаратный комплекс ЛИССИ-УЦ"
#    certckzi "СФ/111-1978 от 01.02.2013"
#    certca "СФ/111-1869 от 26.06.2012"

set profile_test {
    
    CA_ext.#basicConstraints {critical, CA:FALSE}
    CA_ext.keyUsage {digitalSignature keyEncipherment}
    CA_ext.keyUsage.options {digitalSignature nonRepudiation keyEncipherment dataEncipherment keyAgreement keyCertSign cRLSign encipherOnly decipherOnly}
    CA_ext.subjectKeyIdentifier hash
    CA_ext.authorityKeyIdentifier keyid,issuer:always
    CA_ext.nsCertType server
    CA_ext.nsCertType.options {client server email objsign reserved sslCA emailCA objCA}
    
    req.default_keyfile     privkey.pem
    req.default_bits        1024
    req.x509_extensions     v3_ca
    req.string_mask         req.nombstr
    req.attributes          req_attributes
    req.distinguished_name  req_distinguished_name
    
}

set config_file_template {
[ req ]
default_bits        = $prof(req.default_bits)
default_keyfile			  = server.key
distinguished_name		= req_distinguished_name
string_mask			      = utf8only
req_extensions	    	= v3_req
prompt              = no

[ req_distinguished_name ]
$attr(DN)

[ v3_req ]
nsCertType			       = $prof(CA_ext.nsCertType)
basicConstraints  		= $prof(CA_ext.basicConstraints)
subjectSignTool		= $prof(system.ckzi)

[ ca ]
default_ca          = CA

[ CA ]
dir                 = $prof(CA.dir)
certs               = $prof(CA.certs)
new_certs_dir       = $prof(CA.new_certs_dir)
database            = $prof(CA.database)
serial              = $prof(CA.serial)
RANDFILE            = $prof(CA.RANDFILE)
certificate         = $prof(CA.certificate)
private_key         = $prof(CA.private_key)
default_days        = $prof(CA.default_days)
default_crl_days    = $prof(CA.default_crl_days)
default_md          = "default"
preserve            = $prof(CA.preserve)
x509_extensions	   	= cert_ext
policy              = policy_anything

[ policy_anything ]
$prof(line.policy)

[ cert_ext ]
basicConstraints       = critical, CA:FALSE
issuerSignTool		= @issuer_sign_tool_section
subjectSignTool		= $prof(system.ckzi)
certificatePolicies	= $prof(system.kc12)
#SMIME-CAPS		= $prof(system.smime)

$prof(line.keyUsage)
#keyUsage                 = digitalSignature, keyEncipherment
$prof(line.nsCertType)
#nsCertType               = server
$prof(line.extKeyUsage)
#extKeyUsage                 = serverAuth
subjectKeyIdentifier     = hash
authorityKeyIdentifier   = keyid,issuer:always
subjectAltName           = email:copy
issuerAltName            = issuer:copy
$prof(line.authorityInfoAccess)
#authorityInfoAccess caIssuers;URI:http://museum.lissi-crypto.ru/docs/ucfz_63/CAFL63.crt,OCSP;URI:http://museum.lissi-crypto.ru/docs/ucfz_63:2560
$prof(line.crlDistributionPoints)
#crlDistributionPoints    = URI:http://museum.lissi-crypto.ru/docs/ucfz_63/CAFL63.crl

$prof(line.nsBaseUrl)
#nsBaseUrl                = http://www.simpleca.com/
$prof(line.nsRevocationUrl)
#nsRevocationUrl          = cgi/non-CA-rev.cgi?
$prof(line.nsCaPolicyUrl)
#nsCaPolicyUrl            = http://www.simpleca.com/policies/policy.html
$prof(line.nsRenewalUrl)
#nsRenewalUrl             = cgi/check-renw.cgi?
$prof(line.nsComment)
#nsComment                = This certificate was issued by a Server CA

[ ca_extensions ]
basicConstraints		= critical,CA:true
issuerSignTool			= @issuer_sign_tool_section
subjectSignTool			= $prof(system.ckzi)
subjectKeyIdentifier		= hash

[ ca_reqexts ]
nsCertType			= objsign,email,server

[issuer_sign_tool_section]
###### for KC1ClassSignTool policy ####
signTool			= $prof(system.ckzi)
cATool				= $prof(system.cafl63)
signToolCert		= $prof(system.certckzi)
cAToolCert			= $prof(system.certca)

###### for KC2ClassSignTool policy ####

}

namespace eval openssl {
    global db
    global typesys
    variable cmd
    variable config_file
    variable common_errors

    variable iso3166   ;# contains all iso country codes
    
    variable current_profile ;# current profile
                            ;# normally set by CreateConfigFile
                            ;# currently only used in docommand
    variable profiles   ;# array that stores profiles
                        ;# indexed by name
    variable templates  ;# templates for profiles
                        
    variable cfg
    set cfg(config_fn)    "config.cfg"
    #variable configfilename "openssl.config.txt"

    variable dialogfieldlabels
    array set dialogfieldlabels {
        serial "Serial #"
        issuer "Issued By"
        subject "Subject"
        notBefore "Valid From"
        notAfter "Valid Until"
        "MD5 Fingerprint" "MD5 Fingerprint"
        C {Country}
        ST {State or Province}
        L {Locality or City}
        street {street}
        O {Organization}
        OU {Organizational Unit}
        CN {Common Name}
        SN {SN}
        GN {GN}
        INN {INN}
        OGRN {OGRN}
        OGRNIP {OGRNIP}
	SNILS {SNILS}
	title {title}
        emailAddress {Email}
        XXXEmail {Email}
	UN (KPP)
        Type {Certificate Type}
        {X509v3 Basic Constraints} {Basic Constraints}
        {X509v3 Key Usage}        {Key Usage}
        {Netscape Cert Type} {Netscape Cert Type}
        {X509v3 Extended Key Usage} {Ext. Key Usage}
        {X509v3 Subject Key Identifier} {Subject Key ID}
        {X509v3 Authority Key Identifier} {Authority Key ID}
        {X509v3 Subject Alternative Name} {Subject Alternative Name}
        {X509v3 Issuer Alternative Name} {Issuer Alternative Name}
        {X509v3 Certificate Policies} {Certificate Policies}
        {Netscape Comment} {Netscape Comment}
        {Public Key} {Public Key}
    }

    array set newlabels {
        {X509v3 Subject Alternative Name} {Subject Alternative Name}
        {X509v3 Issuer Alternative Name} {Issuer Alternative Name}
        {X509v3 Certificate Policies} {Certificate Policies}
    }
    variable valid_dn_fields {
        C ST L street O OU CN SN GN INN OGRN OGRNIP SNILS title emailAddress unstructuredName
    }
#        C ST L SN O OU CN INN OGRN OGRNIP SNILS title emailAddress




    variable certificateformatguess_default
    set certificateformatguess_default PEM
    variable certificateformatguess
    array set certificateformatguess {
        .cer DER
        .crt PEM
        .der DER
        .pem PEM
        .p10 DER
        .csr PEM
    }

    variable openssl_executable
    set openssl_executable {openssl}
    global typesys

#    set cmd(newroot) {"$openssl" genrsa -des3 -passout env:capassword  1024}
    set cmd(newroot) {"$openssl" genrsa -des3 -passout env:capassword  $defaultpar}
    set cmd(newrootgost) {"$openssl" genpkey -algorithm $defaultkey -pkeyopt paramset:$defaultpar  -des3 -pass env:capassword}

    set cmd(signroot) {"$openssl" req -new -utf8 -x509 -extensions ca_extensions -reqexts ca_reqexts -days 3650 -config config.cfg -key [file join $attr(dir_db) rootca.key] -passin env:capassword}

    set cmd(newkey) {"$openssl" genrsa -out "$attr(key_fn)" $attr(encryptkey) -passout env:keypassword $prof(req.default_bits)}

#    set cmd(newkeygost) {"$openssl" genpkey -algorithm $defaultkey -pkeyopt paramset:$defaultpar -out "$attr(key_fn)" $attr(encryptkey) -pass env:keypassword }
    set cmd(newkeygost) {"$openssl" genpkey -algorithm $attr(default_key) -pkeyopt paramset:$attr(default_param) -out "$attr(key_fn)" $attr(encryptkey) -pass env:keypassword }

    set cmd(newreq) {"$openssl" req -new -utf8 -config config.cfg -key "$attr(key_fn)" -passin env:keypassword -outform $attr(outform) -out "$attr(csr_fn)"}
    set cmd(newreqdb) {"$openssl" req -new -utf8 -config config.cfg -key "$attr(key_fn)" -passin env:keypassword -outform PEM}

    set cmd(req_tmppem) {"$openssl" req -config config.cfg  -inform DER -in "$attr(csr_fn)" -outform PEM -out "$attr(pem_fn)"}
    set cmd(crt_tmppem) {"$openssl" x509 -inform DER -in "$attr(crt_fn)" -outform PEM -out "$attr(pem_fn)"}

    set cmd(signreq) {echo "$attr(csr_fn)" | "$openssl" x509 -req -inform PEM -outform PEM -CA [file join $attr(dir_db) rootca.pem] -CAkey [file join $attr(dir_db) rootca.key] -passin env:capassword -extfile config.cfg -extensions cert_ext -days $prof(CA.default_days) -set_serial $db(serNumCert)}

    set cmd(crt_pem2der) {"$openssl" x509 -inform PEM -in "$attr(crt_fn)" -outform DER -out "$attr(crt_fn)"}
    set cmd(revoke) {"$openssl" ca -config config.cfg -passin env:capassword -revoke "$attr(crt_fn)"}
    set cmd(gencrl) {"$openssl" ca -config config.cfg -gencrl -passin env:capassword }
    set cmd(exportpkcs12) {"$openssl" pkcs12 -export -in "$attr(crt_fn)" -inkey "$attr(key_fn)" -certfile "$prof(CA.certificate)" -name "$attr(username)" -caname "$attr(caname)" -out "$attr(p12_fn)" -passin env:keypassword -passout env:password}
    set cmd(exportpkcs12_gost) {"$openssl" pkcs12 -export -certpbe "gost89" -keypbe "gost89" -macalg "md_gost94" -in "$attr(crt_fn)"  -inkey "$attr(key_fn)" -certfile "$prof(CA.certificate)" -name "$attr(username)" -caname "$attr(caname)" -out "$attr(p12_fn)" -passin env:keypassword -passout env:password}
    set cmd(selfsignedcert) {"$openssl" req -new -x509 -days 3650 -config config.cfg -key "$attr(key_fn)" -passin env:keypassword -outform $attr(outform) -out "$attr(crt_fn)"}

    # list of common_errors
    # contains pairs of values
    # error pattern (regexp) followed by explanation.
    # used by openssl::CheckCommonErrors
    set common_errors {
        "ERROR:There is already a certificate" "Can not sign certificate request.\n\nValid Certificate already exists in database with identical subject."
        "problems making Certificate Request" "Не удается сделать запрос на сертификат.\n\nПожалуйста, проверьте поля DN."
        "unable to load CA private key" "Не удается загрузить закрытый ключ УЦ.\n\nПроверьте корректность пароля УЦ."
        "unable to load CA Private Key" "Нет доступа к закрытому ключу УЦ.\n\nПожалуйста, проверьте введенный вами пароль."
        ":system library:fopen:No such file or directory" "No such file or directory.\n\nPlease verify file name."
        "unable to load X509 request" "Не могу загрузить запрос на сертификат.\n\nПожалйста, проверьте корректость формата вашего файла."
        "Error loading certificates from input" "Unable to load certificate.\n\nPlease check that the certificate file is not damaged." 
        "ERROR:Already revoked" "Certificate has already been revoked before"
        "Error loading private key" "The private key could not be loaded. Please check the password."
        "extra characters after close-quote" "Проблема кавычек/скобок. Проверьте экранирование"
        "UNIQUE constraint failed: certDB.ckaID" "Сертификат для этого запроса (открытого ключа) уже выпущен"
        "UNIQUE constraint failed: reqDB.ckaID" "Запрос с таким открытым ключом уже имеется в БД!\nНеобходимо создать новый запрос на новом ключе."
        "UNIQUE constraint failed: reqDBAr.ckaID" "Запрос с таким открытым ключом уже имеется в БД!\nНеобходимо создать новый запрос на новом ключе."
    }
}

set ::emailpat {
^
(  # local-part
  (?:
    (?:
      (?:[^"().,:;\[\]\s\\@]+)   # one or more non-special characters (not dot)
      |
      (?:
        "  # begin quoted string
        (?:
         [^\\"]  # any character other than backslash or double quote
         |
         (?:\\.) # or a backslash followed by another character
        )+   # repeated one or more times
        "  # end quote
      )
    )
    \.   # followed by a dot
  )*    # local portion with trailing dot repeated zero or more times.
  (?:[^"().,:;\[\]\s\\@]+)|(?:"(?:[^\\"]|(?:\\.))+")  # as above, the final portion may not contain a trailing dot
)
@
(  # domain-name, underscores are not allowed
  (?:(?:[A-Za-z0-9][A-Za-z0-9-]*)?[A-Za-z0-9]\.)+ # one or more domain specifiers followed by a dot
  (?:[A-Za-z0-9][A-Za-z0-9-]*)?[A-Za-z0-9]     # top-level domain
  \.?           # may be fully-qualified
)
$
}

proc verifyemail {emailtest} {
    set rc NG
    if { [regexp -expanded $::emailpat $emailtest emailaddr local domain] } {
	set rc OK
    }
    return $rc
}
## Procedure:  Digit
proc ::Digit {ent len text size} {
    set length [string length $text]
    if {$length != $len} {
#	$ent configure -bg white
	$ent configure -style white.TEntry
    }
    if {$length > $size} {
#	$ent configure -bg #00ffff
	$ent configure -style cyan.TEntry
	return 0
    }
    
    if {[regexp {[^0-9]} $text]} {
#	$ent configure -bg red
	$ent configure -style red.TEntry
	return 0
    }
    if {$length == $size} {
#	$ent configure -bg #00ffff
	$ent configure -style cyan.TEntry
	return 1
    }
    if {$len >= $size} {
#	$ent configure -bg #00ffff
	$ent configure -style cyan.TEntry
	return 0
    }
#    $ent configure -bg white
    $ent configure -style white.TEntry
    return 1
}

proc parse_key_gost_BAD {key } {
	array set parsed_key [::pki::_parse_pem $key "-----BEGIN PRIVATE KEY-----" "-----END PRIVATE KEY-----" ""]

	set key_seq $parsed_key(data)

	::asn::asnGetSequence key_seq key
	::asn::asnGetBigInteger key version

	::asn::asnGetSequence key key_gost
	
					::asn::asnGetObjectIdentifier key_gost pubkey_type
	::asn::asnGetSequence key_gost key_par
					::asn::asnGetObjectIdentifier key_par pubkey_par
					::asn::asnGetObjectIdentifier key_par pubkey_par1
					::asn::asnGetOctetString key pubkey

	
	## Convert Pubkey type to string
	set pubkey_type [::pki::_oid_number_to_name $pubkey_type]
#	puts $pubkey_type
	set pubkey_par [::pki::_oid_number_to_name $pubkey_par]
#	puts $pubkey_par
	set pubkey_par1 [::pki::_oid_number_to_name $pubkey_par1]
#	puts $pubkey_par1
			binary scan $pubkey H* ret(pubkey)
#	puts $ret(pubkey)
#	puts [string range $ret(pubkey) 4 end]

    return [string range $ret(pubkey) 4 end]
}

proc parse_cert_gost {cert} {
#    parray ::pki::oids
#puts "parse_cert_gost=$cert"
    set cert_seq ""
    if { [string range $cert 0 9 ] == "-----BEGIN" } {
	array set parsed_cert [::pki::_parse_pem $cert "-----BEGIN CERTIFICATE-----" "-----END CERTIFICATE-----"]
	set cert_seq $parsed_cert(data)
    } else {
#FORMAT DER
	set cert_seq $cert
    }
    set finger [::sha1::sha1 $cert_seq]
    set ret(fingerprint) $finger

    binary scan  $cert_seq H* certdb 
    set ret(certdb) $certdb
#puts "CERTDB=$certdb"
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
	::asn::asnGetSequence cert validity
		::asn::asnGetUTCTime validity ret(notBefore)
		::asn::asnGetUTCTime validity ret(notAfter)
	::asn::asnGetSequence cert subject
	::asn::asnGetSequence cert pubkeyinfo

	binary scan  $pubkeyinfo H* pubkeyinfoG
	set ret(pubkeyinfo) $pubkeyinfoG


		::asn::asnGetSequence pubkeyinfo pubkey_algoid

	binary scan  $pubkey_algoid H* pubkey_algoidG
	set ret(pubkey_algoid) $pubkey_algoidG

			::asn::asnGetObjectIdentifier pubkey_algoid ret(pubkey_algo)
		::asn::asnGetBitString pubkeyinfo pubkey

	set extensions_list [list]
	while {$cert != ""} {
		::asn::asnPeekByte cert peek_tag

		switch -- [format {0x%02x} $peek_tag] {
			"0xa1" {
				::asn::asnGetContext cert - issuerUniqID
			}
			"0xa2" {
				::asn::asnGetContext cert - subjectUniqID
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
	set ret(data_signature_algo) [::pki::_oid_number_to_name $ret(data_signature_algo)]
	set ret(signature_algo) [::pki::_oid_number_to_name $ret(signature_algo)]
	set ret(pubkey_algo) [::pki::_oid_number_to_name $ret(pubkey_algo)]
	set ret(issuer) [::pki::x509::_dn_to_string $issuer]
	set ret(subject) [::pki::x509::_dn_to_string $subject]
	set ret(signature) [binary format B* $ret(signature)]
	binary scan $ret(signature) H* ret(signature)

	# Handle RSA public keys by extracting N and E
#puts "PUBKEY_ALGO=$ret(pubkey_algo)"
	if {[string range $ret(pubkey_algo) 0 3] != "1.2."} {
	    set ret(pubkey_algo) [::pki::_oid_name_to_number "$ret(pubkey_algo)"]
	}
#puts "ret(pubkey_algo)=$ret(pubkey_algo)"
	switch -- $ret(pubkey_algo) {
		"1 2 840 113549 1 1 1" -
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
		"1.2.643.2.2.19" -
		"1.2.643.7.1.1.1.1" -
		"1.2.643.7.1.1.1.2" -
		"1 2 643 2 2 19" -
		"1 2 643 7 1 1 1 1" -
		"1 2 643 7 1 1 1 2" {
#	gost2001, gost2012-256,gost2012-512
			set pubkey [binary format B* $pubkey]
			binary scan $pubkey H* ret(pubkey)
			set ret(type) gost
			::asn::asnGetSequence pubkey_algoid pubalgost
#OID - параметра
			::asn::asnGetObjectIdentifier pubalgost ret(paramkey)
#OID - Функция хэша
			::asn::asnGetObjectIdentifier pubalgost ret(hashkey)
#puts "ret(paramkey)=$ret(paramkey)\n"
#puts "ret(hashkey)=$ret(hashkey)\n"
		}
	}
	return [array get ret]
}

proc parse_crl {crl} {
    array set ret [list]
    if { [string range $crl 0 9 ] == "-----BEGIN" } {
	array set parsed_crl [::pki::_parse_pem $crl "-----BEGIN X509 CRL-----" "-----END X509 CRL-----"]
	set crl $parsed_crl(data)
    }
    ::asn::asnGetSequence crl crl_seq
	::asn::asnGetSequence crl_seq crl_base
	    ::asn::asnPeekByte crl_base peek_tag
	if {$peek_tag == 0x02} {
		# Version number is optional, if missing assumed to be value of 0
		::asn::asnGetInteger crl_base ret(version)
		incr ret(version)
	} else {
		set ret(version) 1
	}

	::asn::asnGetSequence crl_base crl_full
		::asn::asnGetObjectIdentifier crl_full ret(signtype) 
	    ::::asn::asnGetSequence crl_base crl_issue
		set ret(issue) [::pki::x509::_dn_to_string $crl_issue]

	    ::asn::asnGetUTCTime crl_base ret(publishDate)
	    ::asn::asnGetUTCTime crl_base ret(nextDate)
    return [array get ret]
}

proc parse_csr_gost {csr} {
	array set ret [list]
	if { [string range $csr 0 13 ] == "-----BEGIN NEW" } {
							  
	    array set parsed_csr [::pki::_parse_pem $csr "-----BEGIN NEW CERTIFICATE REQUEST-----" "-----END NEW CERTIFICATE REQUEST-----"]
	    set csr $parsed_csr(data)
	} elseif { [string range $csr 0 9 ] == "-----BEGIN" } {
	    array set parsed_csr [::pki::_parse_pem $csr "-----BEGIN CERTIFICATE REQUEST-----" "-----END CERTIFICATE REQUEST-----"]
	    set csr $parsed_csr(data)
	} 
        set pem "-----BEGIN CERTIFICATE REQUEST-----\n"
	set pem1 [binary encode base64 -maxlen 64 $csr]
	set pem2 "\n-----END CERTIFICATE REQUEST-----\n"
	set pem $pem$pem1$pem2
	set ret(pem) $pem

	::asn::asnGetSequence csr cert_req_seq
		::asn::asnGetSequence cert_req_seq cert_req_info

	set cert_req_info_saved [::asn::asnSequence $cert_req_info]

			::asn::asnGetInteger cert_req_info version
			::asn::asnGetSequence cert_req_info name
			::asn::asnGetSequence cert_req_info pubkeyinfo
				::asn::asnGetSequence pubkeyinfo pubkey_algoid
					::asn::asnGetObjectIdentifier pubkey_algoid pubkey_type
					::asn::asnGetBitString pubkeyinfo pubkey
		::asn::asnGetSequence cert_req_seq signature_algo_seq
			::asn::asnGetObjectIdentifier signature_algo_seq signature_algo
		::asn::asnGetBitString cert_req_seq signature_bitstring

	# Convert parsed fields to native types
	set signature [binary format B* $signature_bitstring]
	set ret(subject) [::pki::x509::_dn_to_string $name]
	## Convert Pubkey type to string
	set pubkey_type [::pki::_oid_number_to_name $pubkey_type]

	# Parse public key, based on type
#puts "pubkey_type=$pubkey_type"
	if {[string range $pubkey_type 0 3] != "1.2."} {
	    set pubkey_type [::pki::_oid_name_to_number "$pubkey_type"]
	}
#puts "pubkey_type=$pubkey_type"
	switch -- $pubkey_type {
		"1 2 840 113549 1 1 1" -
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
		"1.2.643.2.2.19" -
		"1.2.643.7.1.1.1.1" -
		"1.2.643.7.1.1.1.2" -
		"1 2 643 2 2 19" -
		"1 2 643 7 1 1 1 1" -
		"1 2 643 7 1 1 1 2" {
#	gost2001, gost2012-256,gost2012-512
			set pubkey [binary format B* $pubkey]
			binary scan $pubkey H* ret(pubkey)
			set ret(type) $pubkey_type
			::asn::asnGetSequence pubkey_algoid pubalgost
#OID - параметра
			::asn::asnGetObjectIdentifier pubalgost oid1
#OID - Функция хэша
			::asn::asnGetObjectIdentifier pubalgost oid2
#puts "oid1=$oid1\n"
#puts "oid2=$oid2\n"
		}
		default {
			error "Unknown algorithm"
		}
	}

	# Convert key to RSA parts
	set keylist [array get key]

	array set ret $keylist

	return [array get ret]
}

proc openssl::ConfigFile_CreateDN {attr} {
    upvar $attr attributes

    set retval ""

    foreach v {C ST L street O OU CN SN GN INN OGRN OGRNIP SNILS title emailAddress unstructuredName} {
        if {[info exists attributes($v)]} {
            if {$attributes($v) != ""} {
                append retval "$v\t\t= $attributes($v)\n"
            }
        }
    }

    return $retval
}

proc openssl::ConfigFile_IfExists {name variablename} {
#    puts "openssl::IfExists $name $variablename"
    upvar $variablename varname
    #puts "variable : $varname"
    set retval ""
    if {[info exists varname]} {
        if {$varname != ""} {
            append retval "$name\t\t= $varname\n"
        }
    }

}

proc openssl::ConfigFile_GenerateValues {prof} {
    upvar $prof p

#    puts "openssl::GenerateFile_GenerateValues"
    
    # key usage
    set p(line.keyUsage) [ConfigFile_IfExists    keyUsage p(CA_ext.keyUsage)]
    # extended key usage
    set p(line.extKeyUsage) [ConfigFile_IfExists    extendedKeyUsage p(CA_ext.extKeyUsage)]
    # netscape certificate type
    set p(line.nsCertType) [ConfigFile_IfExists    nsCertType p(CA_ext.nsCertType)]
    # netscape others
    set p(line.nsBaseUrl) [ConfigFile_IfExists  nsBaseUrl p(CA_ext.nsBaseUrl)]
    set p(line.nsCaPolicyUrl) [ConfigFile_IfExists  nsCaPolicyUrl p(CA_ext.nsCaPolicyUrl)]
    set p(line.nsRevocationUrl) [ConfigFile_IfExists  nsRevocationUrl p(CA_ext.nsRevocationUrl)]
    set p(line.nsRenewalUrl) [ConfigFile_IfExists  nsRenewalUrl p(CA_ext.nsRenewalUrl)]
    set p(line.nsComment) [ConfigFile_IfExists  nsComment p(CA_ext.nsComment)]
    # policy options
    set p(line.crlDistributionPoints) [ConfigFile_IfExists crlDistributionPoints p(CA_ext.crlDistributionPoints)]
# authorityInfoAccess
    set p(line.authorityInfoAccess) [ConfigFile_IfExists authorityInfoAccess p(CA_ext.authorityInfoAccess)]

    # policy
    global profile_options
    array set opts [array get profile_options]
    set p(line.policy) ""
    foreach {field value} $p(req.dn_fields) {
        if {[lsearch -exact $p(req.dn_fields.required) $field] != -1} {
            append p(line.policy) "$field = supplied\n"
        } else  {
            append p(line.policy) "$field = optional\n"
        }
    }

}

proc openssl::_GenerateConfigAttributes {attr} {
    upvar $attr attributes
    
    set retval ""
    foreach v {C ST L street O OU CN SN GN INN OGRN OGRNIP SNILS title emailAddress unstructuredName} {
        if {[info exists attributes($v)]} {
            if {$attributes($v) != ""} {
                append retval "$v\t\t= $attributes($v)\n"
            }
        }
    }
    
    return $retval
}


proc openssl::CSR_ParseSubject {subject} {
    
    debug::msg "openssl::CSR_ParseSubject \"$subject\"" 2
    
    set result {}
    
    foreach sub [split $subject / ] {
        foreach s [split $sub , ] {
            set v [split $s =]; 
            set v0 [string trim [lindex $v 0]]; 
            set v1 [string trim [lindex $v 1]]
            lappend result $v0 $v1
        }
    }
######################
            set attributes {}
	    set oidsub ""
#puts "Request_GetInfo=$txt"
	    set lsub [split $subject ","]
	    set subject [del_comma $lsub]
#puts "Request_GetInfo new=$txt"

	    foreach a $subject {
		set ind [string first "=" $a]
		if {$ind == -1 } { 
		    set oidval "$oidval $a"
		    continue 
		}
		if {$oidsub != ""} {
		    set oidval [string trimright $oidval ","]
#		    puts "DEL_COMMA: $oidsub = \"$oidval\""
		    lappend attributes $oidsub
		    lappend attributes $oidval
		}
		set oidsub [string trim [string range $a 0 $ind-1]]
#	puts $nameoid
		set oidval "[string trim [string range $a $ind+1 end]]"
	    }
	    lappend attributes $oidsub
	    lappend attributes $oidval
###############
            set result $attributes


#puts "CSR_ParseSubject=\"$result\""
    return $result
}

proc openssl::CSR_GetSubject {filename} {

    variable openssl_executable
    
    debug::msg "openssl::CSR_GetSubject $filename" 2

    # set format of certificate (DER/PEM)
    set inform [Certificate_GuessFormat $filename]


    set cmd(read_req) {"$openssl" req -text -nameopt utf8 -inform "$inform" -in "$filename" -out "req.txt"}

    # openssl executable
    #
    set openssl "$openssl_executable"

    set command [subst $cmd(read_req)]
    Log::LogMessage "\[OPENSSL\] $command" bold
    # should test error messages here
    catch {eval exec $command}
    set f [open "req.txt" r]
    set text [read $f]  
    close $f

    regsub {.* Subject:} $text {} text
    regsub {\n.*} $text {} text
    
    catch {file delete -force "req.txt"}
#puts "CSR_GetSubject=$text"
    return [CSR_ParseSubject $text]
}

proc openssl::CSR_GetSubjectDB {filename} {
    global typesys
    variable openssl_executable
    
    debug::msg "openssl::CSR_GetSubjectDB $filename" 2

    # set format of certificate (DER/PEM)
    set inform [Certificate_GuessFormat $filename]
#puts "CSR_GetSubjectDB=\"$filename\""

    set cmd(read_req) {echo "$filename" | "$openssl" req -text -nameopt utf8 -inform PEM}

    # openssl executable
    #
    set openssl "$openssl_executable"

    set command [subst $cmd(read_req)]
    Log::LogMessage "\[OPENSSL\] $command" bold
    # should test error messages here
#    set err [catch {eval exec $command} result]
#puts "CSR_GetSubjectDB=$command"
    set err [catch {eval tk_exec $command} result]
    
    Log::LogMessage "\[OPENSSL CSR_GetSubjectDB\] result=$err"
#    Log::LogMessage "ACTION=read_req : \[$result\]"

    # check for common error conditions
    set errmsg [CheckCommonErrors $result]
    if {$errmsg != ""} {
        tk_messageBox -icon error -type ok -title Error -message "$errmsg"  -parent .cm
	return ""
    }

    if {$result != 0 } {
	set text $result
    } else {
	puts "Beda REQ"
	return ""
    }
    regsub {.* Subject:} $text {} text
    regsub {\n.*} $text {} text
#puts "CSR_GetSubjectDB=$text"
    return [CSR_ParseSubject $text]

    catch {eval tk_exec $command}
    set f [open "req.txt" r]
    set text [read $f]
    close $f

    regsub {.* Subject:} $text {} text
    regsub {\n.*} $text {} text
    
    catch {file delete -force "req.txt"}

    return [CSR_ParseSubject $text]
}

proc openssl::CheckCommonErrors {result_text} {
    
    variable common_errors

    debug::msg "openssl::CheckCommonErrors \"$result_text\"" 2

    set ret_code ""

    foreach {code explanation} $common_errors {
	if {[regexp $code $result_text]} {
	    set ret_code $explanation
	    break
	}	
    }
    
    return $ret_code
}

proc openssl::GetIso3166 {} {

    global g_iso3166_codes
    variable iso3166
    variable iso3166_map
    
    catch {unset iso3166}
    catch {unset iso3166_map}
    foreach {long short} $g_iso3166_codes {
	lappend iso3166 $long
	set iso3166_map($short) "$long"
	set iso3166_map($long) "$short"
    }
}

proc openssl::Iso3166Map {v} {

    variable iso3166_map
    
    return $iso3166_map($v)

}

##################################################
# openssl::CreateRequest
# create certificate signing request
# profile : certificate profile to use
# attributes : array with DN (distinguited name)
#

proc openssl::CreateRequest {profilename attributes} {
    global defaultkey
    global defaultpar

    debug::msg "openssl::CreateRequest  \"$profilename\" \"$attributes\""
    debug::msg "openssl::CreateRequest  \"$defaultkey\" "
#puts "DEFAULTKEY=$defaultkey"
    
    upvar $attributes attr

    # set format of certificate (DER/PEM)
    set attr(outform) [Certificate_GuessFormat $attr(csr_fn)]
    
    # encryption
    if {$attr(keypassword)!= ""} {
        set attr(encryptkey) -des3
    }
#parray attr
    if {$defaultkey == "RSA"} {
    openssl::docommand newkey $profilename attr
    } else {
    openssl::docommand newkeygost $profilename attr
    }
    set err 0
    set err [openssl::docommand newreq $profilename attr]
    return $err
}

proc page0com2 {} {
    global typeimport
    set typeimport 0
    
    cmd::WizardCreateRequestDB
}

proc page3com1 {} {
    global db
    global certdb

    set file [file join $db(dir) index.txt]
    set fd [open $file w]

    foreach rev [certdb eval {select certDBRev.ckaID from certDBRev}] {
	certdb eval {select * from certDB where certDB.ckaID = $rev} vals {
	    puts $fd "$vals(state)\t$vals(notAfter)\t$vals(dateRevoke)\t$vals(sernum)\t\"unknown\"\t$vals(subject)"
	}
#puts "TAB=$vals(state)\t$vals(notAfter)\t$vals(dateRevoke)\t$vals(sernum)\t\"unknown\"\t$vals(subject)"
    }
    close $fd
    cmd::WizardGenerateCRL
}

proc page4com1 {} {
    page3com1
}

proc openssl::CreateRequestDB {profilename attributes} {
    global defaultkey
    global defaultpar

    debug::msg "openssl::CreateRequestDB  \"$profilename\" \"$attributes\""
    
    upvar $attributes attr

    # set format of certificate (DER/PEM)
    set attr(outform) PEM
    
    # encryption
    if {$attr(keypassword)!= ""} {
        set attr(encryptkey) -des3
    }
    
    if {$defaultkey == "RSA"} {
    openssl::docommand newkey $profilename attr
    } else {
    openssl::docommand newkeygost $profilename attr
    }
    set err 0
    set err [openssl::docommand newreqdb $profilename attr]
    return $err
}

##################################################
# openssl::SignRequest
# sign a certificate signing request
# profile : certificate profile to use
# attributes : array with attributes
#

proc openssl::SignRequest {profilename attributes} {
    global db
    upvar $attributes attr

    debug::msg "openssl::SignRequest  \"$profilename\" \"$attributes\""

    # set format of certificate (DER/PEM)
    set attr(inform) [Certificate_GuessFormat $attr(csr_fn)]
    set attr(outform) [Certificate_GuessFormat $attr(crt_fn)]

    # if input is DER format
    # convert to PEM format, and remember name of that file
    if {$attr(inform) == "DER"} {
        # to be replaced by CA profile
        array set prof [Template_GetData profile_template]
#puts "openssl::SignRequest DER to PEM"
        set attr(pem_fn) $prof(CA.dir)/tempcsr.pem
        openssl::docommand req_tmppem $profilename attr
        set attr(csr_fn) $prof(CA.dir)/tempcsr.pem
    }

    openssl::docommand signreq $profilename attr

    # if output = DER format
    # convert output file (PEM)to DER format
    if {$attr(outform) == "DER"} {
        openssl::docommand crt_pem2der $profilename attr
    }

    # should remove temporary files
    if {$attr(inform) == "DER"} {
        file delete -force $prof(CA.dir)/tempcsr.pem
    }

}

proc openssl::SignRequestByIndex {profilename attributes} {
    global db
    upvar $attributes attr

    debug::msg "openssl::SignRequestByIndex  \"$profilename\" \"$attributes\""

    # set format of certificate (DER/PEM)
    set attr(inform) PEM
    set attr(outform) PEM

    set attr(dir_db) $db(dir)

#    Log::LogMessage "\[openssl::SignRequestByIndex\] $attr(csr_fn)"
     	set f [open ff.txt w]
	puts $f $attr(csr_fn)
	close $f
 

    set err [openssl::docommand signreq $profilename attr]

    return $err 
}

##################################################
# openssl::CreatePKCS12
# create certificate directly as pkcs12
# profile : certificate profile to use
# attributes : array with attributes
#

proc openssl::CreatePKCS12 {profilename attributes} {
    
    variable config_file
    variable cmd
    variable profiles

    debug::msg "openssl::CreatePKCS12  \"$profilename\" \"$attributes\""

    #upvar $attributes attr
    #upvar $profile prof
    upvar $attributes attr
    #array set attr $attributes
    
    # format is not relevant
    # but is supposed to be set
    # set format of certificate (DER/PEM)
    set attr(outform) PEM
    #set attr(inform) PEM

    
    # need to also set export password
    set attr(password) $attr(keypassword)
    
    # encryption
    if {$attr(keypassword)!= ""} {
        set attr(encryptkey) -des3
    }
    
    array set prof [Template_GetData profile_template]
    array set prof [Profile_GetData $profilename]
    
    global profile_template
    global config_file_template
    #set config $config_template

    # temporary files for csr / key
    set attr(csr_fn) $prof(CA.dir)/tmp.csr
    set attr(key_fn) $prof(CA.dir)/tmp.key
    #set attr(crt_fn) $prof(CA.dir)/tmp.crt
    set attr(crt_fn) $prof(CA.dir)/tmp.pem
    
    # get 2 digit code from long name
    #if {$attr(C) != ""} {
    #    set attr(C) [openssl::Iso3166Map $attr(C)]
    #}
    #set attr(all) [openssl::GenerateConfigAttributes attr]
    #set attr(DN) [openssl::GenerateConfigDN attr]
    ConfigFile_Create $profilename attr
    
    if {$defaultkey == "RSA"} {
    openssl::docommand newkey $profilename attr
    } else {
    openssl::docommand newkeygost $profilename attr
    }
    openssl::docommand newreq $profilename attr
    openssl::docommand signreq $profilename attr
    openssl::docommand exportpkcs12 $profilename attr
    
    #RemoveConfigFile
    
    # remove temporary files
    file delete -force $attr(csr_fn)
    file delete -force $attr(key_fn)
    file delete -force $attr(crt_fn)
    
}

##################################################
# openssl::CreatePKCS12
# create certificate directly as pkcs12
# attributes : array with attributes
#

proc openssl::ExportPKCS12 {attributes} {
    
    variable config_file
    variable cmd
    variable profiles
    
    debug::msg "openssl::ExportPKCS12 \"$attributes\""
    

    upvar $attributes attr
    array set prof [Template_GetData profile_template]
    
    # set format of certificate (DER/PEM)
    set attr(inform) [Certificate_GuessFormat $attr(crt_fn)]

    # if input is DER format
    # convert to PEM format, and remember name of that file
    if {$attr(inform) == "DER"} {
        # to be replaced by CA profile
        array set prof [Template_GetData profile_template]
        set attr(pem_fn) $prof(CA.dir)/tempcert.pem
        openssl::docommand crt_tmppem "" attr
        set attr(crt_fn) $prof(CA.dir)/tempcert.pem
    }
    
    
    #openssl::docommand exportpkcs12 profile_template attr
    # no profile !!
    set err [openssl::docommand exportpkcs12 "" attr]

    # should remove temporary files
    if {$attr(inform) == "DER"} {
        file delete -force $prof(CA.dir)/tempcert.pem
    }
    if {[file size $attr(p12_fn)  ] == 0 && $err == 0} {
    	tk_messageBox -icon error -type ok -title "Экспорт PKCS#12" -message "Не смог эспортировать. Проверьте пароль"  -parent .cm
    	return 1	
    }
    #RemoveConfigFile
    return $err
}

proc openssl::RevokeCertificate {attributes} {
    global db
    global certdb
    global certID
    debug::msg "openssl::RevokeCertificate"
    upvar $attributes attr
#puts "RevokeCertificate=$attr(cka_id)"
#puts "RevokeCertificate_treeID=$attr(treeID)"

#parray attr
if {$attr(treeID) != ""} {
#Сертификат в БД
    set hash256 [::sha2::sha256 $attr(capassword)]
    if {$db(pasDB) != $hash256} {
        tk_messageBox -title "Отзыв сертификата" -icon error -message "Вы ошиблись с паролем УЦ\n" -parent .cm
        return
    }
    set ll [$db(treeCert) item $attr(treeID) -values]
    set status [lindex $ll 4]
    if {$status == "R"} {
        tk_messageBox -title "Отзыв сертификата" -icon error -message "Сертификат уже отозван\n" -parent .cm
        return
    }

    set drevoke [clock format [clock seconds]  -format {%y%m%d%H%M%S}]
    certdb eval {begin transaction}
	certdb eval {update certDB set dateRevoke=$drevoke, state="R" where ckaID=$attr(cka_id)}
	certdb eval {insert into certDBRev values ( $attr(cka_id) )}
    certdb eval {end transaction} 
    set ll [$db(treeCert) item $attr(treeID) -values]
    set ll [lreplace $ll 4 4 "R"]
    set ll [lreplace $ll 6 6 $drevoke]
    $db(treeCert) item $attr(treeID) -values $ll
    CertificateRevoke_Update .cm $db(treeCertRev)
    tk_messageBox -title "Отзыв сертификата" -icon info -message "Сертификат отозван.\nПри выпуске списка СОС/CRL он будет включен в него. " -parent .cm
    return
}
    # set format of certificate (DER/PEM)
    set attr(inform) [Certificate_GuessFormat $attr(crt_fn)]
        
    if {$attr(inform) == "DER"} {
        # to be replaced by CA profile
        array set prof [Profile_GetData profile_template]
        
        set attr(pem_fn) $prof(CA.dir)/tmp.pem
        openssl::docommand crt_tmppem profile_template attr
        set attr(crt_fn) $prof(CA.dir)/tmp.pem
    }
    
    openssl::docommand revoke {} attr
    
    # should remove temporary files
    #if {$attr(inform) == "DER"} {
    #    file delete $prof(CA.dir)/tmp.pem
    #}
    
}

proc openssl::ExamineRequest {attributes} {
    global db
    global certdb
    global certID
    global reqID
    global reqIDAr
    debug::msg "openssl::ExamineRequest"
    upvar $attributes attr
#puts "ExamineRequest=$attr(cka_id)"
#puts "ExamineRequest=$attr(treeID)"
#puts "ExamineRequest_Solution=$attr(solution)"
    if {$attr(solution) == 1 } {
	set tit "Утверждение запроса"
	set status "Утвержден"
	set imgcsr csr_ok_40x19
	set arch 0
    } else {
	set tit "Отклонение запроса"
	set status "Отклонен"
	set imgcsr csr_refuze_40x19
	set arch 1
    }

#parray attr
    set hash256 [::sha2::sha256 $attr(capassword)]
    if {$db(pasDB) != $hash256} {
        tk_messageBox -title "Обработка запроса" -icon error -message "Вы ошиблись с паролем УЦ\n" -parent .cm
        return -code break;
    }

    set dexamine [clock format [clock seconds]  -format {%y%m%d%H%M%S}]
    certdb eval {begin transaction}
	certdb eval {update reqDB set status=$status where ckaID=$attr(cka_id)}
    	if {$arch == 1} {
	    certdb eval {select * from reqDB  where ckaID=$attr(cka_id)} r {
#certdb eval {create table reqDB (ckaID text primary key, nick  text,  sernum text, subject text, type text, datereq, status text, reqpem text, pkcs7 text)}
		certdb eval {insert into reqDBAr values ($r(ckaID), $r(nick), $r(sernum), $r(subject), $r(type), $r(datereq), $r(status), $r(reqpem), $r(pkcs7))}
		certdb eval {delete from reqDB where ckaID=$r(ckaID)}
	    }
    	}
    certdb eval {end transaction} 
    if {$arch == 1} {
	RequestArManager_Update .cm $db(treeReqAr)
	$db(treeReq) delete $attr(treeID)
	incr reqID -1
        tk_messageBox -title "Обработка запроса" -icon error -message "Запрос отклонен и перемещен в архив\n" -parent .cm
    } else {
    set ll [$db(treeReq) item $attr(treeID) -values]
    set ll [lreplace $ll 5 5 $status]
    $db(treeReq) item $attr(treeID) -values $ll -image $imgcsr
        tk_messageBox -title "Обработка запроса" -icon error -message "Запрос утвержден. Можно выпускать сертификат\n" -parent .cm
    }
    return
}

proc openssl::GenerateCRL {attributes} {
    
    debug::msg "openssl::GenerateCRL"
    upvar $attributes attr
    
    #openssl::docommand gencrl profile_template attr
    openssl::docommand gencrl "" attr
}

proc openssl::CreateSelfSigned {profilename attributes} {
    global defaultkey
    global defaultpar
    
    debug::msg "openssl::CreateSelfSigned"
    upvar $attributes attr

    # set format of certificate (DER/PEM)
    set attr(outform) [Certificate_GuessFormat $attr(crt_fn)]
    
    # encryption
    if {$attr(keypassword)!= ""} {
        set attr(encryptkey) -des3
    }
    
    if {$defaultkey == "RSA"} {
    openssl::docommand newkey $profilename attr
    } else {
    openssl::docommand newkeygost $profilename attr
    }
    openssl::docommand selfsignedcert $profilename attr
    
}


##################################################
# openssl::profile-pack
# recalculate profile based on input parameters
# profile : (unpacked) certificate profile to use
# returns : packed profile
#

proc openssl::Profile_Pack {profile} {
    global oid_roles
    global profile_options
    upvar #0 profile_options opts
    #array set prof $profile
    upvar $profile prof
    debug::msg "openssl::Profile_Pack"
#puts "openssl::Profile_Pack"
    # Key Usage
    set prof(CA_ext.keyUsage) ""
    foreach v $profile_options(CA_ext.keyUsage.options) {
        if {$prof(CA_ext.keyUsage.$v)} {
            lappend prof(CA_ext.keyUsage) $v
        }
        array unset prof CA_ext.keyUsage.$v
    }
    set prof(CA_ext.keyUsage) [join $prof(CA_ext.keyUsage) ", "]
    
    # Extended Key Usage
    set prof(CA_ext.extKeyUsage) ""
    foreach v $profile_options(CA_ext.extKeyUsage.options) {
	if {$v == "role" } {
	    set role $prof(CA_ext.extKeyUsage.$v)
	    if {$role != ""} {
        	lappend prof(CA_ext.extKeyUsage) $oid_roles($role)
            }
#puts "Role=$role"
#puts "Role=$oid_roles($role)"
	} elseif {$v == "whois"} {
	    set is $prof(CA_ext.extKeyUsage.$v)
	    if {$is == "Физ. лицо" } {
        	lappend prof(CA_ext.extKeyUsage) "1.2.643.6.3.1.2.2"
    	    } elseif {$is == "Юр. лицо" } {
        	lappend prof(CA_ext.extKeyUsage) "1.2.643.6.3.1.2.1"
    	    } elseif {$is == "ИП" } {
        	lappend prof(CA_ext.extKeyUsage) "1.2.643.6.3.1.2.3"
    	    }
#puts "WHOIS=$prof(CA_ext.extKeyUsage.$v)"
	} elseif {$prof(CA_ext.extKeyUsage.$v)} {
            lappend prof(CA_ext.extKeyUsage) $v
        }
        array unset prof CA_ext.extKeyUsage.$v
    }
    set prof(CA_ext.extKeyUsage) [join $prof(CA_ext.extKeyUsage) ", "]
    
    # Netscape Certificate Type
    set prof(CA_ext.nsCertType) ""
    foreach v $profile_options(CA_ext.nsCertType.options) {
        if {$prof(CA_ext.nsCertType.$v)} {
            lappend prof(CA_ext.nsCertType) $v
        }
        array unset prof CA_ext.nsCertType.$v
    }
    set prof(CA_ext.nsCertType) [join $prof(CA_ext.nsCertType) ", "]

    #Library PKCS#11
    set prof(req.default_libp11) $prof(req.default_libp11.selected)
#puts "LIBP11=$prof(req.default_libp11)"
    array unset prof req.default_libp11.selected

    # Key Type
    set i [lsearch $opts(req.default_key.options) $prof(req.default_key.selected)]
    set prof(req.default_key) [lindex $opts(req.default_key.options) $i]
#puts "XA1 prof(req.default_key)=$prof(req.default_key)"
    array unset prof req.default_key.selected
    
    # Key Param
    set prof(req.default_param) ""
    if { $prof(req.default_key) != "RSA" } {
	set prof(req.default_param) $prof(req.default_bits.selected)
#puts "XA2 prof(req.default_param)=$prof(req.default_param)"
    } else {
    # Key Size
#puts "XA0 prof(req.default_bits.selected)=$prof(req.default_bits.selected)"
#	set i [lsearch -exact $opts(req.default_bits.labels) $prof(req.default_bits.selected)]
#	set prof(req.default_bits) [lindex $opts(req.default_bits.options) $i]
	set prof(req.default_param) $prof(req.default_bits.selected)
    }
    array unset prof req.default_bits.selected
    
    # Validity
        
    # DN Fields
    set prof(req.dn_fields) {}
    set prof(req.dn_fields.required) {}
    foreach {field label} $opts(req.dn_fields) {
#        puts "Calculating: $field - $label"
        if {$prof(req.dn_fields.$field)} {
            lappend prof(req.dn_fields) $field $prof(req.dn_fields.val.$field)
        }
        if {$prof(req.dn_fields.required.$field)} {
            lappend prof(req.dn_fields.required) $field
        }

        array unset prof req.dn_fields.$field
        #puts "array unset prof req.dn_fields.$field"
        #set prof(req.dn_fields.val.$field) "x"
        array unset prof req.dn_fields.val.$field
        #unset prof(req.dn_fields.val.$field)
        #puts "array unset prof req.dn_fields.value.$field"
        array unset prof req.dn_fields.required.$field
        #puts "array unset prof req.dn_fields.required.$field"
    }
    #puts ""
    #puts "*************"
    #puts "resuling prof"
    #puts "*************"
    #parray prof
    #return [array get prof]
}

##################################################
# openssl::profile-unpack
# get input parameters from the profile
# profile : (packed) certificate profile to use
# returns : unpacked profile
#

proc openssl::Profile_Unpack {profile} {
    global defaultpar
    global profile_options
    upvar #0 profile_options opts
    #array set prof $profile
    upvar $profile prof
    debug::msg "openssl::Profile_Unpack"
#puts "openssl::Profile_Unpack"

    # Key Usage
    foreach v $profile_options(CA_ext.keyUsage.options) {
        set prof(CA_ext.keyUsage.$v) 0
    }
    foreach v [split $prof(CA_ext.keyUsage) ,] {
        set v [string trim $v]
        set prof(CA_ext.keyUsage.$v) 1
    }
    
    # Extended Key Usage
    foreach v $profile_options(CA_ext.extKeyUsage.options) {
        set prof(CA_ext.extKeyUsage.$v) 0
    }
    foreach v [split $prof(CA_ext.extKeyUsage) ,] {
        set v [string trim $v]
        set prof(CA_ext.extKeyUsage.$v) 1
    }
    
    # Netscape Certificate Type
    foreach v $profile_options(CA_ext.nsCertType.options) {
        set prof(CA_ext.nsCertType.$v) 0
    }
    foreach v [split $prof(CA_ext.nsCertType) ,] {
        set v [string trim $v]
        set prof(CA_ext.nsCertType.$v) 1
    }

    
    # Key Size
    set i [lsearch -exact $opts(req.default_bits.options) $prof(req.default_bits)]
    set prof(req.default_bits.selected) [lindex $opts(req.default_bits.labels) $i]
    
    # Key Type
#puts "prof(req.default_key=$prof(req.default_key)"
    set prof(req.default_key.selected) ""
#    set prof(req.default_key.selected) $prof(req.default_key)
#puts "openssl::Profile_Unpack prof(req.default_key.selected)=$prof(req.default_key.selected)"
    
    # Key Paeam
#set prof(req.default_param) ""
    set prof(req.default_param.selected) ""
    set prof(req.default_libp11.selected) ""
    if {[info exists prof(req.default_param)]} {
	set defaultpar $prof(req.default_param)
	set defaultkey $prof(req.default_key)
	set prof(req.default_param.selected) $prof(req.default_param)
#puts "prof(req.default_param)=$prof(req.default_param)"
	set prof(req.default_key.selected) $prof(req.default_key)
#puts "openssl::Profile_Unpack prof(req.default_param.selected)=$prof(req.default_param.selected)"

    #Library PKCS#11
	set prof(req.default_libp11.selected) $prof(req.default_libp11)
    } else {
	set defaultpar ""
	set defaultkey ""
	set prof(req.default_param.selected) ""
	set prof(req.default_key.selected) ""
	set prof(req.default_libp11.selected) ""
    }
#puts "LIBP11_UNPACK=$prof(req.default_libp11.selected)"

    # Validity
    
    # DN Fields
    foreach {field label} $opts(req.dn_fields) {
        set prof(req.dn_fields.$field) 0
        set prof(req.dn_fields.required.$field) 0
        set prof(req.dn_fields.val.$field) ""
    }
    foreach {field value} $prof(req.dn_fields) {
        set prof(req.dn_fields.$field) 1
        if {[lsearch -exact $prof(req.dn_fields.required) $field] != -1} {
            set prof(req.dn_fields.required.$field) 1
        }
        set prof(req.dn_fields.val.$field) $value
    }
    
    #return [array get prof]
    
}

##################################################
# openssl::ConfigFile_Create
# Generates config file based on specifed profile
# profilename : name of profile to use
# ###profile : (packed) certificate profile to use
#

proc openssl::ConfigFile_Create {profilename attributes} {
    
    variable cfg
    upvar $attributes attr
        
    #variable config_file_template
    global config_file_template
    #variable profile_template
    #global profile_template

    # this is dirty
    # current profile used in openssl::docommand
    #variable current_profile
    #set current_profile $profile
    
    
    # basic template
    #array set prof $profile_template
    #array set prof [Profile_GetData profile_template]
    array set prof [Template_GetData profile_template]
        
    # overrides
    if {$profilename != ""} {
        array set prof [Profile_GetData $profilename]
    }
    
    # calculate additional values
    set attr(DN) [openssl::ConfigFile_CreateDN attr]
    openssl::ConfigFile_GenerateValues prof
    set cfgfile [subst -nocommands $config_file_template]
#    puts "prof(system.ckzi)= $prof(system.ckzi)"
    if {$prof(system.ckzi) == ""} {
	set cfgfile [string map {"subjectSignTool" "#subjectSignTool"} $cfgfile]
    }
#    puts "prof(system.certckzi)= $prof(system.certckzi)"
    if {$prof(system.certckzi) == ""} {
	set cfgfile [string map {"issuerSignTool" "#issuerSignTool"} $cfgfile]
    }
    if {$prof(system.kc12) == ""} {
	set cfgfile [string map {"certificatePolicies" "#certificatePolicies"} $cfgfile]
    }
    
#    puts "cfgfile = $cfgfile"
    set f [open $cfg(config_fn) "w"]
#    puts "f = $cfg(config_fn)"
    puts $f $cfgfile
    close $f
    
}

proc openssl::ConfigFile_Remove {} {
    
    #variable cfg
    #catch {file delete $cfg(config_fn)}

}


proc openssl::CreateRootCA {attributes} {
    global db
    global defaultkey
    global defaultpar

    debug::msg "openssl::CreateRootCA"
    upvar $attributes attr

    if {$defaultkey == "RSA" } {
    openssl::docommand newroot "" attr
    } else {
    openssl::docommand newrootgost "" attr
    }
    set attr(dir_db) $db(dir)

    set err [openssl::docommand signroot "" attr]
    return $err
}

#################
# check if ca exists - has been creates/setup
# profile : profile to use
# return : true if CA exists - false otherwise
# todo : CA profile should be a parameter
proc openssl::CAExists {} {
    
    debug::msg "openssl::CAExists"
    
    #array set prof $profile
    #array set prof [Profile_GetData profile_template]
    array set prof [Template_GetData profile_template]
    #array set prof [GetProfileData $profilename]
    
    # we currently do this check by checking if the private key exists.    
    return [file exists $prof(CA.private_key)]
}


#
# by default "openssl" is called to run an open ssl command
# calling setopensslexecutable overrides the executable name
# possible to give full path
#
proc openssl::set_executable {executablename} {
    
    variable openssl_executable
    #debug::msg "openssl::set_executable $executablename"
    
    set openssl_executable $executablename
}

proc openssl::docommand {action profilename attributes} {
    global db
    variable config_file
    variable cmd
    variable openssl_executable
    global defaultkey
    global defaultpar
    
    #variable current_profile
    #array set prof $current_profile
    
    # *** should be replace by CA profile
    #array set prof [Profile_GetData profile_template]
    array set prof [Template_GetData profile_template]
    
    # profile date
    if {$profilename != ""} {
        array set prof [Profile_GetData $profilename]
    }
#puts "++++++++++++++++++++++++++++++++++++"
#parray prof
    upvar $attributes attr
#puts "==========================================="
#parray attr
    
    debug::msg "openssl::docommand \"$action\" \"$profilename\" \"$attributes\""

    # if C=given and C=long name, convert
    # get 2 digit code from long name
    # *** TO DO this should be removed, rest of code should make
    # sure we always get 2 digits
    if {[info exists attr(C)] && $attr(C) != "" && [string length $attr(C)]!=2} {
        set attr(C) [openssl::Iso3166Map $attr(C)]
    }
    
    # dump password into environment
    foreach pwname {password keypassword capassword} {
        if {[info exists attr($pwname)]} {
            global env
            set env($pwname) $attr($pwname)
        }
    }
    
    ConfigFile_Create $profilename attr
    
    # openssl executable
    #
    set openssl "$openssl_executable"
    if {$action == "exportpkcs12" && [string first "lirssl" $openssl] != -1 } {
	set command [subst $cmd(exportpkcs12_gost)]
#	puts "PKCS12=$openssl"
#	puts "Command=$command"
    } else {
	set command [subst $cmd($action)]
    }
    #set command [subst $cmdstring]
    Log::LogMessage "\[OPENSSL\] $command" bold
    
    #set err [catch {eval exec $command} result]
    set err [catch {eval tk_exec $command } result]
##    set err [catch {eval exec $command} result]
    
    Log::LogMessage "docommand\[OPENSSL\] error=$err"
    Log::LogMessage "docommand ACTION=$action : \[$result\]"

    # check for common error conditions
    set errmsg [CheckCommonErrors $result]
    if {$errmsg != ""} {
        tk_messageBox -icon error -type ok -title Error -message "$errmsg"  -parent .cm
    } else {
    if {$err == 1} {
        tk_messageBox -icon error -type ok -title Error -message "Не смог выполнить $action"  -parent .cm
    } elseif {$result != 0 && $result != ""} {
	switch $action {
	    gencrl {
		insertCRL $result
	    }
	    newreqdb {
		importRequest $result ""
	    }
	    signreq {
		insertCert $result 1
	    }
	    signroot {
		insertCertRoot $result
	    }
	    newroot -
	    newrootgost {
		insertKeyRoot $result
	    }
	}
    } else {
	switch $action {
	    newreqdb {
    		tk_messageBox -icon error -type ok -title "Создания запроса" -message "Не смог создать запрос. Проверьте поля DN"  -parent .cm
    		    set err 1 
#    		    return -code return
	    }
	    signroot {
    		tk_messageBox -icon error -type ok -title "Создание корневого сертификата" -message "Не смог создать корневой сертификат сертификат. Проверьте поля DN,\nа также системные настройки"  -parent .cm
    		    set err 1 
	    }
	    signreq {
    		tk_messageBox -icon error -type ok -title "Создание сертификата" -message "Не смог создать сертификат. Проверьте поля DN в запросе,\nа также системные настройки"  -parent .cm
    		    set err 1 
	    }
	}
    }
    }
    
    # erase password from environment
    foreach pwname {password keypassword capassword} {
        if {[info exists attr($pwname)]} {
            global env
            set env($pwname) ""
        }
    }
    
    # help avoid bugs in openssl
    if {[file exists "$prof(CA.database).new"]} {
        file rename -force "$prof(CA.database).new" "$prof(CA.database)"
    }

    ConfigFile_Remove
    return $err
}


proc openssl::GetCertificateIndex {} {
    
    global profile_template
        
    #array set prof $profile
    array set prof $profile_template
    set f [open $prof(CA.database) r]
#puts "openssl::GetCertificateIndex=$prof(CA.database)"
    set l {}
    
    while {[gets $f line] != -1} {
        lappend l [split $line \t]
    }
#puts "GetCertificateIndex=$l"
    close $f
    return $l
}

proc openssl::GetCertificateDB {} {
    global certdb
    global db
    global profile_template
#      certdb eval {create table certDB(  ckaID text primary key ,  
#      nick text,  sernum text,  certPEM text, subject text, 
#      notAfter text,  notBefore text, dateRevoke text,  state text
#      )}
    set l {}
    certdb eval {select * from certDB} vals {
	set o {}
#	parray vals
	lappend o $vals(state)	    
	lappend o $vals(notAfter)	    
	lappend o $vals(dateRevoke)	    
	lappend o $vals(sernum)	    
	lappend o "unknown"	    
	lappend o $vals(subject)	    
	lappend o $vals(ckaID)
	lappend l $o

    }
#puts "INDEX_DB=$l"
    return $l
}

proc openssl::GetCRLDB { } {
#certdb eval {create table crlDB(ID integer primary key autoincrement, signtype text, issuer text, publishdate text, nextdate text, crlpem text)}
#	certdb eval {insert into crlDB values (NULL, $b(signtype), $b(issue), $b(publishDate), $b(nextDate), $crl)}

    global certdb
    global db
    global profile_template
    set l {}
    certdb eval {select * from crlDB} vals {
	set o {}
#	parray vals
	    lappend o $vals(ID)	    
#	    lappend o $vals(signtype)	    
	    lappend o [string map {" " "."} $vals(signtype)]
	    lappend o $vals(issuer)	    
	    lappend o $vals(publishdate)	    
	    lappend o $vals(nextdate)	    
	lappend l $o
    }
#puts "GetCRLDB=$l"
    return $l
}

proc openssl::GetRequestDB { } {
    global certdb
    global db
    global profile_template
    set l {}
    certdb eval {select * from reqDB} vals {
	set o {}
#	parray vals
	    lappend o $vals(nick)	    
	    lappend o $vals(status)	    
	    lappend o $vals(type)	    
	    lappend o $vals(datereq)	    
	    lappend o $vals(sernum)	    
	    lappend o $vals(subject)	    
	    lappend o $vals(ckaID)
	lappend l $o
    }
#puts "INDEX_DB=$l"
    return $l
}

proc openssl::GetRequestArDB { } {
    global certdb
    global db
    global profile_template
    set l {}
    certdb eval {select * from reqDBAr} vals {
	set o {}
#	parray vals
	    lappend o $vals(nick)	    
	    lappend o $vals(status)	    
	    lappend o $vals(type)	    
	    lappend o $vals(datereq)	    
	    lappend o $vals(sernum)	    
	    lappend o $vals(subject)	    
	    lappend o $vals(ckaID)
	lappend l $o
    }
#puts "INDEX_DB=$l"
    return $l
}

# openssl::GetCertificateStatus sn
# checks revocation status for certificate #sn
# returns :
#   "" : unknown
#   "V" : valid
#   "R" : revoked
#
proc openssl::GetCertificateStatus {sn} {
    
    global profile_template
    
    #array set prof $profile
    array set prof $profile_template
    set f [open $prof(CA.database) r]
    
    set status ""
    
    while {[gets $f line] != -1} {
        ParseCertificateIndexLine [split $line \t] crtinfo
        # serial nr
        if {$crtinfo(serial) == $sn} {
            # status ?
            set status $crtinfo(status)
            break
        }
        # normally s/n are ordered - so stop searching
        #if {$crtinfo(serial) > $sn} {
        #    break
        #}
    }
    
    close $f
    return $status
}

# parses line from certificate index
# returns name/value pairs
# status serial date revokedate dn cn email
#
proc openssl::ParseCertificateIndexLine {v {varname {}} } {
    
    if {$varname != ""} {
        upvar $varname crtinfo
    }
    
    #puts "line=$v"
    
    # valid or revoked
    set crtinfo(status) [lindex $v 0]
    
    # s/n
    set crtinfo(serial) [lindex $v 3]
    #puts "serial=$crtinfo(serial)"
    #set validity [lindex $v 1]
    # date
    set t [lindex $v 1]
    #puts "t=$t"
    set crtinfo(date) [clock format [clock scan "[string range $t 0 1]-[string range $t 2 3]-[string range $t 4 5] [string range $t 6 7]:[string range $t 8 9]"] -format "%d/%m/%Y %H:%M"]
    
    # date revoked
    set t [lindex $v 2]
    #puts "t=$t"
    if {$t != ""} {
        set crtinfo(revokedate) [clock format [clock scan "[string range $t 0 1]-[string range $t 2 3]-[string range $t 4 5] [string range $t 6 7]:[string range $t 8 9]"] -format "%d/%m/%Y %H:%M"]
    } else  {
        set crtinfo(revokedate) ""
    }
    
    # distinguised name
    set crtinfo(dn) [lindex $v 5]
    # common name -> find out from dn
    set v [lrange [split $crtinfo(dn) /=] 1 end]
    foreach {label cn} $v { if {$label == "CN"} break}
    # cn contains now common name
    set crtinfo(cn) $cn
    
    # email -> retrieve from dn
    foreach {label email} $v { if {$label == "Email"} break}
    # email contains now email
    set crtinfo(email) $email

    # return name/value pairs if no upvar
    if {$varname == ""} {
        return [array get crtinfo]
    }
    
}



#proc openssl::Certificate_ParseDN
#
# Arguments :
#  dn distinguised name (canonical form : C=BE,O=some org,)
#  varname (opt) when specified, wil contain DN on return
#
# Returns:
#  DN in list of name value pairs
#
proc openssl::Certificate_ParseDN {dn {varname {} } } {
    
    debug::msg "openssl::Certificate_ParseDN \"$dn\"" 2
    
    set result {}
    
    foreach sub [split $dn / ] {
        foreach s [split $sub , ] {

        set v [split $s =]; set v0 [string trim [lindex $v 0]]; set v1 [string trim [lindex $v 1]]
        lappend result $v0 $v1
        }
    }

    if {$varname != {} } {
        upvar $varname p
        array set p $result
    }
    
    return $result
}

# openssl::Certificate_GetFilenameForSerial
#
# Arguments:
#    serial    serial number of certificate
# Returns:
#    filename    filename of certficate in database
# remark :
#     no check is done whther exists. this shoudl e added and an error raised.
#
proc openssl::Certificate_GetFilenameForSerial_ORIG {serial} {

    global profile_template

    array set prof $profile_template
    return [file join $prof(CA.new_certs_dir) $serial.pem]

}

proc openssl::Object_GetPEMforCKAID {ckaid type} {
    global db
    global certdb
    global profile_template
    set ss ""
#puts "Object_GetPEMforCKAID TYPE=$type"

    if {$ckaid == "ca" } {
	set type "ca"
    }
    switch -- $type {
	"ca" {
		set ss [certdb eval {select mainDB.certCA from mainDB}]
	}
	"cert" {
		set ss [certdb eval {select certDB.certPEM from certDB where certDB.ckaID=$ckaid}]
	    }
	"req" {
#puts "Object_GetPEMforCKAID=$ckaid"
		set err [catch {certdb eval {select reqDB.reqpem from reqDB where reqDB.ckaID=$ckaid}} ss]
		if {$ss == ""} {
		    set err [catch {certdb eval {select reqDBAr.reqpem from reqDBAr where reqDBAr.ckaID=$ckaid}} ss]
		}	
		if {$ss == ""} {
    		    tk_messageBox -icon error -type ok -title "Просмотр запроса" -message "Не могу найти запрос"  -parent .cm
		}
	    }
	"crl" {
		set ss [certdb eval {select crlDB.crlPEM from crlDB where crlDB.ID=$ckaid}]
	    }
	default {
    		    tk_messageBox -icon error -type ok -title "Выборка PEM" -message "Неизвестный объект ($type)"  -parent .cm
	
	}    
    }
#puts "SS=\"$ss\""
    set ss [string trimleft $ss \{]
    return [string trimright $ss \}]
}

# openssl::Certificate_GuessFormat filename
# based on filename's extension
# guesses format of certificate or request
# returns PEM or DER
#
proc openssl::Certificate_GuessFormat {filename} {

    # default : PEM
    # for unknown file extensions.
    variable certificateformatguess_default
    variable certificateformatguess

    set format $certificateformatguess_default

    set extension [file extension $filename]
    if {[info exists certificateformatguess($extension)]} {
        set format $certificateformatguess($extension)
    }

    return $format
}

######################################################################
# openssl::Certificate_GetInfo args
# arguments:
#    args
#        -get
#             text subject details extensions
#        -serial / -filename
#     -get text : return certifcate as text
#     -get subject : return subject
#     -get details : return details (s/n, issuer, subject, ...)
#     -get extensions : return x509 certificate extensions
#     -serial sn : find cert by serail nr
#     -filename fn : find cert by file name
# returns:
#    certificate information
#    as key/value list (or text format for option -get text)
#

proc openssl::Certificate_GetInfo {args} {
    global db
    global typesys
    variable openssl_executable
    debug::msg "openssl::Certificate_GetInfo \"$args\"" 2
    set options {
        {get.arg {details} }
        {serial.arg {} {} }
        {filename.arg {} {} }
    }
    set typecert 0
    # local command definitions
    #
    array set opts [cmdline::getoptions args $options]
#puts "opts(serial)=$opts(serial)"
#puts "opts(filename)=$opts(filename)"
    # if we have a serial : convert to filename
    if {$opts(serial)!=""} {
	set typecert 0
        set opts(filename) [Object_GetPEMforCKAID $opts(serial) "cert"]
        #puts "-serial $opts(serial) -> filename=$opts(filename)"
    } elseif {$opts(filename)==""} {
    # if no filename -> error
        error "please specify a filename (or serialnr)"
    } else {
	set typecert 1
    }

    if { [string range "$opts(filename)" 0 9 ] != "-----BEGIN" } {
        set cmd(crt_gettext) {"$openssl" x509 -text -inform $opts(inform) -nameopt utf8 -in "$opts(filename)"}
        set cmd(crt_getdetails) {"$openssl" x509 -noout -serial -issuer -subject -startdate -enddate -fingerprint -nameopt utf8 -inform $opts(inform) -in "$opts(filename)"}
	set cmd(crt_getsubject) {"$openssl" x509 -noout -subject -nameopt utf8 -inform $opts(inform) -in "$opts(filename)"}
	set opts(inform) [Certificate_GuessFormat $opts(filename)]
    } else {
	set cmd(crt_gettext) {echo "$opts(filename)" | "$openssl" x509 -text -nameopt utf8 -inform PEM}
	set cmd(crt_getdetails) {echo "$opts(filename)" | "$openssl" x509 -noout -serial -issuer -subject -startdate -enddate -fingerprint -nameopt utf8 -inform PEM}
	set cmd(crt_getsubject) {echo "$opts(filename)" | "$openssl" x509 -noout -subject -nameopt utf8 -inform PEM}
	set opts(inform) PEM
    }

    # openssl executable
    #
    set openssl "$openssl_executable"
    set result {}
#    array set opts [cmdline::getoptions args $options]
        
    switch $opts(get) {
        details {
            # get cert details from cert
            if {$typecert == 0}  {
		array set b [parse_cert_gost $opts(filename)]
#		array set b [::pki::x509::parse_cert $opts(filename)]
#parray b
		set notBef [clock format $b(notBefore) -gmt 1]
		set notAft [clock format $b(notAfter)  -gmt 1]
		set dd "serial $b(serial_number) issuer {$b(issuer)} subject {$b(subject)} notBefore {$notBef} notAfter {$notAft} {SHA1 Fingerprint} $b(fingerprint)"
#puts "DD=$dd"
		return $dd
	    }
            # get cert details from cert
            set command [subst $cmd(crt_getdetails)]
            Log::LogMessage "\[OPENSSL\] $command" bold
            set txt [eval tk_exec $command]
            foreach line [split $txt \n] {
                # parse line
                set pos [string first = $line]
                set field [string range $line 0 [expr $pos - 1 ]]
                set value [string trim [string range $line [expr $pos + 1 ] end]]
                lappend result $field $value
            }
        }
        extensions {
            # get x509 v3 cert extensions
            
            # get text form of certificate
            set command [subst $cmd(crt_gettext)]
            Log::LogMessage "\[OPENSSL\] $command" bold
            set text [eval tk_exec $command]
            # now parse text
            # search for start of certificate extensions
            foreach line [split $text \n] {
                
            }
            if {[regexp {.*X509v3 extensions:} $text]} {
                regsub {.*        X509v3 extensions:\n} $text {} text
                regsub {\n    Signature Algorithm:.*} $text {} text
                #set text [string trim $text]
            } else {
                set text ""
            }

            set currentfield {}
            set currentvalue {}
            set extfields {}
            # now return values
            foreach line [split $text \n] {
                # if lead 8 spaces : start new header
                # if we have previous field : store it
                #puts "scanning: $line"
                set re [regexp {^([ ]*).*} $line v spaces]
                #puts "re: $re, v=$v, spaces=\"$spaces\""
                
                if {[string length $spaces] == 12} {
                    #puts "8 spaces in \"$line\""
                    if {$currentfield != "" && $currentvalue != ""} {
                        lappend extfields $currentfield [join $currentvalue \n]
                    }
                    regexp {^([ ]*)([^:]*):.*$} $line v spaces fieldname
                    set currentfield $fieldname
                    set currentvalue {}
                }
                # if lead 12 spaces : another value
                if {[string length $spaces] >= 16 } {
                    #puts "12 spaces in \"$line\""
                    #regexp {^([ ]*)(.*)$} $line v spaces content
                    set content [string range $line 16 end]
                    lappend currentvalue $content
                    #puts "found content=$content"
                }
                
            }
            if {$currentfield != "" && $currentvalue != ""} {
                lappend extfields $currentfield [join $currentvalue \n]
            }
            set result $extfields
            
        }
        publickey {
            # get x509 v3 cert public key
            
            # get text form of certificate
            set command [subst $cmd(crt_gettext)]
#            Log::LogMessage "\[OPENSSL\] $command" bold
            set text [eval tk_exec $command]
            # now parse text
            # search for start of certificate extensions
            foreach line [split $text \n] {
                
            }
#For RSA
            if {[regexp {.*Public-Key:} $text]} {
                regsub {.*            Public-Key:} $text {} text
                regsub {\n        X509v3 extensions:.*} $text {} text
		set text "Public-Key: $text"
                set text [string map {"                " ""} $text]
# for GOST
            } elseif {[regexp {.*Key algorithm: } $text]} {
                regsub {.*        Key algorithm: } $text {} text
                regsub {\n        X509v3 extensions:.*} $text {} text
		set text [string trimleft $text "\n"]
		set text "Key algorithm:\n$text"
                set text [string map {"                " ""} $text]
            } else {
                set text ""
            }
            set result [list {Public Key} $text]
        }
        subject {
            # get subjec value out cert
            set command [subst $cmd(crt_getsubject)]
            Log::LogMessage "\[OPENSSL\] $command" bold
            set txt [eval tk_exec $command]
#            regsub {^subject= } $txt {} txt
            regsub ^subject= $txt "" txt
            
            # attributes : all subject components
            set attributes {}

            foreach attribute  [split $txt ,/] {
#        	foreach attribute  [split $txt /] {}
#        	    if {$attribute == ""} {continue}
#            	    lappend attributes [lindex [split $attribute =] 0] [lindex [split $attribute =] 1]
            	    lappend attributes [string trim [lindex [split $attribute =] 0]] [string trim [lindex [split $attribute =] 1]]
#                {}
            }
            set result $attributes
#puts "SUBJECT from CERT=$result"
	}
        text {
            set command [subst $cmd(crt_gettext)]
            Log::LogMessage "\[OPENSSL\] $command" bold
            set text [eval tk_exec $command]
            set result $text
        }
    }
    return $result
}
######################################################################
# openssl::Request_GetInfo args
# arguments:
#    args
#        -get
#             text subject details extensions
#        -serial / -filename
#     -get text : return certifcate as text
#     -get subject : return subject
#     -get details : return details (s/n, issuer, subject, ...)
#     -get extensions : return x509 certificate extensions
#     -serial sn : find cert by serail nr
#     -filename fn : find cert by file name
# returns:
#    certificate information
#    as key/value list (or text format for option -get text)
#

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

proc openssl::Request_GetInfo {args} {
    variable openssl_executable
    global typesys
    
    debug::msg "openssl::Request_GetInfo \"$args\"" 2
    set options {
        {get.arg {details} }
        {serial.arg {} {} }
        {filename.arg {} {} }
    }

    # local command definitions
    #
    array set opts [cmdline::getoptions args $options]

#puts "Request_GetInfo=$opts(serial)"
    # if we have a serial : convert to filename
    if {$opts(serial)!=""} {
        set opts(filename) [Object_GetPEMforCKAID $opts(serial) "req"]
        #puts "-serial $opts(serial) -> filename=$opts(filename)"
#puts "Request_GetInfo=$opts(filename)"
    }
    # if no filename -> error
    if {$opts(filename)==""} {
        error "please specify a filename (or serialnr)"
    }

    if { [string range "$opts(filename)" 0 9 ] != "-----BEGIN" } {
	set cmd(req_gettext) {"$openssl" req -noout -text -nameopt utf8 -inform $opts(inform) -in "$opts(filename)"}

	set cmd(req_getdetails) {"$openssl" req -noout -subject -nameopt utf8  -inform $opts(inform) -in "$opts(filename)"}

	set cmd(req_getsubject) $cmd(req_getdetails)
	set opts(inform) [Certificate_GuessFormat $opts(filename)]
    } else {
	set cmd(req_gettext) {echo "$opts(filename)" | "$openssl" req -noout -text -nameopt utf8 -inform $opts(inform)}
	set cmd(req_getdetails) {echo "$opts(filename)" | "$openssl" req -noout -subject -nameopt utf8  -inform $opts(inform)}

	set cmd(req_getsubject) $cmd(req_getdetails)
	set opts(inform) PEM
    }
    # openssl executable
    #
    set openssl "$openssl_executable"
    set result {}
        
#puts "Request_GetInfo=$opts(get)"
    switch $opts(get) {
        details {
            # get cert details from cert
            set command [subst $cmd(req_getdetails)]
            Log::LogMessage "\[OPENSSL\] $command" bold
#            set txt [eval tk_exec $command]
            set err [catch {eval tk_exec $command} txt]
#            set err [catch {eval exec $command} txt]
    # check for common error conditions
	    set errmsg [CheckCommonErrors $txt]
	    if {$errmsg != ""} {
    		tk_messageBox -icon error -type ok -title "Импорт запроса " -message "$errmsg"  -parent .cm
		return ""
	    }

            foreach line [split $txt \n] {
                # parse line
                set pos [string first = $line]
                set field [string range $line 0 [expr $pos - 1 ]]
                set value [string trim [string range $line [expr $pos + 1 ] end]]
                lappend result $field $value
            }
        }
        extensions {
            # get x509 v3 cert extensions
            
            # get text form of certificate
            set command [subst $cmd(req_gettext)]
            Log::LogMessage "\[OPENSSL\] $command" bold
            set text [eval tk_exec $command]
            # now parse text
            # search for start of certificate extensions
            foreach line [split $text \n] {
                
            }

            if {[regexp {.*Attributes:} $text]} {
                regsub {.*       Attributes:\n} $text {} text
                regsub {.*Signature Algorithm:\n} $text {} text
                #set text [string trim $text]
            } else {
                set text ""
            }
            set currentfield {}
            set currentvalue {}
            set extfields {}
            # now return values
            foreach line [split $text \n] {
                # if lead 8 spaces : start new header
                # if we have previous field : store it
                #puts "scanning: $line"
                set re [regexp {^([ ]*).*} $line v spaces]
                #puts "re: $re, v=$v, spaces=\"$spaces\""
                
                if {[string length $spaces] == 12} {
                    #puts "8 spaces in \"$line\""
                    if {$currentfield != "" && $currentvalue != ""} {
                        lappend extfields $currentfield [join $currentvalue \n]
                    }
                    regexp {^([ ]*)([^:]*):.*$} $line v spaces fieldname
                    set currentfield $fieldname
                    set currentvalue {}
                }
                # if lead 12 spaces : another value
                if {[string length $spaces] >= 16 } {
                    #puts "12 spaces in \"$line\""
                    #regexp {^([ ]*)(.*)$} $line v spaces content
                    set content [string range $line 16 end]
                    lappend currentvalue $content
                    #puts "found content=$content"
                }
                
            }
            if {$currentfield != "" && $currentvalue != ""} {
                lappend extfields $currentfield [join $currentvalue \n]
            }
            set result $extfields
            
        }
        publickey {
            # get x509 v3 cert public key
            
            # get text form of certificate
            set command [subst $cmd(req_gettext)]
            Log::LogMessage "\[OPENSSL\] $command" bold
            set text [eval tk_exec $command]
            # now parse text
            # search for start of certificate extensions
            foreach line [split $text \n] {
                
            }

#For RSA
            if {[regexp {.*Public-Key:} $text]} {

                regsub {.*            Public-Key:} $text {} text
#                regsub {.*                Modulus \(1024 bit\):\n} $text {} text

                regsub {\n        Attributes:.*} $text {} text
		set text "Public-Key: $text"
                set text [string map {"                " ""} $text]
# for GOST
            } elseif {[regexp {.*Key algorithm: } $text]} {
                regsub {.*        Key algorithm: } $text {} text
                regsub {\n        Attributes:.*} $text {} text
		set text [string trimleft $text "\n"]
		set text "Key algorithm:\n$text"
                set text [string map {"                " ""} $text]
            } else {
                set text ""
            }
            set result [list {Public Key} $text]
        }
        subject {
            # get subjec value out cert
            set command [subst $cmd(req_getsubject)]
            Log::LogMessage "\[OPENSSL\] $command" bold
            set err [catch {eval tk_exec $command} txt]
    # check for common error conditions
	    set errmsg [CheckCommonErrors $txt]
	    if {$errmsg != ""} {
    		tk_messageBox -icon error -type ok -title "Импорт запроса " -message "$errmsg"  -parent .cm
		return ""
	    }

#            regsub {^subject= } $txt {} txt
            regsub ^subject= $txt "" txt
######################
            set attributes {}
	    set oidsub ""
#puts "Request_GetInfo=$txt"
	    set lsub [split $txt ","]
	    set txt [del_comma $lsub]
#puts "Request_GetInfo new=$txt"

	    foreach a $txt {
#puts "Request_GetInfo a=$a"
		set ind [string first "=" $a]
		if {$ind == -1 } { 
		    set oidval "$oidval $a"
		    continue 
		}
		if {$oidsub != ""} {
		    set oidval [string trimright $oidval ","]
#		    puts "DEL_COMMA: $oidsub = \"$oidval\""
		    lappend attributes $oidsub
		    lappend attributes $oidval
		}
		set oidsub [string trim [string range $a 0 $ind-1]]
#	puts $nameoid
		set oidval "[string trim [string range $a $ind+1 end]]"
	    }
	    lappend attributes $oidsub
	    lappend attributes $oidval
###############
            set result $attributes
#puts "REQUEST SUBJECT=$result"
	}
        text {
            set command [subst $cmd(req_gettext)]
            Log::LogMessage "\[OPENSSL\] $command" bold
            set text [eval tk_exec $command]
            set result $text
        }
    }
    return $result
}

proc openssl::CRL_GetInfo {args} {
    global db
    global typesys
    variable openssl_executable
    debug::msg "openssl::CRL_GetInfo \"$args\"" 2
    set options {
        {get.arg {details} }
        {serial.arg {} {} }
        {filename.arg {} {} }
    }

    # local command definitions
    #
    array set opts [cmdline::getoptions args $options]
    # if we have a serial : convert to filename
    if {$opts(serial)!=""} {
        set opts(filename) [Object_GetPEMforCKAID $opts(serial) "crl"]
        #puts "-serial $opts(serial) -> filename=$opts(filename)"
    } elseif {$opts(filename)==""} {
        error "please specify a filename (or serialnr or ckaid)"
    }
    if { [string range "$opts(filename)" 0 9 ] != "-----BEGIN" } {
        set cmd(crl_gettext) {"$openssl" crl -text -inform $opts(inform) -in "$opts(filename)"}
        set cmd(crl_getdetails) {"$openssl" crl  -noout -issuer -lastupdate -nextupdate -crlnumber -fingerprint  -inform $opts(inform) -in "$opts(filename)"}
	set cmd(crl_getissuer) {"$openssl" crl -noout -issuer -inform $opts(inform) -in "$opts(filename)"}
	set opts(inform) [Certificate_GuessFormat $opts(filename)]
    } else {
	set cmd(crl_gettext) {echo "$opts(filename)" | "$openssl" crl -text -inform PEM}
	set cmd(crl_getdetails) {echo "$opts(filename)" | "$openssl" crl -noout -issuer -lastupdate -nextupdate -crlnumber -fingerprint -inform PEM}
	set cmd(crl_getissuer) {echo "$opts(filename)" | "$openssl" crl -noout -issuer -inform PEM}

	set opts(inform) PEM
    }

    # openssl executable
    #
    set openssl "$openssl_executable"
    set result {}
#    array set opts [cmdline::getoptions args $options]
        
    switch $opts(get) {
        details {
            # get cert details from cert
            set command [subst $cmd(crl_getdetails)]
            Log::LogMessage "\[OPENSSL\] $command" bold
            set txt [eval tk_exec $command]
            foreach line [split $txt \n] {
                # parse line
                set pos [string first = $line]
                set field [string range $line 0 [expr $pos - 1 ]]
                set value [string trim [string range $line [expr $pos + 1 ] end]]
                lappend result $field $value
            }
        }
        issuer {
            # get subjec value out cert
            set command [subst $cmd(crl_getissuer)]
            Log::LogMessage "\[OPENSSL\] $command" bold
            set txt [eval tk_exec $command]
            regsub {^issuer= } $txt {} txt
            
            # attributes : all subject components
            set attributes {}

            foreach attribute  [split $txt ,] {
        	foreach attribute  [split $txt /] {
        	    if {$attribute == ""} {continue}
            	    lappend attributes [lindex [split $attribute =] 0] [lindex [split $attribute =] 1]
                }
            }
            set result $attributes
	}
        text {
            set command [subst $cmd(crl_gettext)]
            Log::LogMessage "\[OPENSSL\] $command" bold
            set text [eval tk_exec $command]
            set result $text
        }
    }
    return $result
}


set Cert_UsageMessage {
    serverAuth "Ensures the identity of a remote computer"
    clientAuth "Proves your identity to a remote computer"
    codeSigning "Ensures software came from software publisher\nProtects software from alteration after publication"
    emailProtection "Protects e-mail messages"
    ipsecEndSystem ""
    ipsecTunnel ""
    ipsecUser ""
    timeStamping "Allows data to be signed with the current time"
    OCSPSigning "Allows you to digitally sign a certificate trust list"
    msSGC "Microsoft Server Gate Crypto"
    nsSGC "Netscape Server Gate Crypto"
}

######################################################################
# openssl::Certificate_IsValid args
# arguments:
#    args
#        -check
#             all date chain use
#        -serial / -filename
#     -check all : check all validity options
#     -serial sn : find cert by serail nr
#     -filename fn : find cert by file name
# returns:
#    certificate validity
# validation :
# (1) Validity Period
# (2) Certificate Chain
# (3) Root Certificate Valid (all certs in chain)
# (4) Is certificate revoked ?
# (5) Is certificate valid for the specified use ?
#

proc openssl::Certificate_IsValid {args} {
    global db
    debug::msg "openssl::Certificate_IsValid \"$args\"" 2
    set result {}

    set options {
        {check.arg {details} }
        {serial.arg {} {} }
        {filename.arg {} {} }
    }
    array set opts [cmdline::getoptions args $options]
    #puts "opts ="
    #parray opts
    
    # if we have a serial : convert to filename
    if {$opts(serial)!=""} {
        set opts(filename) [Object_GetPEMforCKAID $opts(serial) "cert"]
        #puts "-serial $opts(serial) -> filename=$opts(filename)"
    }
    # if no filename -> error
    if {$opts(filename)==""} {
        error "please specify a filename (or serialnr)"
    }

    # get some certificate info
    #array set crtdetails [eval Certificate_GetInfo -get details -filename $opts(filename)]
    array set crtdetails [Certificate_GetInfo -get details -filename $opts(filename)]
    
    
    # check validity date
    
    # we need
    # crtdetails(notBefore)
    # crtdetails(notAfter)
    #parray crtdetails
    set startdate [clock scan $crtdetails(notBefore)]
    set enddate [clock scan $crtdetails(notAfter)]
    
    # today
    set now [clock seconds]
    
    # <now> should be between start/end dates
    #set isvalid [expr ($startdate < $now) && ($now < $enddate)]
    set isvalid 1
    set reason "Certificate is valid."
    #puts "validity: startdate=$startdate, enddate=$enddate, now=$now"
    if {$startdate > $now} {
        set isvalid 0
        set reason "Certificate is not yet valid."
    }
    if {$now > $enddate} {
        set isvalid 0
        set reason "Certificate has expired."
    }
    
    # check revocation
#Вставить проверку для своих по статусу в БД, а для чужих по СОС
#    set crtstatus [openssl::GetCertificateStatus $crtdetails(serial)]

    set isvalid 0
    set reason "Certificate revocation state can not be verified."
    
    # check certificate chain
    
    # check usage
    
    set result [list $isvalid $reason]
    
    return $result
    
}
proc openssl::Certificate_IsValidDB {args} {
    global db
    global certdb
    debug::msg "openssl::Certificate_IsValidDB \"$args\"" 1
    set result {}

    set options {
        {check.arg {details} }
        {serial.arg {} {} }
        {filename.arg {} {} }
    }
    array set opts [cmdline::getoptions args $options]
    #puts "opts ="
    #parray opts
    
    # if we have a serial : convert to filename
    if {$opts(serial)!=""} {
        set opts(filename) [Object_GetPEMforCKAID $opts(serial) "cert"]
        #puts "-serial $opts(serial) -> filename=$opts(filename)"
    }
    # if no filename -> error
    if {$opts(filename)==""} {
        error "please specify a filename (or serialnr)"
    }

    # get some certificate info
    #array set crtdetails [eval Certificate_GetInfo -get details -filename $opts(filename)]
    array set crtdetails [Certificate_GetInfo -get details -filename $opts(filename)]
    
    
    # check validity date
    
    # we need
    # crtdetails(notBefore)
    # crtdetails(notAfter)
    #parray crtdetails
    set startdate [clock scan $crtdetails(notBefore)]
    set enddate [clock scan $crtdetails(notAfter)]
    
    # today
    set now [clock seconds]
    
    # <now> should be between start/end dates
    set isvalid 1
    set reason "Certificate is valid."
    #puts "validity: startdate=$startdate, enddate=$enddate, now=$now"
    if {$startdate > $now} {
        set isvalid 0
        set reason "Срок действмя сертификата еще не наступил."
    }
    if {$now > $enddate} {
        set isvalid 0
        set reason "Сертификат просрочен."
    }
    
    # check revocation
    if {$opts(serial) == "ca"} {
	set crtstatus "V"
    } else {
	set crtstatus [certdb eval {select certDB.state from certDB where certDB.ckaID=$opts(serial)}]
    }
    switch $crtstatus {
        "" {
            set isvalid 0
            set reason "Невозможно проверить отозванность сертификата."
        }
        "R" {
            set isvalid 0
            set reason "Серификат отозван."
        }
        "V" {
        }
    }
    
    # check certificate chain
    
    # check usage
    
    set result [list $isvalid $reason]
    
    return $result
    
}

proc openssl::Profile_Create {profilename {templatename {}} } {
    
    variable profiles
    variable templates
    global profile_template

#    puts "openssl::Profile_Create $profilename $templatename"
    
    if {$templatename == ""} {
        set templatename profile_template
        
    }
    
    set t  $templates($templatename)
    set profiles($profilename) $t
    
}

proc openssl::Profile_GetData {profilename } {
    
    variable profiles
    
    return $profiles($profilename)
    
}

proc openssl::Profile_SetData {profilename data} {
    
    variable profiles
    
    return [set profiles($profilename) $data]
    
}

proc openssl::Profile_Delete {profilename} {
    
    variable profiles
    
    unset profiles($profilename)
    
}

proc openssl::Profile_Save {} {
    global certdb
    global db
    variable profiles
    set db(profilesReq) [array get profiles]
#puts "Profile_Save=$db(profilesReq)"
    certdb eval {begin transaction}
    certdb eval {update mainDB set profilesReq=$db(profilesReq) where dateCreateDB=$db(dateCreateDB)}
    certdb eval {end transaction} 

}

proc openssl::Profile_Load {} {
    global certdb
    global db
    variable profiles
    global profile_template
    set prof [certdb eval {select mainDB.profilesReq from mainDB where mainDB.dateCreateDB=$db(dateCreateDB)}]
#    puts "PROF_LOAD=$prof"
    if {[lindex $prof 0] != "" } {
#    puts "Я ЗДЕСЯ1"
	set prof [string range $prof 1 end-1]
#    puts "PROF_LOAD1=$prof"
        array unset profiles
#catch {	array set profiles $prof}
	array set profiles $prof
    } 
}

##
# openssl::ListProfiles
# returns list of available profiles
# arg : type:
#   profile : return profiles
#   template : return profile templates
#   default : profile
#
proc openssl::Profile_List {} {
    variable profiles
    
    set l [array names profiles]
    
    # should erase template profile
    return $l    
}

proc openssl::Template_Create {templatename} {
    
    variable templates
    global profile_template
    
    set templates($templatename) {}
    
}

proc openssl::Template_GetData {templatename } {
    
    variable templates
    
    return $templates($templatename)
    
}

proc openssl::Template_SetData {templatename data} {
    
    variable templates
    
    return [set templates($templatename) $data]
    
}

proc openssl::Template_List {} {
    variable templates
    
    set l [array names templates]
    
    # should erase template profile
    return $l
}


proc openssl::GetDialogFieldLabel {field} {
    
    variable dialogfieldlabels
    
    if {[info exists dialogfieldlabels($field)]} {
        return $dialogfieldlabels($field)
    } else  {
        return $field
    }
    
}

proc tk_exec_fileevent {id} {
    global tk_exec_data
    global tk_exec_cond
    global tk_exec_pipe
    
    if {[eof $tk_exec_pipe($id)]} {
        fileevent $tk_exec_pipe($id) readable ""
        set tk_exec_cond($id) 1
        return
    }
    append tk_exec_data($id) [read $tk_exec_pipe($id) 1024]
    
}

proc tk_exec {args} {
    global tk_exec_id
    global tk_exec_data
    global tk_exec_cond
    global tk_exec_pipe
    global tcl_platform
    global env
    
    if {![info exists tk_exec_id]} {
        set tk_exec_id 0
    } else {
        incr tk_exec_id
    }
#puts "TK_EXEC=$args"
    set dat ""
    set ii [string first "|" $args]
    if { $ii > 0 } {
	incr ii -3
	set dat [string range $args 6 $ii]
#	puts "TK_EXEC DATA=$dat"
	incr ii 4
	set args [string range $args $ii end]
#	puts "TK_EXEC ARGS=$args"
    }
    
    set keepnewline 0
    
    for {set i 0} {$i < [llength $args]} {incr i} {
        set arg [lindex $args $i]
        switch -glob -- $arg {
            -keepnewline {
                set keepnewline 1
            }
            -- {
                incr i
                break
            }
            -* {
                error "unknown option: $arg"
            }
            #?* {
            #    # the glob should be on *, but the wiki reformats
            #    # that as a bullet
            #    break
            #}
            * {
                break
            }
        }
    }
    if {$i > 0} {
        set args [lrange $args $i end]
    }
    
    #if {$tcl_platform(platform) == "windows" && \
    #            [info exists env(COMSPEC)]} {
    #    set args [linsert $args 0 $env(COMSPEC) "/c"]
    #}
    
    set pipe [open "|$args" r+]
    if {$ii > 0} {
	puts $pipe $dat
	flush $pipe
    }

    set tk_exec_pipe($tk_exec_id) $pipe
    set tk_exec_data($tk_exec_id) ""
    set tk_exec_cond($tk_exec_id) 0
    
    fconfigure $pipe -blocking 0
    fileevent $pipe readable "tk_exec_fileevent $tk_exec_id"
    
    vwait tk_exec_cond($tk_exec_id)
    
    if {$keepnewline} {
        set data $tk_exec_data($tk_exec_id)
    } else {
        set data [string trimright $tk_exec_data($tk_exec_id) \n]
    }
    
    unset tk_exec_pipe($tk_exec_id)
    unset tk_exec_data($tk_exec_id)
    unset tk_exec_cond($tk_exec_id)
    
    if {[catch {close $pipe} err]} {
        puts "pipe error: $err"
        error "pipe error: $err"
    } 
    
    return $data
}


#initialisation
openssl::GetIso3166

# profiles
# template

set openssl::templates(profile_template) $profile_template

# Personal
openssl::Template_Create "Personal"
openssl::Template_SetData "Personal" {
    req.default_key {RSA}
    req.default_param ""
    req.default_libp11        ""
    req.default_bits {1024}
    CA.default_days {366}
    CA_ext.nsCertType {client, email}
    CA_ext.keyUsage {digitalSignature, keyEncipherment, keyAgreement}
    CA_ext.keyUsage.default {digitalSignature, keyEncipherment, keyAgreement}
    CA_ext.extKeyUsage {clientAuth, emailProtection}
    req.dn_fields    {CN "" emailAddress ""}
    req.dn_fields.required    "CN emailAddress"
    CA_ext.nsCaPolicyUrl {}
    CA_ext.nsComment {}
    CA_ext.crlDistributionPoints {}
    CA_ext.authorityInfoAccess {}

    CA_ext.nsRevocationUrl {}
    CA_ext.nsBaseUrl {}
    CA_ext.nsRenewalUrl {}
    CA_ext.basicConstraints {critical, CA:FALSE}
    other.suggestfilename {Email}
    other.subjecttype {Personal}
}

    
# SSL Server
openssl::Template_Create "SSL Server"
openssl::Template_SetData "SSL Server" {
    req.default_key {RSA}
    req.default_param ""
    req.default_libp11        ""
    req.default_bits {1024}
    CA.default_days {366}
    CA_ext.nsCertType server
    CA_ext.keyUsage {digitalSignature, keyEncipherment}
    CA_ext.keyUsage.default {digitalSignature, keyEncipherment}
    CA_ext.extKeyUsage {serverAuth}
    req.dn_fields    {C "" ST "" L "" O "" OU "" CN "" INN "" emailAddress ""}
    req.dn_fields.required    "C O OU CN INN emailAddress"
    CA_ext.nsCaPolicyUrl {}
    CA_ext.nsComment {}
    CA_ext.crlDistributionPoints {}
    CA_ext.authorityInfoAccess {}
    CA_ext.nsRevocationUrl {}
    CA_ext.nsBaseUrl {}
    CA_ext.nsRenewalUrl {}
    CA_ext.basicConstraints {critical, CA:FALSE}
    other.suggestfilename {Common Name}
    other.subjecttype {Server}
}
#    other.suggestefilename {Common Name}

# Sub CA
openssl::Template_Create "Sub CA"
openssl::Template_SetData "Sub CA" {
    req.default_key {RSA}
    req.default_param ""
    req.default_libp11        ""
    req.default_bits {1024}
    CA.default_days {1830}
    CA_ext.nsCertType {sslCA, emailCA, objCA}
    CA_ext.keyUsage {keyCertSign, cRLSign}
    CA_ext.keyUsage.default {keyCertSign, cRLSign}
    CA_ext.extKeyUsage {codeSigning, timeStamping, OCSPSigning}
    req.dn_fields    {C "" O "" OU "" CN ""}
    req.dn_fields.required    "C O CN"
    CA_ext.nsCaPolicyUrl {}
    CA_ext.nsComment {}
    CA_ext.crlDistributionPoints {}
    CA_ext.authorityInfoAccess {}
    CA_ext.nsRevocationUrl {}
    CA_ext.nsBaseUrl {}
    CA_ext.nsRenewalUrl {}
    CA_ext.basicConstraints {critical, CA:TRUE}
    other.suggestfilename {Common Name}
    other.subjecttype {Other}
}



# base profiles
openssl::Profile_Create "Personal" "Personal"
openssl::Profile_Create "SSL Server" "SSL Server"
#В openDB
#openssl::Profile_Load

#
# Create a new notebook widget
#
proc Notebook:create {w args} {
    global Notebook
    set vwidth ""
    set vheight ""
    set vpages {}
    set vpad ""
    set vbg ""
    set vfg ""
    set vdisabledforeground ""
  foreach {tag value} $args {
    switch -- $tag {
      -width {
        set Notebook($w,width) $value
	set vwidth "-width $value"
#puts $vwidth
      }
      -height {
        set Notebook($w,height) $value
	set vheight "-height  $value"
      }
      -pages {
        set Notebook($w,pages) $value
	set vpages $value
      }
      -pad {
        set Notebook($w,pad) $value
	set vpad "-pad $value"
      }
    }
  }
    set com "ttk::notebook $w  $vwidth $vheight -takefocus {} -padding 0 $vpad -pad 2"
#puts "COM=$com"
    eval $com
    $w state {hover}
    set colpag [llength $vpages]
    for {set i 0} { $i < $colpag } {incr i} {
#	frame $w.f$i -background {#e0e0da} -highlightbackground {#eff0f1} -highlightcolor {black} -padx {5}
	frame $w.f$i -background {white}  -padx {0} -relief flat -bd 0 -pady 0
	$w add $w.f$i -padding 0 -sticky nwse -state normal -text [lindex $vpages $i] -image {} -compound none -underline -1 
    }
    pack  $w -fill both -expand 1
}
#
# Return the frame associated with a given page of the notebook.
#
proc Notebook:frame {w name} {
  global Notebook
#puts "PAGES=$Notebook($w,pages)"
#puts "NAME=$name"
  set i [lsearch $Notebook($w,pages) $name]
  if {$i>=0} {
    return $w.f$i
  } else {
    return {}
  }
}


package require Config

package provide OptionsDialog 1.0

namespace eval OptionsDialog {
    variable windowname
    
    variable input ;# contains pending input values
}

proc OptionsDialog::Create {w} {
    global env
    variable input
    
    variable windowname
    set windowname $w
    
    catch "destroy $w"
#puts "НАСТРОЙКИ=$w"
    labelframe  $w -labelanchor n -bd 0 -relief flat -padx 0 -pady 0  -background #e0e0da
    $w configure -text "УЦ ФЗ-63. Настройки" -font {Times 11 bold}

    tk busy hold .cm.mainfr
    menu_disable
    place $w -in .cm.mainfr.ff.notbok -x 1 -y 0  -relwidth 0.998  -relheight 1.0
    raise $w

    frame $w.mainfr -relief groove -background white  -bd 2
    pack $w.mainfr -fill both -pady 2
    set w $w.mainfr

    frame $w.f 
    frame $w.b
    $w configure -pady 8
    set zag {Настройки Удостоверяющего Центра УЦ ФЗ-63}
    ttk::label $w.who -text $zag -justify center -image logobuild_60x40 -compound left -background white -font {Times 11 bold italic}   -borderwidth 4 -relief flat
    pack $w.who  -side top   -anchor n -pady 0 -ipadx 5
    $w.who configure -text $zag 

    pack $w.f -side top -expand 1 -anchor e -fill both -padx 5 -pady 2
    pack $w.b  -side top -expand 1 -anchor e -padx 5 -pady 2
    

    array unset input
    array set input [Config::GetAll]

    frame $w.sep -height 2 -bd 0 -relief flat -background #c0bab4 
    $w configure -relief flat
    #e0e0da
    pack $w.sep -fill x 

    # buttons
    ttk::button $w.b2ok -text "Готово" -width 8 -command "OptionsDialog::ButtonOK" -style MyBorder.TButton
    ttk::button $w.b2cancel -text "Отмена" -width 8 -command "OptionsDialog::ButtonCancel" -style MyBorder.TButton
#    ttk::button $w.b2restore -text "Restore" -width 8 -command "OptionsDialog::ButtonRestore" -style MyBorder.TButton
#    pack $w.b2cancel $w.b2ok $w.b2restore  -side right -padx 5  -pady {2mm 0} -anchor w
    pack $w.b2cancel $w.b2ok  -side right -padx 5  -pady {2mm 0} -anchor w
    
    Notebook:create $w.f.n -pages {"Настройки для Web" "Каталоги" "Типы сертификатов" "Системные"} -width 550 # -height 300
#    Notebook:create $w.f.n -pages {"Export" "Web" "Folders" "Certificate Classes" "System"} -width 500 # -height 300
    set n $w.f.n

    # web options
    set f [Notebook:frame $n "Настройки для Web"]
    $f configure -background white -borderwidth 0 -relief flat

    label $f.l0 -text ""
    set bg_lab [$f.l0 cget -bg]
    option add *Label.background white
    option add *Label.anchor w
     #e0e0da
    option add *Checkbutton.background #e0e0da
    $f.l0 configure -background #e0e0da

    # publish folder input
    label $f.l1 -text "Входящий каталог:"
    cagui::FileEntry $f.e1 \
            -dialogtype directory \
            -variable ::OptionsDialog::input(web.infolder) \
            -title "Укажите входящий каталог" \
            -parent ".cm"

    label $f.l2 -text "Каталог сертификатов:"
    cagui::FileEntry $f.e2 \
            -dialogtype directory \
            -variable ::OptionsDialog::input(web.outfolder) \
            -title "Укажите каталог сертификатов" \
            -parent ".cm"

    label $f.l3 -text "Mail Host:"
    ttk::entry $f.e3  -textvariable ::OptionsDialog::input(web.mailhost)

    label $f.l4 -text "From Address:"
    ttk::entry $f.e4 -textvariable ::OptionsDialog::input(web.mailfrom)

    label $f.l5 -text "Web Server Prefix:"
    ttk::entry $f.e5 -textvariable ::OptionsDialog::input(web.webserver)


    grid $f.l1 -row 1 -column 0 -sticky w -padx {3mm 0} -pady {3mm 1mm}
    grid $f.e1 -row 1 -column 1 -sticky nwse -padx {0 3mm} -pady {3mm 1mm}
    grid $f.l2 -row 2 -column 0 -sticky w -padx {3mm 0} -pady 1mm
    grid $f.e2 -row 2 -column 1 -sticky nwse -padx {0 3mm} -pady 1mm
    grid $f.l3 -row 3 -column 0 -sticky w -padx {3mm 0} -pady 1mm
    grid $f.e3 -row 3 -column 1 -sticky nwse -padx {0 3mm} -pady 1mm
    grid $f.l4 -row 4 -column 0 -sticky w -padx {3mm 0} -pady 1mm
    grid $f.e4 -row 4 -column 1 -sticky nwse -padx {0 3mm} -pady 1mm
    grid $f.l5 -row 5 -column 0 -sticky w -padx {3mm 0} -pady 1mm
    grid $f.e5 -row 5 -column 1 -sticky nwse -padx {0 3mm} -pady 1mm
    grid columnconfigure $f 1 -weight 1

    # publish options
    set f [Notebook:frame $n "Каталоги"]
    $f configure -background #e0e0da
    $f configure -background white -borderwidth 0 -relief flat
    
    set i 1
    set folderlist [Config::Get folder.folderlist]
    
    foreach {label varname} $folderlist {
        label $f.l$i -text "$label"
        cagui::FileEntry $f.e$i \
                -dialogtype directory \
                -variable ::OptionsDialog::input($varname) \
                -title "Выберите $label" \
                -parent ".cm"
        
	if {$i == 1 } {
    	    grid $f.l$i -row $i -column 0 -sticky nw -pady {5mm 1mm} -padx 4 
    	    grid $f.e$i -row $i -column 1 -sticky nwse  -padx 4 -pady {5mm 1mm}
        } else {
    	    grid $f.l$i -row $i -column 0 -sticky nw -pady 1mm -padx 4 
    	    grid $f.e$i -row $i -column 1 -sticky nwse  -padx 4 -pady 1mm
        }
        incr i
    }
    grid columnconfigure $f 1 -weight 1
    
    # Manage Certificate Classes
    set f [Notebook:frame $n "Типы сертификатов"]
    $f configure -background #e0e0da
    
    label $f.l0 -image subjectDN_40x33 -compound left -bg #eff0f1
    grid $f.l0 -row 0 -column 0 -sticky w -padx 8 -pady 8
    
    listbox $f.listbox -yscrollcommand [list $f.vsb set]
#     -font {* 10}
#     -width 30  -height 5 
    
    ttk::scrollbar $f.vsb -orient vertical -command [list $f.listbox yview]
    grid $f.listbox -row 1 -column 1 -rowspan 8 -sticky nwse -pady 4
    grid $f.vsb -row 1 -column 2 -rowspan 8 -sticky nsw -pady 4
    grid columnconfigure $f 1 -weight 1
    
    ttk::button $f.b1 -text "Новый" -command "OptionsDialog::NewProfile $f.listbox"
    ttk::button $f.b2 -text "Редактировать" -command "OptionsDialog::EditProfile $f.listbox"
    ttk::button $f.b3 -text "Уничтожить" -command "OptionsDialog::DeleteProfile $f.listbox"
    grid $f.b1 -row 1 -column 3 -sticky ew -padx 5mm -pady 4
    grid $f.b2 -row 2 -column 3 -sticky ew -padx 5mm -pady 4
    grid $f.b3 -row 3 -column 3 -sticky ew -padx 5mm -pady 4
    
    # fill listbox
    # insert existing profiles
set cc 0
    foreach v [openssl::Profile_List] {
        $f.listbox insert end $v
incr cc
    }
    $f.listbox selection set 0
    # button commands
set hl [winfo reqheight $f.listbox]
#Высота строки
set fl [$f.listbox configure -font]
#set yfont [font metrics TkDefaultFont -linespace]
set yfont [font metrics TkDefaultFont -ascent]
#Высота виджеты = высота строки * кол-во строк (\n)
set y1 [expr $yfont * ($cc - 0) + 1]
#tk_messageBox -title "SCROLLBAR"   -icon info -message "listprofile=$y1\nlistbox=$hl\nfont=$yfont"
if {$y1 < $hl} {
    grid forget $f.vsb  
}

    
    # System options
    set f [Notebook:frame $n "Системные"]
    $f configure -background white -borderwidth 0 -relief flat
    
    label $f.l0 -text "" -font {Times 11 bold italic}
    set fnt(std) [$f.l0 cget -font]
#puts "FONT=[$f.l0 cget -font]"
    set fnt(bold) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] bold]

    label $f.l1 -text "Системные средства" -font $fnt(bold) -bg #eff0f1

    grid $f.l1 -row 1 -column 1 -columnspan 2 -sticky w -pady 0
        
    set i 2
    set list [Config::Get system.tools]
    
    foreach {label varname} $list {
        
        label $f.l$i -text "$label"
	if { $i > 2 } {
	    ttk::entry $f.e$i -width 40 -textvariable ::OptionsDialog::input($varname)
        } else {
    	    cagui::FileEntry $f.e$i \
                -dialogtype open \
                -initialdir "" \
                -variable ::OptionsDialog::input($varname) \
                -title "Выберите $label" \
                -parent ".cm"

        }
        grid $f.l$i -row $i -column 0 -sticky nw -pady 1mm  -padx 4 
        grid $f.e$i -row $i -column 1 -sticky nwse -padx 4 -pady 1mm
        incr i
        
    }
    grid columnconfigure $f 1 -weight 1
    
    label $f.l$i -text "Другие системные опции" -font $fnt(bold) -bg #eff0f1
    grid $f.l$i -row $i -column 1 -columnspan 2 -sticky w -pady {0 1mm}
    incr i
    
    label $f.l$i -text "CA Friendly Name:"
    ttk::entry $f.e$i -width 40 -textvariable ::OptionsDialog::input(system.caname)
    grid $f.l$i -row $i -column 0 -columnspan 1 -sticky nw -pady 1mm -padx 4
    grid $f.e$i -row $i -column 1 -columnspan 1 -sticky nwse -pady 1mm -padx 4 
    incr i
    
    option add *Label.background $bg_lab
    option add *Checkbutton.background $bg_lab
}

proc OptionsDialog::UpdateProfileList {listbox} {
    
    
    $listbox delete 0 end
    # fill listbox
    # insert existing profiles
    foreach v [openssl::Profile_List] {
        $listbox insert end $v
    }
    $listbox selection set 0
}

proc OptionsDialog::NewProfile {listbox} {
    
    variable selectprofiletemplate
    variable selectprofilename
    
    set w .newprofile
    
    catch "destroy $w"
    toplevel $w
    
    set selectprofiletemplate {}
    set selectprofilename {}
    
    frame $w.f
    frame $w.b
    pack $w.f $w.b -side top -padx 8 -pady 8
    
    # buttons
    ttk::button $w.b.ok -text "Готово" -width 8 -command " \
        destroy $w ;\
        openssl::Profile_Create \${::OptionsDialog::selectprofilename} \${::OptionsDialog::selectprofiletemplate} ;\
        openssl::Profile_Save ;\
        OptionsDialog::UpdateProfileList $listbox ;\
        ProfileDialog::Create .cm.setupprofiles \${::OptionsDialog::selectprofilename} \
    "
    ttk::button $w.b.cancel -text "Отмена" -width 8 -command "destroy $w"
    pack $w.b.cancel $w.b.ok  -side right -padx 4 -pady 0
    
    wm title $w "Создать новый профиль для сертификата"
    wm iconphoto $w iconCert_32x32
    wm geometry $w +150+150

    set f $w.f
    set listTempl {}
    # insert existing templates
    set alltemplates [openssl::Template_List]
    foreach v $alltemplates {
	lappend listTempl $v
    }
    label $f.l1 -text "Прототип:"
    ttk::combobox $f.e1 -width 12 \
            -textvariable ::OptionsDialog::selectprofiletemplate -value $listTempl
    $f.e1 delete 0 end
    $f.e1 insert 0 [lindex $listTempl 0]
    
    # select first
    label $f.l2 -text "Имя нового профиля:"
    entry $f.e2 -width 30 -textvariable ::OptionsDialog::selectprofilename
    
    grid $f.l1 -row 0 -column 0 -sticky w -padx 4 -pady 4
    grid $f.e1 -row 0 -column 1 -sticky w -padx 4 -pady 4
    grid $f.l2 -row 1 -column 0 -sticky w -padx 4 -pady 4
    grid $f.e2 -row 1 -column 1 -sticky w -padx 4 -pady 4
    grid columnconfigure $f 0 -weight 0
    grid columnconfigure $f 1 -weight 0
    grid columnconfigure $f 2 -weight 1
    grid rowconfigure $f 0 -weight 0
    grid rowconfigure $f 1 -weight 0
    grid rowconfigure $f 2 -weight 1
    
    
}

proc OptionsDialog::EditProfile {w} {
    
    #set s {}
    #foreach i [$w curselection] {
    #    lappend s [lindex [$w get $i] 0]
    #}
    set index [$w curselection]
    if {$index != ""} {
        set profilename [$w get $index]
        ProfileDialog::Create .cm.setupprofiles $profilename
    }
}

proc OptionsDialog::DeleteProfile {w} {
    set index [$w curselection]
    if {$index != ""} {
        set profilename [$w get $index]
        set message "Вы действительно хотите уничтожить профиль \"$profilename\"."
        set answer [tk_messageBox -icon question \
                -message $message \
                -parent $w \
                -title "Уничтожение профиля сертификата" \
                -type yesno]
                
        #puts "answer=$answer"
        if {$answer == "yes"} {
            #puts "delete profile $profilename"
            # delete the certificate profile
            openssl::Profile_Delete $profilename
            openssl::Profile_Save
            OptionsDialog::UpdateProfileList $w
        }
    }
}

proc OptionsDialog::ChooseFolder {varname} {
    upvar $varname v
    if {$v != ""} {
        set folder [tk_chooseDirectory -initialdir $v]
    } else  {
        set folder [tk_chooseDirectory]
    }
    if {$folder!=""} {
        set v $folder
    }
}

proc OptionsDialog::ButtonOK {} {
    # dirty
    variable windowname
    variable input
    array set Config::config [array get input]
parray Config::config
    # save profiles to disk
    Config::SaveConfig
    
    # close dialog
    destroy $windowname
    tk busy forget .cm.mainfr
    menu_enable
}

proc OptionsDialog::ButtonCancel {} {
    variable windowname
    # do nothing
    # close dialog
    destroy $windowname
    tk busy forget .cm.mainfr
    menu_enable
}

proc OptionsDialog::ButtonRestore {} {

    variable input
    array set input [::Config::GetAllDefault]
}


#
#
#

package provide ProfileDialog 1.0


namespace eval ProfileDialog {
    
    variable opts
    variable prof
    variable input
    
    set input(keysize) ""
    set input(validity) ""
    set input(keysize.override) ""
    set input(validity.override) ""
    set input(formatKey.override) 0
    # dirty
    variable windowname
    variable profname
    
}
proc ProfileDialog::keyParam {w num key} {
    global defaultpar
    global defaultkey
    variable opts
    global profile_options
    array set opts [array get profile_options]
    set a [string last "." $w ]
    set a [expr {$a - 1}]
    set f [string range $w 0 $a]

#puts "keyParam w=$w"
#puts "keyParam f=$f"
#puts "keyParam=$num"
#puts "keyParam=$key"
    set listBits {}
    $f.c1 delete 0 end
#tk_messageBox -title "keyParam" -icon info -message "keyParam w=$w\nkeyParam f=$f\nkeyParam=$key"  -parent $w

#    $f.c2 configure -state disabled
if {$key == "RSA"} {
    $f.c2 configure -state normal
    $f.c1 configure -state normal
    set first ""
    $f.l2 configure -text "Key Size"
    # insert choices
    set i 0
    foreach v $opts(req.default_bits.options) {
	if {$first == "" && $i == 1 } { set first $v}
	lappend listBits $v
	incr i
    }
    $f.c1 insert 0 $first
} elseif {$key == "gost2012_512"} {
    $f.c2 configure -state disabled
    $f.l2 configure -text "Параметры ГОСТ-12-512"
    set listBits {1.2.643.7.1.2.1.2.1 1.2.643.7.1.2.1.2.2 1.2.643.7.1.2.1.2.3}
    set defaultpar [lindex $listBits 1]
    $f.c1 insert end $defaultpar
} elseif {$key == "gost2012_256"} {
    $f.c2 configure -state disabled
    $f.l2 configure -text "Параметры ГОСТ-12-256"
    set listBits {1.2.643.2.2.35.1 1.2.643.2.2.35.2  1.2.643.2.2.35.3  1.2.643.2.2.36.0 1.2.643.2.2.36.1 1.2.643.7.1.2.1.1.1 1.2.643.7.1.2.1.1.2 1.2.643.7.1.2.1.1.3 1.2.643.7.1.2.1.1.4}
    if {$key == "gost2012_256"} {
    set defaultpar [lindex $listBits 3]
    } else {
    set defaultpar [lindex $listBits 0]
    }
    $f.c1 insert end $defaultpar
} elseif {$key == "gost2001"} {
    $f.l2 configure -text "Параметры ГОСТ-12-256"
    set listBits {1.2.643.2.2.35.1 1.2.643.2.2.35.2  1.2.643.2.2.35.3  1.2.643.2.2.36.0 1.2.643.2.2.36.1}
    if {$key == "gost2012_256"} {
    set defaultpar [lindex $listBits 3]
    } else {
    set defaultpar [lindex $listBits 0]
    }
    $f.c1 insert end $defaultpar
} else {
    $f.l2 configure -text "Paramets for Bad Key"
    set listBits {A B C XA XB}
    $f.c1 insert 0 A
    set defaultpar ""
}
    set defaultkey $key
    $f.c1 configure -values $listBits
}

proc selectdays {i} {
    set ::ProfileDialog::prof(CA.default_days) [expr {$i + $::yearcert * 365}]
}
proc selectyears {} {
    set ::ProfileDialog::prof(CA.default_days) [expr {$::dayscert + $::yearcert * 365}]
#    tk_messageBox -title "Дни" -message "Установлено дней:$::ProfileDialog::prof(CA.default_days) " -icon info -parent .cm
}


proc ProfileDialog::Create {w profilename} {
    global defaultkey
    global defaultpar
    global config
    global profile_options
    global userroles
    global typesys
    global home

    variable opts
    variable prof
    
    # dirty
    variable windowname
    variable profname
    set windowname $w
    set profname $profilename
    
    catch "destroy $w"
    labelframe  $w -labelanchor n -bd 0 -relief flat -background #e0e0da -padx 2 -pady 2 
    $w configure -text "УЦ ФЗ-63. Настройки для сертификатов" -font {Times 11 bold}

if {$w != ".cm.setupprofiles"} {
    tk busy hold .cm.mainfr
    menu_disable
}

    place $w -in .cm.mainfr.ff.notbok -x 1 -y 0  -relwidth 0.998  -relheight 1.0
#    place $w -in .cm.mainfr -x 0 -y 0  -relwidth 1.0  -relheight 0.92

    raise $w


    frame $w.mainfr -relief flat -background white -bd 0

    pack $w.mainfr -fill both -pady 2
    set w $w.mainfr

    frame $w.title -bg #eff0f1
    frame $w.f
    frame $w.b
    frame $w.b2

    $w configure -pady 8
    pack $w.title $w.f -side top -expand 1 -anchor e -fill both -padx 8 -pady 0
    pack $w.f -side top -expand 1 -anchor center -fill both -padx 8 -pady 2
    pack $w.b -side top -expand 1 -anchor e -padx 8 -pady 2
    
    # title
    set tekpr "Профиль сертификата: $profilename"
    ttk::label $w.title.l -text $tekpr -justify center -image shieldbuild_40x40 -compound left -background white -borderwidth 0 -relief flat -font {Times 11 bold italic} -padding 0

#    label $w.title.l -text "Certificate Profile:" -font {Times 10 bold italic}
    set fnt(std) [$w.title.l cget -font]
    set fnt(bold) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] bold]
#    $w.title.l configure -font $fnt(bold)
#    label $w.title.t -text "$profilename" -background #e0e0da  -borderwidth 4 -relief groove
    pack $w.title.l -fill x  -in $w.title -pady 0
#    pack $w.title.l $w.title.t -side left
    
    frame $w.sep -height 2 -bd 0 -relief flat -background #e0e0da
    pack $w.sep -fill x 

    ttk::button $w.b2ok -text "Готово" -width 8 \
            -command "ProfileDialog::ButtonOK"  -style MyBorder.TButton
    ttk::button $w.b2cancel -text "Отмена" -width 8 \
            -command "ProfileDialog::ButtonCancel" -style MyBorder.TButton

    pack $w.b2cancel $w.b2ok -side right -padx 8 -pady {2mm 0} -anchor w
    
    # create notebook - Notebook
    Notebook:create $w.f.n -pages {"Subject DN" "Key Pair" "Certificate" "Key Usage" "Extensions" "Other" } -width 550 -height 290

    set n $w.f.n
    
    # get data from profile
    array set prof [openssl::Profile_GetData $profilename]
    openssl::Profile_Unpack prof
    array set opts [array get profile_options]
#tk_messageBox -title "OPTS" -message "КЛЮЧИ.\n $::ProfileDialog::prof(req.default_key.selected) \n$::ProfileDialog::opts(req.default_key.default)" -icon error  -parent .cm
#tk_messageBox -title "PARAN" -message "КЛЮЧИ.\n $::ProfileDialog::prof(req.default_param.selected) \n$::ProfileDialog::opts(req.default_param.default)" -icon error  -parent .cm
    
    #parray opts
    #parray prof
    
    # we use following from profile
    #req.default_bits 1024
    #CA.default_days 365
    #CA_ext.keyUsage {digitalSignature, keyEncipherment}
    #CA_ext.keyUsage.options {digitalSignature nonRepudiation keyEncipherment dataEncipherment keyAgreement keyCertSign cRLSign encipherOnly decipherOnly}
    #CA_ext.nsCertType server
    #CA_ext.nsCertType.options {client server email objsign reserved sslCA emailCA objCA}
    
    # request options
    set f [Notebook:frame $n "Key Pair"]
    $f configure -background white -borderwidth 0
#    $f configure -background #eff0f1 -borderwidth 1

    label $f.l1  -image keypair_40x39 -compound left -bg white

    #Type Key
    # combo box
    label $f.lkey -text "Тип ключа:"
    set listKey {RSA gost2001 gost2012_256 gost2012_512}
    if {$::ProfileDialog::prof(req.default_key.selected) != ""} {
	set defaultkey $::ProfileDialog::prof(req.default_key.selected)
    }
    if {$::ProfileDialog::prof(req.default_param.selected) != ""} {
	set defaultpar $::ProfileDialog::prof(req.default_param.selected)
    }
    ttk::combobox $f.ckey -width 20  -textvariable ::ProfileDialog::prof(req.default_key.selected) -values $listKey
#puts "CKEY_F=$f"
    $f.ckey delete 0 end
    $f.ckey insert 0 $defaultkey
    bind $f.ckey <<ComboboxSelected>> {ProfileDialog::keyParam %W f $::ProfileDialog::prof(req.default_key.selected);puts $::ProfileDialog::prof(req.default_key.selected)}
 
    # combo box
    set listBits {}
    label $f.l2
    set tekB 0
if {$defaultkey == "RSA"} {
    $f.l2 configure -text "Длина ключа:"
    # insert choices
    set as $::ProfileDialog::prof(req.default_bits.selected)
    set ok 0
    foreach v $opts(req.default_bits.options) {
	lappend listBits $v
	if {$v != $as && $ok == 0} {
	    incr tekB
	} else {incr ok}
    }
} elseif {$defaultkey == "gost2012_512"} {
    $f.l2 configure -text "Параметры ГОСТ-12-512:"
    set listBits {1.2.643.7.1.2.1.2.1 1.2.643.7.1.2.1.2.2 1.2.643.7.1.2.1.2.3}
} elseif {$defaultkey == "gost2012_256"} {
    $f.l2 configure -text "Параметры ГОСТ-12-256:"
    set listBits {1.2.643.2.2.35.1 1.2.643.2.2.35.2  1.2.643.2.2.35.3  1.2.643.2.2.36.0 1.2.643.2.2.36.1 1.2.643.7.1.2.1.1.1 1.2.643.7.1.2.1.1.2 1.2.643.7.1.2.1.1.3 1.2.643.7.1.2.1.1.4}
} else {
    $f.l2 configure -text "Параметры ГОСТ-2001:"
    set listBits {1.2.643.2.2.35.1 1.2.643.2.2.35.2  1.2.643.2.2.35.3  1.2.643.2.2.36.0 1.2.643.2.2.36.1}
}
    ttk::combobox $f.c1 -width 20  -textvariable ::ProfileDialog::prof(req.default_bits.selected) -values $listBits
    # set current setting
    $f.c1 delete 0 end
    if {$defaultkey == "RSA"} {
#	$f.c1 insert end [lindex $listBits $tekB]
	$f.c1 insert 0 $defaultpar
    } else {
	$f.c1 insert 0 $defaultpar
    }
    
    ttk::checkbutton $f.c2 -text "Allow Key Size Override" -variable input(keysize.override)
    grid $f.l1 -row 0 -column 0 -columnspan 2 -sticky w -padx 0 -pady 8
    set ::ProfileDialog::input(formatKey.override) 0
    label $f.lb11 -text "Библиотека PKCS#11:"
    set typedef ""
    set libtyp ""
    if {$typesys != "win32" } {
	set typedef [Config::Get filetype.liblinux_default]
	set libtyp [Config::Get filetype.liblinux]
    } else {
	set typedef [Config::Get filetype.libwin32_default]
	set libtyp [Config::Get filetype.libwin32]
    }
    cagui::FileEntry $f.eb11 \
            -dialogtype open \
            -initialdir $home \
            -variable ::OptionsDialog::input(library.pkcs11) \
            -title "Выберите библиотеку PKCS#11" \
            -width 60 \
            -defaultextension $typedef \
            -filetypes $libtyp \
            -parent ".cm"

    grid $f.lb11 -row 2 -column 0 -sticky nw -pady 1mm
    grid $f.eb11 -row 2 -column 1 -sticky nwse -padx 4 -pady 1mm
    
    grid $f.lkey -row 3 -column 0 -sticky new -padx 0 -pady 1mm
    grid $f.ckey -row 3 -column 1 -sticky w -padx 4 -pady 1mm


    grid $f.l2 -row 4 -column 0 -sticky new -padx 0 -pady 4
    grid $f.c1 -row 4 -column 1 -sticky w -padx 4 -pady 4
	grid $f.c2 -row 5 -column 0 -columnspan 2 -sticky w -padx 8 -pady 8
    if {$defaultkey == "RSA"} {
	$f.c2 configure -state normal
    } else {
	$f.c2 configure -state disabled
    }

    # sign options
    set f [Notebook:frame $n "Certificate"]
    $f configure -background #eff0f1

################
    $f configure -bg white 
    set ::yearcert [expr {$::ProfileDialog::prof(CA.default_days) / 365} ]
    set ::dayscert [expr {$::ProfileDialog::prof(CA.default_days) % 365} ]
    label $f.lyear -text "Срок действия сертификата в годах и днях:" -font {Times 10 bold roman}
    grid $f.lyear -row 0 -column 0 -columnspan 2 -sticky w -padx {5mm 0} -pady {5mm 1mm}
    label $f.labyear -text "Количество лет:" 
    grid $f.labyear -row 1 -column 0  -sticky w -padx {10mm 0} -pady 1mm
    ttk::spinbox $f.years -from 0 -to 25 -state readonly -textvariable ::yearcert -justify right -width 5 -command {selectyears} 
    #  -bg white
    grid $f.years -row 1 -column 1 -columnspan 1 -sticky w -padx 0 -pady {0 0}
    label $f.labdays -text "Количество дней:"
    grid $f.labdays -row 2   -sticky w -padx {10mm 0} -pady 1mm
    scale $f.days -from 0 -to 366 -tickinterval 30 -orient horizontal -variable ::dayscert -showvalue true -length 530 -width 8  -font {Times 8 bold roman} -bg snow -command selectdays
    grid $f.days -row 2 -column 1 -columnspan 2 -sticky w -padx 0 -pady 1mm

###########################
    ttk::checkbutton $f.c2 -text "Allow Certificate Validity Override" -variable input(validity.override)
    
    label $f.l3 -text "Basic Constraints"
    set listConst {}
    foreach v $opts(CA_ext.basicConstraints.options) {
	lappend listConst $v
    }
    set tekB [lsearch -exact $opts(CA_ext.basicConstraints.options) $prof(CA_ext.basicConstraints)]
    
    ttk::combobox $f.c3 -width 40  -textvariable ::ProfileDialog::prof(CA_ext.basicConstraints) -values $listConst
    $f.c3 delete 0 end
    $f.c3 insert 0 [lindex $listConst $tekB]

#    grid $f.l1 -row 0 -column 0 -columnspan 2 -sticky w -padx 8 -pady 8

#    grid $f.l2 -row 6 -column 0 -sticky w -padx {5mm 0} -pady {5mm 2mm}
#    grid $f.c1 -row 6 -column 1 -sticky w -padx 0 -pady {5mm 2mm}
    grid $f.c2 -row 7 -column 0 -columnspan 2 -sticky w -padx {5mm 0} -pady 1mm
    grid $f.l3 -row 8 -column 0 -sticky w -padx {5mm 0} -pady 8
    grid $f.c3 -row 8 -column 1 -sticky w -padx 0 -pady 8
    grid columnconfigure $f 1 -weight 1
    
    
    set f1 [Notebook:frame $n "Subject DN"]
    $f1 configure -background white -borderwidth 0 -relief flat
    global rfregions
    set scrfr    "scrolledframe $f1.sf -yscroll {$f1.vs set} "
    set scrver    "ttk::scrollbar $f1.vs -command {$f1.sf yview}"
    set com [subst $scrfr]
    set com1 [subst $scrver]
    eval $com
    eval $com1
    pack $f1.vs -side right -fill y
    set scrpack "pack $f1.sf  -side left -fill both -expand 1" 
    set com2 [subst $scrpack]
    eval $com2

    $f1.sf configure -background #e0e0da -borderwidth 0
    set f $f1.sf.scrolled
    $f1.sf.scrolled configure -background white -borderwidth 0

    grid columnconfigure $f 0 -weight 0
    grid columnconfigure $f 1 -weight 0
    grid columnconfigure $f 2 -weight 0
    grid columnconfigure $f 3 -weight 1
    grid rowconfigure $f 0 -weight 0
    grid rowconfigure $f 1 -weight 0
    
#    label $f.l0 -text ""
#    grid $f.l0 -row 0 -column 0 -columnspan 1 -sticky w -padx 0 ;#-pady 4
    
    label $f.l1 -text "Включать следующие поля в Subject Distinguished Name (DN):" -font $fnt(bold)
    grid $f.l1 -row 1 -column 0 -columnspan 3 -sticky w -padx 8 -pady 1mm

    label $f.l2 -text "Поле:" -font $fnt(bold)
    grid $f.l2 -row 2 -column 0 -columnspan 1 -sticky w -padx 8 -pady 1mm
    label $f.l2b -text "Обязательно:" -font $fnt(bold)
    grid $f.l2b -row 2 -column 1 -columnspan 1 -sticky w -padx 8 -pady 1mm
    label $f.l2c -text "Значение по умолчанию:" -font $fnt(bold)
    grid $f.l2c -row 2 -column 2 -columnspan 1 -sticky nwse -padx 8 -pady 1mm
#    grid rowconfigure $f 2 -weight 0
    grid columnconfigure $f 2 -weight 1
    set i 3
    foreach {field label} $opts(req.dn_fieldsFL63) {
#puts "FIELD=$field LABEL=$label"
        ttk::checkbutton $f.c$i -text "$label" -variable ::ProfileDialog::prof(req.dn_fields.$field)

        grid $f.c$i -row $i -column 0 -columnspan 1 -sticky w -padx 8 -pady {0 1mm}
        ttk::checkbutton $f.cr$i  -variable ::ProfileDialog::prof(req.dn_fields.required.$field)
        grid $f.cr$i -row $i -column 1 -columnspan 1 -sticky w -padx {32 0} -pady {0 1mm}

        if {$field == "C"} {
	    set listCountry {}
            foreach v $::openssl::iso3166 {
		lappend listCountry $v
            }
            set tekC 0
            if {$prof(req.dn_fields.val.$field) != ""} {
		set tekC [lsearch $listCountry $::ProfileDialog::prof(req.dn_fields.val.$field)]
            }
#puts "listCountry=$::ProfileDialog::prof(req.dn_fields.val.$field)"

            ttk::combobox $f.ce$i -textvariable ::ProfileDialog::prof(req.dn_fields.val.$field) -width 80 -values $listCountry
	    $f.ce$i delete 0 end
	    $f.ce$i insert end [lindex $listCountry $tekC]
        } elseif {$field == "ST"} {
            set tekC 0
            if {$prof(req.dn_fields.val.$field) != ""} {
		set tekC [lsearch $rfregions $::ProfileDialog::prof(req.dn_fields.val.$field)]
            }
#puts "listCountry=$::ProfileDialog::prof(req.dn_fields.val.$field)"

            ttk::combobox $f.ce$i -textvariable ::ProfileDialog::prof(req.dn_fields.val.$field)  -values $rfregions
	    $f.ce$i delete 0 end
	    $f.ce$i insert end [lindex $rfregions $tekC]
        } else  {
            ttk::entry $f.ce$i  -textvariable ::ProfileDialog::prof(req.dn_fields.val.$field)
        }
        grid $f.ce$i -row $i -column 2 -columnspan 1 -sticky nwse -padx 8  -pady {0 1mm}
        incr i
    }
    grid columnconfigure $f 2 -weight 1
    set m $i
#    grid rowconfigure $f $i -weight 1
        
    #key usage options
    #set f [$n getframe keyUsage]
    set f1 [Notebook:frame $n "Key Usage"]
    $f1 configure -background white -borderwidth 0
#    set scrfr    "scrolledframe $f1.sf -yscroll {$f1.vs set} "
    set scrfr    "scrolledframe $f1.sf -yscroll {hidescroll  $f1.vs}"

    set scrver    "ttk::scrollbar $f1.vs -command {$f1.sf yview}"
    set com [subst $scrfr]
    set com1 [subst $scrver]
    eval $com
    eval $com1
#Не включаем вертикальную прокрутку
    pack $f1.vs -side right -fill y

    set scrpack "pack $f1.sf  -side left -fill both -expand 1" 
    set com2 [subst $scrpack]
    eval $com2

    $f1.sf configure -background white -borderwidth 0
    set f $f1.sf.scrolled
    $f1.sf.scrolled configure -background white -borderwidth 0

    grid columnconfigure $f 0 -weight 0
    grid columnconfigure $f 1 -weight 0
    grid columnconfigure $f 2 -weight 0
    grid columnconfigure $f 3 -weight 1
    grid rowconfigure $f 0 -weight 0
    grid rowconfigure $f 1 -weight 0
        
#    label $f.l0 -text ""
#    grid $f.l0 -row 0 -column 0 -columnspan 1 -sticky w -padx 8 ;#-pady 4
    
#Key Usage:
    label $f.l1 -text "Key Usage:" -font $fnt(bold)
    grid $f.l1 -row 1 -column 0 -columnspan 1 -sticky w -padx 8 -pady 2mm
    grid rowconfigure $f 1 -weight 0
    
    set i 2
    foreach v $opts(CA_ext.keyUsage.options) {
        ttk::checkbutton $f.c$i -text "$v" -variable ::ProfileDialog::prof(CA_ext.keyUsage.$v)
        grid $f.c$i -row $i -column 0 -columnspan 1 -sticky w -padx 8  ;# -pady 4
        incr i
    }
    set m $i

    label $f.l3 -text "Ext. Key Usage:" -font $fnt(bold)
    grid $f.l3 -row 1 -column 1 -columnspan 1 -sticky w -padx 8 -pady 2mm
    grid rowconfigure $f 1 -weight 0
    
    set i 2
    foreach v $opts(CA_ext.extKeyUsage.options) {
	    if {$v == "whois" || $v == "role"} {
		continue;
	    }
    	    ttk::checkbutton $f.ccc$i -text "$v" -variable ::ProfileDialog::prof(CA_ext.extKeyUsage.$v)
        grid $f.ccc$i -row $i -column 1 -columnspan 1 -sticky w -padx 8 ;# -pady 4
        grid rowconfigure $f $i -weight 0
        incr i
    }
    if {$i>$m} {set m $i}
#Netscape Type
    label $f.l2 -text "Netscape Type:" -font $fnt(bold)
    grid $f.l2 -row 1 -column 2 -columnspan 1 -sticky w -padx 8 -pady 2mm
    grid rowconfigure $f 1 -weight 0
    
    set i 2
    foreach v $opts(CA_ext.nsCertType.options) {
        ttk::checkbutton $f.cc$i -text "$v" -variable ::ProfileDialog::prof(CA_ext.nsCertType.$v)
        grid $f.cc$i -row $i -column 2 -columnspan 1 -sticky w -padx 8 ;# -pady 4
        grid rowconfigure $f $i -weight 0
        incr i
    }
    if {$i>$m} {set m $i}
    grid rowconfigure $f $m -weight 1
#Роли сертификата - Детище российского PKI
    label $f.l4 -text "Роли:" -font $fnt(bold)
    grid $f.l4 -row 1 -column 3 -columnspan 1 -sticky w -padx 8 -pady 2mm
    grid rowconfigure $f 1 -weight 0
    set i 2
    foreach v $opts(CA_ext.extKeyUsage.options) {
	if {$v == "whois" && $profilename != "SSL Server"} {
		label $f.lwho -text "Владелец сертификата:" -font $fnt(bold)
		grid $f.lwho -row $i -column 3 -columnspan 1 -sticky w -padx 8 -pady 1mm
		incr i
    		ttk::combobox $f.cr$i -text "$v" -textvariable ::ProfileDialog::prof(CA_ext.extKeyUsage.$v) -values {"" "Физ. лицо" "Юр. лицо" "ИП"}
    		$f.cr$i delete 0 end
#    		$f.cr$i insert end "Физ. лицо"
    		$f.cr$i insert end ""
	} elseif {$v == "role" && $profilename != "SSL Server" } {
		label $f.lutil -text "Область использования:" -font $fnt(bold)
		grid $f.lutil -row $i -column 3 -columnspan 1 -sticky w -padx 8 -pady 1mm
		incr i
    		ttk::combobox $f.cr$i -text "$v" -textvariable ::ProfileDialog::prof(CA_ext.extKeyUsage.$v) -values $userroles
    		$f.cr$i delete 0 end
    		$f.cr$i insert end ""
#    		$f.cr$i insert end "Госуслуги"
	}  else {
	    continue
	}
        grid $f.cr$i -row $i -column 3 -columnspan 1 -sticky we -padx 15mm ;# -pady 4
        grid rowconfigure $f $i -weight 0
        incr i
    }
    grid columnconfigure $f 3 -weight 1
    if {$i>$m} {set m $i}



    #
    # other extensions
    set f [Notebook:frame $n "Extensions"]
    $f configure -background #e0e0da
    $f configure -background white -borderwidth 0 -relief flat

#authorityInfoAccess
    label $f.l1 -text "Точки доступа к корневому сертификату и серверу OCSP (authorityInfoAccess):" -font $fnt(bold)
    grid $f.l1 -row 1 -column 0 -columnspan 2 -sticky nw -padx 2mm -pady {0 0}
#        label $f.l3 -text "caIssuers;URL:<>,OCSP;URL:<>"
    
    set i 2
    foreach {field label} {
            CA_ext.authorityInfoAccess "Authority Info Access"
            CA_ext.crlDistributionPoints "CRL Distribution Point"
            CA_ext.nsCaPolicyUrl "Netscape Policy URL"
            CA_ext.nsComment "Netscape Comment"
            CA_ext.nsBaseUrl "NS Base URL"
            CA_ext.nsRevocationUrl "NS Revocation URL"
            CA_ext.nsRenewalUrl "NS Renewal URL"
    } {

if {$i == 3} {
    label $f.l$i -text "Точки доступа к СОС/CRL:" -font $fnt(bold)
    grid $f.l$i -row $i -column 0 -columnspan 2 -sticky nw -padx 2mm -pady {1mm 0}
    incr i
        label $f.l$i -text $label
        ttk::entry $f.e$i  -textvariable ::ProfileDialog::prof($field)
        grid $f.l$i -row $i -column 0 -columnspan 1 -sticky nw -padx 5mm -pady  0
        grid $f.e$i -row $i -column 1 -columnspan 1 -sticky nwse -padx 5mm -pady 0
  set lc "bind $f.e$i <Enter> {.cm.helpview configure -text \"URI:<путь>\";place .cm.helpview -in $f.e$i -relx 0.0 -rely 1.0;raise .cm.helpview}"
  set lc [subst $lc]
  eval $lc
  bind $f.e$i <Leave> {place forget .cm.helpview}
    incr i
    label $f.l$i -text "Дополнительные поля:" -font $fnt(bold)
    grid $f.l$i -row $i -column 0 -columnspan 2 -sticky nw -padx 2mm -pady 0
    incr i
    continue
}
        label $f.l$i -text $label
        ttk::entry $f.e$i  -textvariable ::ProfileDialog::prof($field)
if {$i == 2} {
  set lc "bind $f.e$i <Enter> {.cm.helpview configure -text \"caIssuers;URI:<путь>,OCSP;URI:<путь>\";place .cm.helpview -in $f.e$i -relx 0.0 -rely 1.0;raise .cm.helpview}"
  set lc [subst $lc]
  eval $lc
  bind $f.e$i <Leave> {place forget .cm.helpview}
}
        grid $f.l$i -row $i -column 0 -columnspan 1 -sticky nw -padx 5mm -pady {1mm 0}
        grid $f.e$i -row $i -column 1 -columnspan 1 -sticky nwse -padx 5mm -pady {1mm 0}
        incr i
    }
#    grid rowconfigure $f $i -weight 1
    grid columnconfigure $f 1 -weight 1
    
    
    #
    # other options
    set f [Notebook:frame $n "Other"]
    $f configure -background #e0e0da
    
#    label $f.l1 -text ""
    
    # combo box for "subbest file name option"
    label $f.l2 -text "Suggest File Name"
    set listSugg {}
    # insert choices
    foreach v $opts(other.suggestfilename.options) {
	lappend listSugg $v
    }

    set tekB [lsearch  $listSugg $::ProfileDialog::prof(other.suggestfilename)]

    ttk::combobox $f.c2 -width 20  -textvariable ::ProfileDialog::prof(other.suggestfilename) -values $listSugg
    # set current setting
    $f.c2 delete 0 end
    $f.c2 insert 0 [lindex $listSugg $tekB]
    
    # combo box for "subject type option"
    label $f.l3 -text "Subject Type"
    set listSub {}
    # insert choices
    foreach v $opts(other.subjecttype.options) {
	lappend listSub $v
    }
    set tekB [lsearch $listSub $::ProfileDialog::prof(other.subjecttype)]
    ttk::combobox $f.c3 -width 20  -textvariable ::ProfileDialog::prof(other.subjecttype) -values $listSub
    # set current setting
    $f.c3 delete 0 end
    $f.c3 insert 0 [lindex $listSub $tekB]
    
#    grid $f.l1 -row 0 -column 0 -columnspan 2 -sticky w -padx 8 -pady 8
    grid $f.l2 -row 1 -column 0 -sticky new -padx {5mm 0} -pady {5mm 0}
    grid $f.c2 -row 1 -column 1 -sticky w -padx 5mm -pady {5mm 0}
    grid $f.l3 -row 2 -column 0 -sticky new -padx {5mm 0} -pady 2mm
    grid $f.c3 -row 2 -column 1 -sticky w -padx 5mm -pady 2mm
    grid columnconfigure $f 0 -weight 0
    grid columnconfigure $f 1 -weight 0
    grid columnconfigure $f 2 -weight 1
    grid rowconfigure $f 0 -weight 0
    grid rowconfigure $f 1 -weight 0
    grid rowconfigure $f 2 -weight 0
    grid rowconfigure $f 3 -weight 1

}

proc ProfileDialog::ButtonOK {} {
    # dirty
    variable windowname
    variable profname
    global defaultkey
    global defaultpar
#puts "WINDOWNAME=$windowname"
    if { $::ProfileDialog::input(formatKey.override) == 0 } {
	set ::ProfileDialog::prof(req.default_libp11.selected) ""
    } else {
	set ::ProfileDialog::prof(req.default_libp11.selected) $::OptionsDialog::input(library.pkcs11)
    }    
#puts "LIBP11=$::ProfileDialog::prof(req.default_libp11.selected)"
    set defaultkey [$windowname.mainfr.f.n.f1.ckey get]
    set ::ProfileDialog::prof(req.default_key.selected) [$windowname.mainfr.f.n.f1.ckey get]
    if {$defaultkey != "RSA"} {
	set defaultpar [$windowname.mainfr.f.n.f1.c1 get]
    } else {
	set ::ProfileDialog::prof(req.default_bits.selected) [$windowname.mainfr.f.n.f1.c1 get]
	set ::ProfileDialog::prof(req.default_param.selected) [$windowname.mainfr.f.n.f1.c1 get]
    }
#uts "DEFAULTKEY=$defaultkey"
#uts "DEFAULTPAR=$defaultpar"
    set ::ProfileDialog::prof(req.dn_fields.val.C) [$windowname.mainfr.f.n.f0.sf.scrolled.ce3 get]
    set ::ProfileDialog::prof(other.suggestfilename) [$windowname.mainfr.f.n.f5.c2 get]
    set ::ProfileDialog::prof(other.subjecttype) [$windowname.mainfr.f.n.f5.c3 get]

    variable opts
    variable prof
    
    # now this is tricky
    # we definitely should FIRST close dialog, then calculate
    # reason :
    # dialog binds to text variables, directly in prof array
    # this means the profile-unpack does not delete all unpacked parameters
    # (bug in tcl ?)
    # resulting in writing out/ keeping in profile unpacked variables.
    
    # close dialog
    destroy $windowname
    
    
    # save values in current profile
    openssl::Profile_Pack prof
    #puts "after pack"
    #puts ""
    #parray prof
    
    openssl::Profile_SetData $profname [array get prof]
    
    # save profiles to disk
    openssl::Profile_Save
    
}

proc ProfileDialog::ButtonCancel {} {
    variable windowname
    # do nothing
    # close dialog
    destroy $windowname
}

#
# cagui.tcl
#
# CAFL63 Gui Componenets

# CAFL63 Logo

package provide cagui 1.0

namespace eval cagui {
    
    variable img_cert
    set img_cert img_cert
    
    variable status {}  ;# status displayed in progress
    
}

proc cagui::FileDialog {args} {

    set validopts {-dialogtype -defaultextension -filetypes -title -variable -initialdir -command -parent}
    set passingopts {-defaultextension -filetypes -title -initialdir -initialfile -parent}
        
    # parse arguments
    array set opts_in $args
#parray opts_in
    foreach opt $validopts {
#puts "cagui::FileDialog: "
        if {[info exists opts_in($opt)]} {
#puts "cagui::FileDialog: $opt=$opts_in($opt) "
            set opts($opt) $opts_in($opt)
        }
    }

    if {[info exists opts_in(-variable)]} {
        upvar $opts_in(-variable) variable
    }
    if {$opts(-dialogtype)=="directory"} {
        if {![info exists variable] || $variable == ""} {
            if {[info exists opts_in(-initialdir)]} {
                set opts(-initialdir) $opts_in(-initialdir)
            }
        } else  {
            set opts(-initialdir) $variable
        }
    } else  {
        if {![info exists variable] || $variable == ""} {
            set opts(-initialfile) ""
            if {[info exists $opts_in(-initialdir)]} {
                set opts(-initialdir) $opts_in(-initialdir)
            }
        } else  {
            set opts(-initialfile) [file tail $variable]
            set opts(-initialdir) [file dirname $variable]
        }
    }
    
    # build command
    # parray opts
    set command tk_getOpenFile

    if {[info exists opts(-dialogtype)]} {
        if {$opts(-dialogtype)=="open"} {
            set command "tk_getOpenFile -parent .cm"
        } elseif {$opts(-dialogtype)=="save"} {
            set command "tk_getSaveFile  -parent .cm"
        } elseif {$opts(-dialogtype)=="directory"} {
    	    if {![info exists opts(-parent)]} {
        	set command "tk_chooseDirectory  -parent .cm"
    	    } else {
        	set command "tk_chooseDirectory "
            }
        }
    }
    foreach opt $passingopts {
        if {[info exists opts($opt)]} {
            lappend command $opt $opts($opt)
        }
    }

    set v [eval $command]
    
    if {$v != ""} {
        if {[info exists variable]} {
            set variable $v
        }
        if {[info exists opts(-command)] && $opts(-command) != ""} {
            uplevel #0 $opts(-command)
        }
    }
    
    return $v
}

proc cagui::FileEntry {w args} {
    ttk::style map My1.TButton -background [list disabled #d9d9d9  active #00ff7f] -foreground [list disabled #a3a3a3] -relief [list {pressed !disabled} sunken]

    set validopts {-dialogtype -width -defaultextension -filetypes -title -variable -initialdir -command -parent}
    set passingopts {-dialogtype -defaultextension -filetypes -title -variable -initialdir -command -parent}
    set entryopts {-width}
    
    # parse arguments
    array set opts_in $args
    foreach opt $validopts {
        if {[info exists opts_in($opt)]} {
            set opts($opt) $opts_in($opt)
        }
    }
    upvar $opts(-variable) variable
    upvar $opts_in(-variable) variable
    if {$variable == ""} {
        set opts(-initialfile) ""
        if {[info exists opts_in(-initialdir)]} {
            set opts(-initialdir) $opts_in(-initialdir)
        }
    } else  {
        set opts(-initialfile) [file tail $variable]
        set opts(-initialdir) [file dirname $variable]
    }

    # build buttoncommand
    set buttoncommand "cagui::FileDialog"
    foreach opt $passingopts {
        if {[info exists opts($opt)]} {
            lappend buttoncommand $opt $opts($opt)
        }
    }

    set entrycommand [list ttk::entry $w.entry -textvariable $opts(-variable)]
    #puts "entrycommand : $entrycommand"
    foreach opt $entryopts {
        if {[info exists opts($opt)]} {
            lappend entrycommand $opt $opts($opt)
        }
    }
#puts "entrycommand : $entrycommand"
#puts "buttoncommand : $buttoncommand"
    
    frame $w -background white
    eval $entrycommand
    button $w.but -image icon_openfile_18x16  -compound center -command $buttoncommand -bd 0 -background white -activebackground white -highlightthickness 0

    pack $w.entry $w.but -side right -ipadx 1 -fill none
    pack $w.entry  -side left -ipadx 1 -fill x -expand 1

}

proc cagui::ProgressWindow_Create {w {title {Running ...}}  {message {}}} {
    variable status
    global countfile
    global cancelexport
    set cancelexport 0
    
    catch "destroy $w"
    frame $w -width 400 -height 100  -relief flat -bd 0 -highlightbackground chocolate -highlightthickness 3
    $w configure -background #3daee9
    
    frame $w.f -background white
    frame $w.bt -background white
    pack $w.f -expand 1 -fill both -padx 3 -pady 3
    pack $w.bt -expand 1 -fill both -padx 3 -pady {0 3} 

    ttk::button $w.bt.cancel -text "Отмена" -command {global cancelexport; set cancelexport 1}
    pack $w.bt.cancel -side right -padx 5 -pady 5
    
    label $w.f.l1 -text "$message" -font {Times 10 bold italic}
    label $w.f.status -textvariable "::cagui::status"
    set status "-"
    
    ttk::progressbar $w.f.c -variable countfile

    grid $w.f.l1 -row 0 -column 0 -columnspan 2 -sticky nw
    grid $w.f.status -row 1 -column 0 -columnspan 2 -sticky nw
    grid $w.f.c -row 2 -column 0 -columnspan 2 -sticky nwe
    grid columnconfigure $w.f 0 -pad 8 -weight 1
    grid columnconfigure $w.f 1 -pad 8 -weight 0
    grid columnconfigure    $w.f 0  -weight 1
    grid rowconfigure    $w.f 1 -weight 0
    grid rowconfigure    $w.f 2 -weight 0
    grid rowconfigure    $w.f 3 -weight 1

    place $w -in .cm.mainfr.ff.notbok -x 215 -y 60  -relwidth 0.5
    raise $w
    update
}

proc cagui::ProgressWindow_SetStatus {w message {progress {}} } {
    
    variable status
    global countfile    
    set status $message
    if {$progress != ""} {
        if {$progress < 0} {
            set progress 0
            set countfile 0
        }
        if {$progress >100} {
            set countfile 10
        }
    }
    update
}

# Copyright (c) 2001, Bryan Oakley
# All Rights Reservered
#
# Bryan Oakley
# oakley@bardo.clearlight.com
#
# tkwizard 1.0a1
#
# this code is freely distributable without restriction, and is 
# provided as-is with no warranty expressed or implied. 
#

package provide tkwizard 1.0

# create the package namespace, and do some basic initialization
namespace eval tkwizard {

    namespace export tkwizard
    
    set ns [namespace current]

    # define class bindings
    bind Wizard <<WizHelp>>     [list ${ns}::handleEvent %W <<WizHelp>>]
    bind Wizard <<WizNextStep>> [list ${ns}::handleEvent %W <<WizNextStep>>]
    bind Wizard <<WizPrevStep>> [list ${ns}::handleEvent %W <<WizPrevStep>>]
    bind Wizard <<WizCancel>>   [list ${ns}::handleEvent %W <<WizCancel>>]
    bind Wizard <<WizFinish>>   [list ${ns}::handleEvent %W <<WizFinish>>]

    # create a default image
    image create photo [namespace current]::feather -data {
       R0lGODlhIAAgALMAANnZ2QAAwAAA/wBAwAAAAICAgAAAgGBggKCgpMDAwP//
       /////////////////////yH5BAEAAAAALAAAAAAgACAAAAT/EMhJq60hhHDv
       pVCQYohAIJBzFgpKoSAEAYcUIRAI5JSFlkJBCGLAMYYIIRAI5ASFFiqDgENK
       EUIwBAI5ywRlyhAEHFKKEEIgEMgJyiwUBAGHnCKEEAyBQM4yy5RhCDikFDBI
       SSCQExRKwxBDjAGHgEFKQyCQk9YgxBBjDAGDnAQCOWkNQgwxxDgwyGkIBHJS
       GoQQYohRYJDTEAjkpDWIIYQQBQY5A4FATlqDEEIMgWCQMxgCgZy0BiikRDDI
       GQyBQE5aAxRSIhjkNIRAICetAQop04BBTgOBnLTKIIQQacAgZzAQyEkrCEII
       kQYMckoDgZy0giCESAMGOaWBQMoydeeUQYhUYJBTGgikLHNOGYRACQY5pYFA
       yjLnnEGgNGCQMxgAACgFAjnpFEUNGOQ0BgI5Z6FUFlVgkJNAICctlMqiyggB
       BkMIBHLOUiidSUEiJwRyzlIopbJQSilFURJUIJCTVntlKhhjCwsEctJqr0wF
       Y0xhBAA7
    }
image create photo iconCert_32x32 -data {
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
} -gamma 1.0 -height 0 -width 0

    # Make a class binding to do some housekeeping
    bind Wizard <Destroy> [list ${ns}::wizard-destroy %W]
}

# usage: tkwizard ?-showhelp boolean? ?-title string? 
proc tkwizard::tkwizard {name args} {

    set showHelp 0
    set body {}

    set i 0
    while {$i < [llength $args]} {
        set arg [lindex $args $i]
        switch -glob -- $arg {
            -showhelp {
                incr i
                set showHelp [lindex $args $i]
            }
            -title {
                incr i
                set title [lindex $args $i]
            }
            default {
                return -code error "unknown option \"$arg\" (!)"
            }
        }
        incr i
    }
            
    if {![info exists title]} {set title $name}

    init $name $showHelp $title

    return $name
}

##
# wizard-destroy
#
# does cleanup of the wizard when it is destroyed. Specifically,
# it destroys the associated namespace
# 
proc tkwizard::wizard-destroy {name} {

    upvar #0 [namespace current]::@$name-state wizState

    if {![info exists wizState]} {
        return -code error "unknown wizard \"$name\""
    }
    set w $wizState(window)
    interp alias {} $wizState(alias) {}
    catch {namespace delete $wizState(namespace)} message

    return ""
}


# intended for an end user to draw a step for the purpose
# of measuring it's size. Not fully realized yet; it seems to 
# put the wizard in a slightly weird state
proc tkwizard::wizProx-drawstep {name stepname} {

    upvar #0 [namespace current]::@$name-state wizState
    upvar #0 [namespace current]::@$name-config wizConfig
    upvar #0 [namespace current]::@$name-stepData wizStepData

    # First, build the appropriate layout...
    set layout $wizStepData($stepname,layout)
    buildLayout $name $layout

    # then build the step...
    set wizConfig(-step) $stepname
    buildStep $name $stepname
}

##
# 
proc tkwizard::wizProc-cget {name args} {
    upvar #0 [namespace current]::@$name-config wizConfig

    if {[llength $args] != 1} {
        return -code error "wrong \# args: should be \"$name cget option\""
    }
    set option [lindex $args 0]
    if {[info exists wizConfig($option)]} {
        return $wizConfig($option)
    } 
    return -code error "unknown option \"$option\""
}

proc tkwizard::wizProc-configure {name args} {
    upvar #0 [namespace current]::@$name-config wizConfig

    if {[llength $args] == 0} {
        set result [list]
        foreach item [lsort [array names wizConfig]] {
            lappend result $item $wizConfig($item)
        }
        return $result

    } elseif {[llength $args] == 1} {
        uplevel $name cget [lindex $args 0]

    } else {
        foreach {option value} $args {
            if {![info exists wizConfig($option)]} {
                return -code error "unknown option \"$option\""
            }
            set wizConfig($option) $value
            switch -exact -- $option {
                -background {
                    $wizConfig(toplevel) configure -background $value
                    # in theory we should step through all widgets,
                    # changing their color as well. Maybe I generate
                    # a virtual event like <<WizConfigure>> so the
                    # programmer can reconfigure their steps appropriately
                }
                -title {
                    wm title $w $value
		    wm iconphoto $w iconCert_32x32
                }
            }
        }
    }
}

##
# wizProc
#
# this is the procedure that represents the wizard object; each
# wizard will be aliased to this proc; the wizard name will be
# provided as the first argument (this is transparent to the caller)

proc tkwizard::wizProc {name command args} {
    # define the state variable here; that way the worker procs
    # can do an uplevel to access the variable with a simple name
    variable @$name-state

    # call the worker proc
    eval wizProc-$command $name $args
}

##
# wizProc-hide
#
# usage: wizHandle hide
#
# hides the wizard without destroying it. Note that state is NOT
# guaranteed to be preserved, since a subsequent "show" will reset
# the state. 

proc tkwizard::wizProc-hide {name args} {
    upvar #0 [namespace current]::@$name-state wizState
    place forget $name
    tk busy forget .cm.mainfr
    menu_enable
}

##
# wizProc-order
#
# usage: wizHandle order ?-nocomplain? ?step step ...?
#
# example: wizHandle order step1 step2 step3 finalStep
#
# unless -nocomplain is specified, will throw an error if
# a nonexistent step is given, or if a duplicate step is
# given.
#
# without any steps, will return the current order

proc tkwizard::wizProc-order {name args} {
    upvar #0 [namespace current]::@$name-state wizState

    set i [lsearch -exact $args "-nocomplain"]
    set complain 1

    if {$i >= 0} {
        set complain 0
        set args [lreplace $args $i $i]
    }

    if {$complain} {
        # make sure all of the steps are defined.  "defined" means
        # there is a initialize proc for that step. We also need to
        # make sure we don't have the same step represented twice.
        # This is inefficient, but speed isn't particularly critical
        # here
        array set found [list]
        foreach step $args {
            set tmp [info commands $wizState(namespace)::initialize-$step]
            if {[llength $tmp] != 1} {
                return -code error "unknown step \"$step\""
            }
            if {[info exists found($step)]} {
                return -code error "duplicate step \"$step\""
            }
            set found($step) 1
        }
    }

    if {[llength $args] == 0} {
        return $wizState(steps)
    } else {
        set wizState(steps) $args
    }
}

##
# wizProc-step
#
# implements the "step" method of the wizard object. The body
# argument is code that will be run when the step identified by
# 'stepName' is to be displayed in the wizard
#
# usage: wizHandle step stepName ?-layout layout? body
#

proc tkwizard::wizProc-step {name stepName args} {

    upvar #0 [namespace current]::@$name-state wizState
    upvar #0 [namespace current]::@$name-stepData wizStepData

    set body [lindex $args end]
    set args [lreplace $args end end]
#    set args [lrange $args 0 end-1]

    set layout "basic"
    set i [lsearch -exact $args {-layout}]
    if {$i >= 0} {
        set j [expr {$i + 1}]
        set layout [lindex $args $j]
        if {[llength [info commands [namespace current]::buildLayout-$layout]] == 0} {
            return -code error "unknown layout \"$layout\""
        }
        set args [lreplace $args $i $j]
    }
    set wizStepData($stepName,layout) $layout

    lappend wizState(steps) $stepName

    set procname "[namespace current]::${name}::initialize-$stepName"
    proc $procname {} "[list set this $name];\n$body"
}

##
# wizProc-widget
#
# Returns the path to an internal widget, or executes the
# an internal widget command
#
# usage: wizHandle widget widgetName ?args?
#
# if [llength $args] > 0 it will run the widget command with
# the args. Otherwise it will return the widget path

proc tkwizard::wizProc-widget {name args} {
    upvar #0 [namespace current]::@$name-state wizState

    if {[llength $args] == 0} {
        # return a list of all widget names
        set result [list]
        foreach item [array names wizState widget,*] {
            regsub {widget,} $item {} item
            lappend result $item
        }
        return $result
    }

    set widgetname [lindex $args 0]
    set args [lrange $args 1 end]

    if {![info exists wizState(widget,$widgetname)]} {
        return -code error "unknown widget: \"$widgetname\""
    }

    if {[llength $args] == 0} {
        return $wizState(widget,$widgetname)
    }

    # execute the widget command
    eval [list $wizState(widget,$widgetname)] $args
}

##
# wizProc-info
#
# Returns the information in the state array
# 
# usage: wizHandle info

proc tkwizard::wizProc-info {name args} {

    if {[llength $args] > 0} {
        return -code error "wrong \# args: should be \"$name info\""
    } 
    upvar #0 [namespace current]::@$name-state wizState

    foreach item [lsort [array names wizState]] {
        puts "$item = $wizState($item)"
    }
}

# return the namespace of the wizard
proc tkwizard::wizProc-namespace {name} {
    set ns [namespace current]::${name}
    return $ns
}

# execute the code in the namespace of the wizard
proc tkwizard::wizProc-eval {name code} {
    set ns [namespace current]::${name}
    namespace eval $ns $code
}
    
##
# wizProc-show
# 
# Causes the wizard to be displayed in it's initial state
#
# usage: wizHandle show
#
# This is where all of the widgets are created, though eventually
# I'll probably move the widget drawing to a utility proc...

proc tkwizard::wizProc-show {name args} {

    upvar #0 [namespace current]::@$name-state wizState
    upvar #0 [namespace current]::@$name-config wizConfig

    # initialize the remainder of the wizard state
    set wizState(history)         [list]
    set wizConfig(-previousstep)  ""
    set wizConfig(-nextstep)      ""

    set steps $wizState(steps)
    if {[llength $steps] == 0} {
        # no steps? Just show it as-is.
        wm deiconify $name
        return
    }

    # set a trace on where we store the next state. The trace
    # will cause the next and previous buttons to become
    # enabled or disabled. Thus, within a step a programmer can
    # decide when to enable or disable the buttons by merely 
    # setting these variables.
    set code [namespace code "varTrace [list $name]"]
    set stateVar "[namespace current]::@$name-config"
    foreach item {-previousstep -nextstep -state -complete} {
        trace vdelete  ${stateVar}($item) wu $code
        trace variable ${stateVar}($item) wu $code
    }

    # show the first step
    set wizState(history) [lindex $steps 0]
    showStep $name 

    # make it so, Number One
    update idletasks
    tk busy hold .cm.mainfr
    menu_disable
    place $name -in .cm.mainfr.ff.notbok -x 1 -y 0  -relwidth 0.998  -relheight 1.0
    raise $name
    return ""
}

# This gets called whenever certain parts of our state variable
# get set or unset (presently this only happens with -nextstep 
# and -previousstep)
proc tkwizard::varTrace {name varname index op} {
    upvar #0 [namespace current]::@$name-state wizState
    upvar #0 [namespace current]::@$name-config wizConfig

    catch {
        switch -- $index {
            -state {
                set state $wizConfig(-state)
                if {[string equal $state "normal"]} {
#                    $name configure -cursor {}
                    if {[string length $wizConfig(-previousstep)] == 0} {
                        $wizState(widget,backButton) configure -state disabled
                    } else {
                        $wizState(widget,backButton) configure -state normal
                    }
                    if {[string length $wizConfig(-nextstep)] == 0} {
                        $wizState(widget,nextButton) configure -state disabled
                    } else {
                        $wizState(widget,nextButton) configure -state normal
                    }
                    if {$wizConfig(-complete)} {
                        $wizState(widget,finishButton) configure -state normal
                    } else {
                        $wizState(widget,finishButton) configure -state disabled
                    }

                } else {
                    $wizState(widget,cancelButton) configure -cursor left_ptr
                    $wizState(widget,nextButton)   configure -state disabled
                    $wizState(widget,backButton)   configure -state disabled
                    $wizState(widget,helpButton)   configure -state disabled
                    $wizState(widget,finishButton) configure -state disabled
                }
            }
            -complete {
                if {$wizConfig(-complete)} {
                    $wizState(widget,finishButton) configure -state normal
                } else {
                    $wizState(widget,finishButton) configure -state disabled
                }
            }

            -previousstep {
                set state normal
                if {[string length $wizConfig(-previousstep)] == 0} {
                    set state disabled
                }
                $wizState(widget,backButton) configure -state $state
            }
            -nextstep {
                set state normal
                if {[string length $wizConfig(-nextstep)] == 0} {
                    set state disabled
                }
                $wizState(widget,nextButton) configure -state $state
            }

            default {
                puts "bogus variable trace: name=$varname index=$index op=$op"
            }
        }
    }
}

# Causes a step to be built by clearing out the current contents of
# the client window and then executing the initialization code for
# the given step

proc tkwizard::buildStep {name step}  {
    upvar #0 [namespace current]::@$name-state wizState

    # reset the state of the windows in the wizard
    eval destroy [winfo children $wizState(widget,clientArea)]
#    wizProc-stepconfigure $name -title "" -subtitle "" -pretext "" -posttext ""

    namespace eval $wizState(namespace) initialize-$step 

}


# This block of code is common to all wizard actions. 
# (ie: it is the target of the -command option for wizard buttons)
proc tkwizard::cmd {command name} {

    upvar #0 [namespace current]::@$name-state wizState
    upvar #0 [namespace current]::@$name-config wizConfig
#puts "tkwizard::cmd=$command ;name=$name"

#        Next       {puts "tkwizard::cmd=$command";tkwizard::handleEvent .cm$name "<<WizNextStep>>";puts "tkwizard::cmd=END"}
#OK?        Next       {puts "tkwizard::cmd=$command";tkwizard::handleEvent $name "<<WizNextStep>>";puts "tkwizard::cmd=END"}
#        Previous   {tkwizard::handleEvent $name "<<WizPrevStep>>"}
#        Cancel	   {tkwizard::wizProc-hide $nameN}
    switch $command {
        Help       {event generate $name <<WizHelp>>}
        Next       {event generate $name <<WizNextStep>>}
        Previous   {event generate $name <<WizPrevStep>> ;tkwizard::handleEvent $name <<WizPrevStep>>}
        Finish     {event generate $name <<WizFinish>>}
        Cancel     {event generate $name <<WizCancel>>}

        default {
            puts "'$command' not implemented yet"
        }
    }
    return
#        Next       {puts "tkwizard::cmd=$command";event generate $nameN <<WizNextStep>>;puts "tkwizard::cmd=END"}
#{}

    switch $command {
        Help       {event generate $name <<WizHelp>>}
        Next       {event generate $name <<WizNextStep>>}
        Previous   {event generate $name <<WizPrevStep>>}
        Finish     {event generate $name <<WizFinish>>}
        Cancel     {event generate $name <<WizCancel>>}

        default {
            puts "'$command' not implemented yet"
        }
    }
}

proc tkwizard::handleEvent {name event} {
#puts "tkwizard::handleEvent=$name"

    upvar #0 [namespace current]::@$name-state wizState
    upvar #0 [namespace current]::@$name-config wizConfig
    upvar #0 [namespace current]::@$name-stepData wizStepData
    switch $event {
        <<WizHelp>> {
            # not implemented yet
        }

        <<WizNextStep>> {
#puts "tkwizard::handleEvent=WizNextStep; name=$name"
            set thisStep [lindex $wizState(history) end]
            lappend wizState(history) $wizConfig(-nextstep)
            showStep $name 
        }

        <<WizPrevStep>> {
#puts "tkwizard::handleEvent=WizPrevStep; name=$name"
#puts "History=$wizState(history)"
            # pop an item off of the history

            set p [expr {[llength $wizState(history)] -2}]
            set wizState(history) [lrange $wizState(history) 0 $p]
            showStep $name 
        }

        <<WizFinish>> {

            set thisStep [lindex $wizState(history) end]
            wizProc-hide $name
        }

        <<WizCancel>> {

            wizProc-hide $name
        }

        default {
            puts "'$event' not implemented yet"
        }
    }
}

proc tkwizard::showStep {name} {
#puts "tkwizard::showStep=$name"
    upvar #0 [namespace current]::@$name-state wizState
    upvar #0 [namespace current]::@$name-config wizConfig
    upvar #0 [namespace current]::@$name-stepData wizStepData

    # the step is whatever is at the tail end of our 
    # history
    set step [lindex $wizState(history) end]
    set proc "initialize-$step"
    set wizConfig(-step) $step

    set layout $wizStepData($step,layout)

    # First, build the appropriate layout...
    buildLayout $name $layout

    # then build the step...
    set steps $wizState(steps)
    set lastStep [expr {[llength $steps] -1}]
    set stepIndex [lsearch $steps $step]
    set prevIndex [expr {$stepIndex -1}]
    set nextIndex [expr {$stepIndex + 1}]

    # initialize the next, previous and current step configuration
    # options; this will set the state of the next/previous buttons.
    # note that the user can retrieve these values with the normal
    # 'cget' and 'configure' methods
    set p [expr {[llength $wizState(history)] -2}]
    set wizConfig(-previousstep) [lindex $wizState(history) $p]
    set wizConfig(-nextstep) [lindex $steps $nextIndex]

    if {$stepIndex == ([llength $steps]-1)} {
        set wizConfig(-complete) 1
    } else {
        set wizConfig(-complete) 0
    }

    buildStep $name $step

}


proc tkwizard::init {name showHelp title} {

    # name should be a widget path
    set w $name

    # create variables in this namespace to keep track
    # of the state of this wizard. We do this here to 
    # avoid polluting the namespace of the widget. We'll
    # create local aliases for the variables to make the
    # code easier to read and write

    # this variable contains state information about the 
    # wizard, such as the wizard title, the name of the 
    # window and namespace associated with the wizard, the
    # list of steps, and so on.
    variable "@$name-state"
    upvar \#0 [namespace current]::@$name-state wizState

    # this variable contains all of the parameters associated
    # with the wizard and settable with the "configure" method
    variable "@name-config"
    upvar \#0 [namespace current]::@$name-config wizConfig

    # this is an experimental array containing data of known
    # step types. Presently not being used.
    variable "@name-stepTypes"
    upvar \#0 [namespace current]::@$name-stepTypes wizStepTypes

    # this contains step-specific data, such as the step title
    # and subtitle, icon, etc. All elements are unset prior to
    # rendering a given step. It is each step's responsibility
    # to set it appropriately, and it is each step type's 
    # responsibility to use the data.
    variable "@name-stepData"
    upvar \#0 [namespace current]::@$name-stepData  wizStepData

    # do some state initialization; more will come later when
    # the wizard is actually built
    set wizConfig(-complete)      0
    set wizConfig(-state)         normal
    set wizConfig(-title)         $title
    set wizConfig(-nextstep)      ""
    set wizConfig(-previousstep)  ""
    set wizConfig(-step)          ""
    set wizConfig(-showhelp)      $showHelp

    set wizState(title)        $title
    set wizState(window)       $w
    set wizState(steps)        [list]
    set wizState(namespace)    [namespace current]::$name
    set wizState(name)         $name
    set wizState(toplevel)     {}

    # create the wizard (except for the step pages...)
    buildDialog $name

    # this establishes a namespace for this wizard; this namespace
    # will contain wizard-specific data managed by the creator of
    # the wizard
    namespace eval $name {}

    # this creates the instance command by first renaming the widget
    # command associated with our toplevel, then making an alias 
    # to our own command
    set wizState(toplevel) $wizState(namespace)::originalWidgetCommand

    rename "$w" $wizState(toplevel)
    interp alias {} ::$w {} [namespace current]::wizProc $name
    set wizState(alias) ::$w

    # set some useful configuration values
    set wizConfig(-background) \
        [$wizState(namespace)::originalWidgetCommand cget -background]

}
#Упаковка: Виджет с титулом, основным полем и кнопками
proc tkwizard::buildDialog {name} {
#puts "tkwizard::buildDialog name=$name"
    upvar #0 [namespace current]::@$name-state wizState
    upvar #0 [namespace current]::@$name-config wizConfig
    set prefix [string trimright $wizState(window) .]

    set wizState(widget,topframe)     $prefix.topframe
    set wizState(widget,sep1)         $prefix.sep1
    set wizState(widget,sep2)         $prefix.sep2
    set wizState(widget,buttonFrame)  $prefix.buttonFrame
    set wizState(widget,helpButton)   $prefix.buttonFrame.helpButton
    set wizState(widget,nextButton)   $prefix.buttonFrame.nextButton
    set wizState(widget,backButton)   $prefix.buttonFrame.backButton
    set wizState(widget,cancelButton) $prefix.buttonFrame.cancelButton
    set wizState(widget,finishButton) $prefix.buttonFrame.finishButton
    set wizState(widget,layoutFrame)  $prefix.layoutFrame

    if {![winfo exists ".cm"]} {
	frame ".cm" -bd 2 -padx 1 -pady 1 -background #cdc7c2
	pack .cm -fill both -expand 1
#	toplevel ".cm" -bd 2 -padx 1 -pady 1 -background #cdc7c2
	#c0bab4
    }

    # create the toplevel window
    set w $wizState(window)

    labelframe  $w -labelanchor n -bd 0 -relief flat -background #e0e0da -padx 0 -pady 0
    $w configure -text $wizConfig(-title)

    # the dialog is composed of two areas: the row of buttons and the
    # area with the dynamic content. To make it look the way we want it to
    # we'll use another frame for a visual separator
    frame $wizState(widget,buttonFrame) -relief flat  -highlightthickness 0 -bg #eff0f1  -highlightbackground #c0bab4
#    ttk::frame $wizState(widget,buttonFrame) -style butFr.TFrame -relief groove 

#    $wizState(widget,buttonFrame) configure -style butFr.TFrame
    frame $wizState(widget,layoutFrame) -bd 0
    frame $wizState(widget,sep1) -class WizSeparator -height 2 -bd 0 -relief flat -bg #c0bab4
    pack $wizState(widget,buttonFrame) -side bottom -fill x -padx 0 -pady 0
    pack $wizState(widget,sep1)  -side bottom -fill x -pady 0
    pack $wizState(widget,layoutFrame) -side top -fill both -expand 1

    # make all of the buttons
    ttk::button $wizState(widget,helpButton) \
        -text "What's This?" \
        -default normal \
        -command [namespace code "cmd Help [list $name]"] \
	-style MyBorder.TButton

if {$name != ".cm.opendb" } {
    ttk::button $wizState(widget,backButton) \
        -text "< Пред" \
        -default normal \
        -width 8 \
        -command [namespace code "cmd Previous [list $name]"] \
	-style MyBorder.TButton

    ttk::button $wizState(widget,nextButton) \
        -text "След >" \
        -default normal \
        -width 8 \
        -command [namespace code "cmd Next [list $name]"] \
	-style MyBorder.TButton
}

    ttk::button $wizState(widget,finishButton) \
        -text "Готово" \
        -default normal \
        -width 8 \
        -command [namespace code "cmd Finish [list $name]"] \
	-style MyBorder.TButton
if {$name == ".cm.exportp12wizard" || $name == ".cm.certificatewizard" || $name == ".cm.signwizard"} {
eval "    ttk::button $wizState(widget,cancelButton) \
        -text {Отмена}   \
        -default normal \
        -width 8 \
        -command {global dbca;place forget $name;tk busy forget .cm.mainfr;menu_enable;set dbca {.cm}}" \
	-style MyBorder.TButton
#        -command {global dbca;wm state .opendb withdraw;wm state .cm normal;set dbca ".cm"}
} elseif {$name == ".cm.opendb"} {
    eval "    ttk::button $wizState(widget,cancelButton) \
        -text {Отмена}   \
        -default normal \
        -width 8 \
        -command {global dbca;place forget $name;tk busy forget .cm.mainfr;set dbca {.cm}}" \
	-style MyBorder.TButton
} else {
    ttk::button $wizState(widget,cancelButton) \
        -text "Отмена"   \
        -default normal \
        -width 8 \
        -command [namespace code "cmd Cancel [list $name]"] \
	-style MyBorder.TButton
}

    # pack the buttons
    if {$wizConfig(-showhelp)} {
        pack $wizState(widget,helpButton) -side left -padx 4 -pady 8
    }
    pack $wizState(widget,cancelButton) -side right -padx 4 -pady 8
    pack $wizState(widget,finishButton) -side right -pady 8 -padx 4
if {$name != ".cm.opendb" } {
    pack $wizState(widget,nextButton) -side right -pady 8
    pack $wizState(widget,backButton) -side right -pady 8 -padx 8
}
    # return the name of the toplevel, for lack of a better idea...
#    return $wizState(window)
    return "$name"
}

proc tkwizard::buildLayout {name layoutName} {
    upvar #0 [namespace current]::@$name-state wizState
    upvar #0 [namespace current]::@$name-config wizConfig

    set w $wizState(window)
    set lf $wizState(widget,layoutFrame)

    # initialize the layout variables
    initLayout-$layoutName $name

    # if the layout hasn't actually been built yet, build it
    if {![winfo exists $lf.$layoutName]} {
        buildLayout-$layoutName $name
    }
    eval pack forget [winfo children $lf]
    pack $lf.$layoutName -side top -fill both -expand y

}

# this is a user-callable interface to configureLayout-<layout>
proc tkwizard::wizProc-stepconfigure {name args} {
    upvar #0 [namespace current]::@$name-state wizState
    upvar #0 [namespace current]::@$name-config wizConfig
    upvar #0 [namespace current]::@$name-stepData wizStepData

    set step $wizConfig(-step)
    set layout $wizStepData($step,layout)
    eval configureLayout-$layout $name $args
}


# this defines the widget paths. Will be called each time we
# switch layouts
proc tkwizard::initLayout-basic {name} {
    upvar #0 [namespace current]::@$name-state wizState
    upvar #0 [namespace current]::@$name-config wizConfig

    set layout $wizState(widget,layoutFrame).basic
    set wizState(widget,clientArea)   $layout.clientArea
    set wizState(widget,icon)         $layout.icon
    set wizState(widget,title)        $layout.title
    set wizState(widget,subtitle)     $layout.subtitle
    set wizState(widget,pretext)      $layout.pretext
    set wizState(widget,posttext)     $layout.posttext

}

proc tkwizard::buildLayout-basic {name} {
    upvar #0 [namespace current]::@$name-state wizState
    upvar #0 [namespace current]::@$name-config wizConfig

    set layout $wizState(widget,layoutFrame).basic
#    ttk::frame $layout -class WizLayoutBasic -style ClientArea.TFrame
    ttk::frame $layout -class WizLayoutBasic -style basic.TFrame -relief flat
#    pack $layout
    #  -bg #e0e0da
#    frame $layout -class WizLayoutBasic  -bg #cdc7c2
    option add *WizLayoutBasic*Label.background	white interactive
#    option add *WizLayoutBasic*Label.background	39b5da interactive

    # using the option database saves me from hard-coding it for
    # every widget. I guess I'm just lazy.
    option add *WizLayoutBasic*Label.justify             left interactive
    option add *WizLayoutBasic*Label.anchor              nw   interactive
    option add *WizLayoutBasic*Label.highlightThickness  0    interactive
    option add *WizLayoutBasic*Label.borderWidth         0    interactive
    option add *WizLayoutBasic*Label.padX                5    interactive

    # Client area. This is where the caller places its widgets.
    ttk::frame $wizState(widget,clientArea) -style area.TFrame 
#    ttk::frame $wizState(widget,clientArea) -style butFr.TFrame 
    #-style ClientArea.TFrame
#    $wizState(widget,clientArea) configure -style ClientArea.TFrame
#    frame $wizState(widget,clientArea)  -bd 8 -relief flat -bg #e0e0da

#    ttk::frame $layout.sep1
    # -height 2 -borderwidth 4 -relief solid
    frame $layout.sep1 -class WizSeparator -height 2 -bd 0 -relief flat -bg #c0bab4

#    ttk::separator $layout.sep1 -orient horizontal -style sep1.TSeparator
#    $layout.sep1 configure -style sep1.TSeparator
#    $layout.sep1 configure -style sep.TFrame

    # title and subtitle and icon
#    frame $layout.titleframe -bd 4 -relief groove -background #550000
    ttk::frame $layout.titleframe -relief flat -style title.TFrame 
#    $layout.titleframe configure -style butFr.TFrame
    #ClientArea.TFrame
    #white
#    label $wizState(widget,title) -background white -width 40
    ttk::label $wizState(widget,title) -style labTit.TLabel
#    label $wizState(widget,subtitle) -height 2 -background red -padx 15 
    #   -width 40
    ttk::label $wizState(widget,subtitle) -style Label.TLabel
#    -height 2 -background white -padx 15   -width 40
    label $wizState(widget,icon) \
        -borderwidth 0 \
        -image [namespace current]::feather \
        -background #eff0f1 \
        -anchor c
#        -background white 
#        -background #e0e0da 


#    set labelfont [font actual [$wizState(widget,title) cget -font]]
    set labelfont [font actual [$wizState(widget,icon) cget -font]]
    $wizState(widget,title) configure -font [concat $labelfont -weight bold]

    # put the title, subtitle and icon inside the frame we've
    # built for them
    set tf $layout.titleframe
#    pack $top.tFr62 
#		-in $top -anchor center -expand 0 -fill both -side top 
    pack $wizState(widget,icon) -anchor center -expand 0 -fill y -side right -padx 8 -pady 5 \
		-in $layout.titleframe 
    pack $wizState(widget,title)  -anchor center -expand 1 -fill both -side top -padx 8 -pady 5 \
		-in $layout.titleframe
    pack $wizState(widget,subtitle)  -anchor center -expand 1 -fill both -side top -padx 8 -pady 5 \
		-in $layout.titleframe

    
    
#    grid $wizState(widget,title)    -in $tf -row 0 -column 0 -sticky nsew
#    grid $wizState(widget,subtitle) -in $tf -row 1 -column 0 -sticky nsew
#    grid $wizState(widget,icon)     -in $tf -row 0 -column 1 -rowspan 2 -padx 8
#    grid columnconfigure $tf 0 -weight 1
#    grid columnconfigure $tf 1 -weight 0

    # pre and post text. We'll pick rough estimates on the size of these
    # areas. I noticed that if I didn't give it a width and height and a
    # step defined a really, really long string, the label would try to
    # accomodate the longest string possible, making the widget unnaturally
    # wide.

    ttk::label $wizState(widget,pretext) -style Label.TLabel
#    label $wizState(widget,pretext)  -width 40 -anchor c
    ttk::label $wizState(widget,posttext) -style Label.TLabel
#    label $wizState(widget,posttext) -width 40 -anchor c
    # when our label widgets change size we want to reset the
    # wraplength to that same size.
    foreach widget {title subtitle pretext posttext} {
        bind $wizState(widget,$widget) <Configure> {
            # yeah, I know this looks weird having two after idle's, but
            # it helps prevent the geometry manager getting into a tight
            # loop under certain circumstances
            #
            # note that subtracting 10 is just a somewhat arbitrary number
            # to provide a little padding...
            after idle {after idle {%W configure -wraplength [expr {%w -10}]}}
        }
    }
    
if {$wizState(widget,pretext) == 0} {
    grid $layout.titleframe            -row 0 -column 0 -sticky nsew -padx 0

    grid $layout.sep1                 -row 1 -sticky ew 
    grid $wizState(widget,pretext)    -row 2 -sticky nsew -pady 8 -padx 8
    grid $wizState(widget,clientArea) -row 3 -sticky nsew -padx 8 -pady 8
    grid $wizState(widget,posttext)   -row 4 -sticky nsew -pady 8 -pady 8

    grid columnconfigure $layout 0 -weight 1
    grid rowconfigure $layout 0 -weight 0
    grid rowconfigure $layout 1 -weight 0
    grid rowconfigure $layout 2 -weight 0
    grid rowconfigure $layout 3 -weight 1
    grid rowconfigure $layout 4 -weight 0
}
    pack $layout.titleframe    -padx 0 -fill both -padx 6 -pady 6

    pack $layout.sep1 -fill x 
pack $wizState(widget,pretext) -fill x -side top -pady 8 -padx 8
#    pack $wizState(widget,pretext)  -pady 8 -padx 8 -fill x -side top -expand 1
    pack $wizState(widget,clientArea) -padx 8 -pady 8 -fill both -side top -expand 1
#    pack $wizState(widget,posttext) -pady 8 -pady 8 -fill x -side bottom -expand 1
#pack $wizState(widget,pretext) $wizState(widget,clientArea) $wizState(widget,posttext) -in $layout -side top -padx 8 -pady 8 -fill both
pack $wizState(widget,posttext) -fill x -side top -padx 8 -pady 8

    # the pre and post text will initially not be visible. They will pop into
    # existence if they are configured to have a value
#    grid remove $wizState(widget,pretext) $wizState(widget,posttext)
#    pack forget $wizState(widget,pretext) $wizState(widget,posttext)

}
###############

# usage: configureLayout-basic ?-title string? ?-subtitle string? ?-icon image?
proc tkwizard::configureLayout-basic {name args} {
    upvar #0 [namespace current]::@$name-state wizState
    upvar #0 [namespace current]::@$name-config wizConfig

    if {[llength $args]%2 == 1} {
        return -code error "wrong number of args..."
    }

    foreach {option value} $args {
        switch -- $option {
            -title {
                $wizState(widget,title) configure -text "$value" -background #e0e0da
#                $wizState(widget,title) configure -text "$value" -background #eff0f1
            }

            -subtitle {
#                $wizState(widget,subtitle) configure -text $value
                $wizState(widget,subtitle) configure -text $value
            }

            -icon {
                $wizState(widget,icon) configure -image $icon
            }

            -pretext {
#                $wizState(widget,pretext) configure -text $value -background #eff0f1
                $wizState(widget,pretext) configure -text $value -background #e0e0da
                if {[string length $value] > 0} {
                    pack $wizState(widget,pretext)
#                    grid $wizState(widget,pretext)

                } else {
                    pack remove $wizState(widget,pretext)
#                    grid remove $wizState(widget,pretext)
                }
            }

            -posttext {
#                $wizState(widget,posttext) configure -text $value -background #eff0f1
                $wizState(widget,posttext) configure -text $value -background #e0e0da
                if {[string length $value] > 0} {
                    pack $wizState(widget,posttext)
#                    grid $wizState(widget,posttext)
                } else {
                    pack remove $wizState(widget,posttext)
#                    grid remove $wizState(widget,posttext)
                }
            }

            default {
                return -code error "unknown option \"$option\""
            }
        }
    }
}

######################################
# SetupWizard
#
# Wizard that collects information to setup the CA
#
#

lappend auto_path .
package require tkwizard
package require openssl

tkwizard::tkwizard .cm.setupwizard -title "Разворачивание нового УЦ"

.cm.setupwizard eval {
    variable wizData

    # default values
    catch {unset wizData}
    array set wizData {
        type "pers"
        O ""
        OU ""
        C ""
        ST ""
        L ""
        CN ""
        INN ""
        street ""
        OGRN ""
        OGRNIP ""
        unstructuredName ""
        emailAddress ""
        capassword ""
        capassword2 ""
        opensslexec ""
        exit "cancel"
        dir_ca ""
	system.ckzi ""
	system.kc12 ""
	system.cafl63 ""
	system.certckzi ""
	system.certca ""
    }
    [namespace current]::originalWidgetCommand configure  -font {Times 11 bold}
}

bind .cm.setupwizard <<WizFinish>> {[%W namespace]::finalize}
bind .cm.setupwizard <<WizCancel>> {[%W namespace]::cancel}
bind .cm.setupwizard <<WizNextStep>> {[%W namespace]::nextStep %W}

.cm.setupwizard step {dirname} -layout basic {
    variable wizData
    global env
    global home

    # use nice icon
    $this widget icon configure -image img_cert  -background white
        
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Выбор каталога для БД УЦ} \
            -subtitle {Выберите каталог для БД УЦ} \
            -pretext {Введите каталог и пароль для доступа к БД.} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 

    label $c.l1 -text "Каталог БД УЦ:"
    cagui::FileEntry $c.e1 \
            -dialogtype directory \
            -variable [namespace current]::wizData(dir_ca) \
            -title "Выберите каталог для БД УЦ" \
            -initialdir $env(HOME) \
            -parent ".cm"
    $c.e1 configure  -background white
#Подключаем файловый проводник FE
    eval "$c.e1.but configure -command {feselect dir {.cm} window {Выберите каталог для БД УЦ} $home {[namespace current]::wizData(dir_ca)} {}}"

    label $c.l0  -image db_build_40x40 -compound left -bg white
    grid $c.l0 -row 0 -column 0 -columnspan 2 -sticky w -padx 2mm -pady 3mm



    label $c.l2 -text "Пароль для БД УЦ:"
    ttk::entry $c.e2 -width 40 -show * -textvariable [namespace current]::wizData(capassword) 
    
    label $c.l3 -text "Повторите пароль:"
    ttk::entry $c.e3 -width 40 -show * -textvariable [namespace current]::wizData(capassword2)

    grid $c.l1 -row 1 -column 0 -sticky w -padx 4 -pady {5mm 1mm}
    grid $c.e1 -row 1 -column 1 -sticky news -padx {4 5mm} -pady {5mm 1mm}
    grid columnconfigure $c 1 -weight 1
    grid $c.l2 -row 2 -column 0 -sticky w -padx 4 -pady 1mm
    grid $c.e2 -row 2 -column 1 -sticky w -padx 4 -pady 1mm
    grid $c.l3 -row 3 -column 0 -sticky w -padx 4 -pady 1mm
    grid $c.e3 -row 3 -column 1 -sticky w -padx 4 -pady 1mm

    focus $c.e1.entry
}

.cm.setupwizard step {setup} -layout basic {
    variable wizData
    global defaultkey
    global defaultpar
    set defaultkey gost2012_256
    set defaultpar "1.2.643.2.2.36.0"
    # use nice icon
    $this widget icon configure -image img_cert -background #eff0f1

    set c [$this widget clientArea]

    $this stepconfigure \
        -title {Установка УЦ} \
        -subtitle {Создание корневого сертификата} \
        -pretext {Добро пожаловать в УЦ ФЗ-63. Для того, чтобы он начал работать необходимо создать корневой сертификат.} \
        -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
#=================
    #Type Key
    # combo box
    set f $c
    label $f.lkey -text "Тип ключа:"
    set listKey {gost2012_256 gost2012_512 RSA gost2001}
    ttk::combobox $f.ckey -width 20  -textvariable ::ProfileDialog::prof(req.default_key.selected) -values $listKey
    $f.ckey delete 0 end
    $f.ckey insert end $defaultkey
    bind $f.ckey <<ComboboxSelected>> {ProfileDialog::keyParam %W f $::ProfileDialog::prof(req.default_key.selected);puts $::ProfileDialog::prof(req.default_key.selected)}
    # combo box
    set listBits {}
    label $f.l2
if {$defaultkey == "RSA"} {
    $f.l2 configure -text "Key Size"
    # insert choices
    foreach v $opts(req.default_bits.options) {
	lappend listBits $v
    }
} elseif {$defaultkey == "gost2012_512"} {
    $f.l2 configure -text "Параметры ГОСТ-12-512:"
    set listBits {1.2.643.7.1.2.1.2.1 1.2.643.7.1.2.1.2.2 1.2.643.7.1.2.1.2.3}
} elseif {$defaultkey == "gost2012_256"} {
    $f.l2 configure -text "Параметры ГОСТ-12-256:"
    set listBits {1.2.643.2.2.35.1 1.2.643.2.2.35.2  1.2.643.2.2.35.3  1.2.643.2.2.36.0 1.2.643.2.2.36.1 1.2.643.7.1.2.1.1.1 1.2.643.7.1.2.1.1.2 1.2.643.7.1.2.1.1.3 1.2.643.7.1.2.1.1.4}
} else {
    $f.l2 configure -text "Параметры ГОСТ-2001:"
    set listBits {1.2.643.2.2.35.1 1.2.643.2.2.35.2  1.2.643.2.2.35.3  1.2.643.2.2.36.0 1.2.643.2.2.36.1}
}
    ttk::combobox $f.c1 -width 20  -textvariable ::ProfileDialog::prof(req.default_bits.selected) -values $listBits
    $f.c1 delete 0 end
if {$defaultkey == "RSA"} {
    set j 0
    foreach v $opts(req.default_bits.options) {
	if {$j == 1 } { 
	    $f.c1 insert end $v 
	    break    
	}
	incr j 
    }
} else {
    $f.c1 insert 0 $defaultpar
} 
    grid $f.lkey -row 1 -column 0 -sticky new -padx 8 -pady {5mm 1mm}
    grid $f.ckey -row 1 -column 1 -sticky w -padx 8 -pady {5mm 1mm}
    grid $f.l2 -row 2 -column 0 -sticky new -padx 8 -pady 1mm
    grid $f.c1 -row 2 -column 1 -sticky w -padx 8 -pady 1mm

    ttk::checkbutton $f.c2 -text "Allow Key Size Override" -variable input(keysize.override)
#    grid $f.c2 -row 3 -column 0 -columnspan 2 -sticky w -padx 8 -pady 8
    set ::ProfileDialog::input(formatKey.override) 0

#    grid columnconfigure $f 1 -weight 0
#    grid rowconfigure $f 0 -weight 0
}
            
            
.cm.setupwizard step {ca_name} -layout basic {
    variable wizData
    global rfregions
    
    set c [$this widget clientArea]

    $this stepconfigure \
            -title {Удостоверяющий Центр (УЦ)} \
            -subtitle {Формирование корневого сертификата УЦ} \
            -pretext {Пожалуйста, введите данные об организации, в которой разварачивается УЦ.} \
        -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
    $this configure -nextstep "ca_attr"

    label $c.l1 -text " 1. Страна:\n     (C)"
    set listC {}
    foreach v $::openssl::iso3166 {
	lappend listC $v
    }

    ttk::combobox $c.e1 -textvariable [namespace current]::wizData(C) -width 80 -values $listC
    $c.e1 delete 0 end
    set tekC [lsearch $listC {Российская Федерация}]
    $c.e1 insert 0 [lindex $listC $tekC]
    label $c.l2 -text " 2. Регион организации:\n     (ST)"
    ttk::combobox $c.e2 -textvariable [namespace current]::wizData(ST) -width 80 -values $rfregions
    $c.e2 delete 0 end
    set tekC [lsearch $rfregions {Московская область}]
    $c.e2 insert 0 [lindex $rfregions $tekC]
    label $c.l3 -text " 3. Организация:\n     (CN)"
    ttk::entry $c.e3 -textvariable [namespace current]::wizData(CN)

    label $c.l4 -text " 4. Населенный пункт:\n     {L}"
    ttk::entry $c.e4 -textvariable [namespace current]::wizData(L)
    label $c.l5 -text " 5. Улица, номер дома:\n     (street)"
    ttk::entry $c.e5 -textvariable [namespace current]::wizData(street) 

    grid $c.l1 -row 0 -column 0 -sticky w -padx 4 -pady {5mm 4}
    grid $c.e1 -row 0 -column 1 -sticky we -padx {4 5mm} -pady {5mm 4}
    grid $c.l2 -row 1 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e2 -row 1 -column 1 -sticky we -padx {4 5mm} -pady 4
    grid $c.l3 -row 2 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e3 -row 2 -column 1 -sticky we -padx {4 5mm} -pady 4
    grid $c.l4 -row 3 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e4 -row 3 -column 1 -sticky we -padx {4 5mm} -pady 4
    grid $c.l5 -row 4 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e5 -row 4 -column 1 -sticky we -padx {4 5mm} -pady 4
    grid columnconfigure $c 1 -weight 1
    focus $c.e3
}

.cm.setupwizard step {ca_attr} -layout basic {
    variable wizData
    global rfregions
        
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Информация о владельце УЦ} \
            -subtitle {Пожалуйста заполните следующие поля} \
            -pretext {Все эти данные войдут в ваш корневой сертификат и станут доступны всем, прежде всего получателям сертификатов на вашем УЦ. Все поля подлежат обязательному заполнению} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
    #$this configure -prevstep "type"
    #$this configure -nextstep "capasswd"
    
    label $c.l1 -text " 6.Наименование организации:\n     (O)"
    ttk::entry $c.e1 -width 40 -textvariable [namespace current]::wizData(O) 
    label $c.l2 -text " 7.Подразделение организации:\n     (OU)"
    ttk::entry $c.e2 -width 40 -textvariable [namespace current]::wizData(OU) 
    label $c.l3 -text " 8.ОГРН (13 символов):"
    
    set com "ttk::entry $c.e3 -width 40 -textvariable [namespace current]::wizData(OGRN) -validate key -validatecommand {Digit $c.e3 %i %P 13}  -style white.TEntry "
    set com1 [subst $com]
    eval $com1
    label $c.l4 -text " 9.ИНН (12 символов (слева два нуля)):"
    set com "ttk::entry $c.e4 -width 40 -textvariable [namespace current]::wizData(INN) -validate key -validatecommand {Digit $c.e4 %i %P 12}  -style white.TEntry"
    set com1 [subst $com]
    eval $com1

    label $c.l5 -text "10.Электронный почтовый адрес:\n     (emailAddress)"
    ttk::entry $c.e5  -textvariable [namespace current]::wizData(emailAddress) 
    
    grid $c.l1 -row 0 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e1 -row 0 -column 1 -sticky we -padx {4 5mm} -pady 4
    grid $c.l2 -row 1 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e2 -row 1 -column 1 -sticky we -padx {4 5mm} -pady 4
    grid $c.l3 -row 2 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e3 -row 2 -column 1 -sticky w -padx 4 -pady 4
    grid $c.l4 -row 3 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e4 -row 3 -column 1 -sticky w -padx 4 -pady 4
    grid $c.l5 -row 4 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e5 -row 4 -column 1 -sticky we -padx {4 5mm} -pady 4
    grid columnconfigure $c 1 -weight 1
    focus $c.e1
    
}

.cm.setupwizard step {opensslexec} -layout basic {
    variable wizData
    global env
    global home
    global typesys
    global defaultkey

    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Утилита OpenSSL} \
            -subtitle {Выберите утилиту OpenSSL.} \
            -pretext {Для УЦ ФЗ-63 требуется OpenSSL с поддержкой российской криптографиии. Пожалуйста, укажите путь к утилите OpenSSL, которую вы будете использовать.} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
    
    #upon setup we have not yet configured an open ssl program
    # lets try to find it
    if {![info exists wizData(opensslexec)] || $wizData(opensslexec) == ""} {
        foreach try [Config::Get system.openssl_locations] {
            if {[file isfile $try] && [file executable $try] && [lindex [exec $try version] 0]=="OpenSSL"} {
                set wizData(opensslexec) $try
                break;
            }
        }
    }
    
    set i 1
    set list [Config::Get system.tools]
    set f $c
    $f configure -pad 5
    foreach {label varname} $list {
        
        label $f.l$i -text "$label"
	if { $i > 1 } {
#	    puts "SYSTEM=$varname"
            set wizData($varname) [Config::Get $varname]
	    ttk::entry $f.e$i -textvariable [namespace current]::wizData($varname)
	    if {$defaultkey == "RSA"} {
		$f.e$i delete 0 end
	    }
        } else {
    	    cagui::FileEntry $f.e$i \
                -dialogtype open \
                -initialdir $env(HOME) \
                -variable [namespace current]::wizData(opensslexec) \
                -title "Выберите $label" \
            $f.e$i.entry configure -style red.TEntry
	    if {$typesys == "x11" } {
		eval "$c.e1.but configure -command {feselect open {.cm} window {Выберите $label} $home {[namespace current]::wizData(opensslexec)} {*openssl* *ssl* *.exe *}}"
	    }

    	    grid $f.l$i -row $i -column 0 -sticky w -pady {3mm 1mm} -padx 4 
    	    grid $f.e$i -row $i -column 1 -sticky nwse -padx {0 5mm} -pady {3mm 1mm}
    	    incr i
    	    continue
        }
	if {$defaultkey != "RSA"} {
    	    grid $f.l$i -row $i -column 0 -sticky w  -padx 4 -pady {0 1mm}
    	    grid $f.e$i -row $i -column 1 -sticky nwse  -padx {0 5mm} -pady {0 1mm}
        }
        incr i
        
    }
    grid columnconfigure $f 1 -weight 1
    set uu $wizData(opensslexec)
    $f.e1.entry delete 0 end
    $f.e1.entry insert end $uu
    focus $f.e1.entry

}


.cm.setupwizard step {final} -layout basic {
    variable wizData
    global certdb
    
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Настройка вашего УЦ} \
            -subtitle {Вы еще можете поменять настройки УЦ} \
            -pretext {Посмотрите на ваши настройки УЦ:} \
        -posttext {Нажмите "Готово" чтобы настройки УЦ вступили в силу}
    
    text $c.t1 -width 60 -heigh 15 -background white \
            -yscrollcommand [list $c.vsb set]  -font {Times 10 bold italic}
    ttk::scrollbar $c.vsb -orient vertical -command [list $c.t1 yview]
    
    set fnt(std) [$c.t1 cget -font]
    set fnt(bold) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] bold]
    $c.t1 tag configure bold -font $fnt(bold)
    
    $c.t1 insert end "Конфигурация УЦ:\n" bold
#    $c.t1 insert end "\n"
    $c.t1 insert end "Distinguished Name:\n" bold
#    $c.t1 insert end "\n"
    
    global profile_options
    array set opts [array get profile_options]
    
    array set opts [array get profile_options]

    foreach {field label} $opts(req.dn_fieldsCA) {
        if {[info exists wizData($field)] && $wizData($field)!= ""} {
            $c.t1 insert end "\t$label = $wizData($field)\n"
        }
    }
    
    $c.t1 insert end "\n"
    $c.t1 insert end "Каталог по умолчанию:\n" bold
    $c.t1 insert end "\t$wizData(defaultfolder)\n"
                
    $c.t1 insert end "\n"
    $c.t1 insert end "Модуль OpenSSL:\n" bold
    $c.t1 insert end "\t$wizData(opensslexec)\n"
##############
    $c.t1 insert end "Данные по СКЗИ:\n" bold
    set list [Config::Get system.tools]
    set i 0
        foreach {label varname} $list {
    	    if {$i == 0 } {
    		incr i
    		continue
    	    }
    	    Config::Set $varname $wizData($varname)
	$c.t1 insert end "\t$varname: $wizData($varname)\n"
#puts "VARNAME=$varname"
#puts "VARNAME REZ=$wizData($varname)"
	}
    $c.t1 insert end "Тип ключевой пары:\n" bold
        $c.t1 insert end "\t$::ProfileDialog::prof(req.default_key.selected)"
        $c.t1 insert end "  ($::ProfileDialog::prof(req.default_bits.selected) )\n"


############
    
    $c.t1 configure  -state disabled
    pack $c.vsb -side right -fill y
    pack $c.t1 -side top -fill both 
if { 0 } {
    grid $c.t1 -row 0 -column 0 -sticky w ;# -padx 4 -pady 4
    grid $c.vsb -row 0 -column 1 -sticky ns
    grid columnconfigure $c 0 -weight 0
    grid columnconfigure $c 1 -weight 0
    grid columnconfigure $c 2 -weight 1
    grid rowconfigure $c 0 -weight 0
    grid rowconfigure $c 1 -weight 1
}
}

proc updatewait {tt1} {
    variable ttw
    set tt2 [clock seconds]
#    update
    set tt2 [clock seconds]
    if {[expr $tt2 - $tt1] > 1} {
	set ttw 1
    }
    after  100 [list updatewait $tt1]
}

.cm.setupwizard eval {
        
    proc finalize {} {
	global profile_template
	global db
	global certdb
        variable wizData
        
        # set folder options
        foreach {label varname} [Config::Get folder.folderlist] {
            Config::Set $varname $wizData(defaultfolder)
        }
        Config::Set system.openssl $wizData(opensslexec)
	set list [Config::Get system.tools]
        set i 0
        foreach {label varname} $list {
    	    if {$i == 0 } {
    		incr i
    		continue
    	    }
    	    Config::Set $varname $wizData($varname)
	}
        Config::Set system.caname $wizData(CN)
        Config::SaveConfig
###########################################
	openssl::Profile_Load
# load config if exists
# При открытии БД
	Config::LoadConfig

	set list [Config::Get system.tools]
        set i 0
        foreach {label varname} $list {
#puts "LABEL=$label"
#puts "VARNAME=$varname"

    	    if {$i == 0 } {
    		incr i
    		continue
    	    }
	    set indexdb [lsearch $profile_template "$varname"]
	    incr indexdb
	    set rdb  [Config::Get $varname]
#puts "rdb=$rdb"
	    if {$i == 1 } {
		set prof [lreplace $profile_template $indexdb $indexdb $rdb]
		incr i
	    } else {
		set prof [lreplace $prof $indexdb $indexdb $rdb]
	    }
	}
	
	set indexdb [lsearch $profile_template "system.smime"]
	incr indexdb
	set prof [lreplace $prof $indexdb $indexdb "GOST 28147-89"]

	openssl::Template_SetData "profile_template" $prof
    

####################################
        # configure openssl for right program
        openssl::set_executable [Config::Get system.openssl]
        
        #setup the CA
        array set attr [array get wizData]
#parray attr
        set err [openssl::CreateRootCA attr]
        
        # should create this folder
	catch {certdb close}

	if {$err == 1 } {
    	    tk_messageBox -title "Разворачивание нового УЦ" -message "Ошибка при развертывании УЦ.\nПовторите операцию." -icon error -parent .cm
	} else {
    	    tk_messageBox -title "Разворачивание нового УЦ" -message "УЦ успешно развернуто.\nНадежно храните пароль к БД УЦ." \
    		 -detail "Для начала работы необходимл открыть БД УЦ.\nПервым вашим шагом должна быть настройка конфигурации УЦ (Средства->Настройки).\n
Настройте необходимые каталоги и профили выпускаемых сертификатов. \
    		 " -icon info -parent .cm
        }
	cancel
    }
    proc cancel {} {
	global db
	place forget .cm.setupwizard
	catch {tk busy forget .cm.mainfr}
	if {$db(filedb) != "" } {
	    catch {menu_enable}
	}
    }
    proc nextStep {this} {
        global defaultpar
        global db
        global certdb
        variable wizData
        set tt {Разворачивание УЦ}
        set currentStep [$this cget -step]
#puts "currentStep=$currentStep"
# ГОСТ-параметры
	if {$currentStep == "setup"} {
	    set defaultpar [$this.layoutFrame.basic.clientArea.c1 get]
#	    puts "DefaultPar=$defaultpar"
	} elseif {$currentStep == "dirname"} {
	    if {$wizData(dir_ca) == ""} {
                tk_messageBox -title $tt -message "Выберите каталог для БД УЦ." -icon error  -parent .cm
                return;
	    }
	    if { [file exists $wizData(dir_ca)] != 1 }  { 
    		if {[catch {file mkdir $wizData(dir_ca)}] == 1 } {
        	    tk_messageBox -title $tt -icon error -parent .cm \
        		-message "Нельзя создать каталог $dir  для БД.\nПроверьте полномочия"
        	    return
    		}	 
	    }

            if {$wizData(capassword) == ""} {
                tk_messageBox -title $tt -message "Вы не задали пароль.
Длина пароля должна быть не менее 6 символов.
В пароле рекомендуется использовать заглавные и прописные символы,
цифры и специальные символы" -icon error  -parent .cm
                return
            }
            if {$wizData(capassword2) != $wizData(capassword)} {
                tk_messageBox -title $tt -message "Пароли различаются, повторите.
Длина пароля должна быть не менее 6 символов.
В пароле рекомендуется использовать заглавные и прописные символы,
цифры и специальные символы" -icon error  -parent .cm
                return
            }
            if {[string length $wizData(capassword)] < 6 } {
                tk_messageBox -title $tt -message "Длина пароля должна быть не менее 6 символов.
В пароле рекомендуется использовать заглавные и прописные символы,
цифры и специальные символы" -icon error  -parent .cm
                return
            }
	    set c [$this widget clientArea]
	    variable tt1
	    waitevent .cm.topwait 10
	    .cm.topwait configure -text "Идет создания БД УЦ"
	    .cm.topwait.lwait configure -text "Начался процесс инициализации БД УЦ\n\nПридется подождать!"
	    place .cm.topwait -in $c.e1  -relx 0.2 -rely 0.0 -relwidth 0.6
#tk_messageBox -title "Waitevent" -icon info -message "WAIT" -parent .cm

            set db(dir) $wizData(dir_ca)
	    set wizData(defaultfolder) $db(dir)
##################Создание БД УЦ####################
#База для сертификатов
	    set filedb [file join $db(dir) "certdb.cadb"]
#	puts $filedb
	    if {[file exist $filedb] != 0} {
		catch {certdb close}
		file rename $filedb $filedb.1
		file delete -force $filedb.1
	    }
	    sqlite3 certdb $filedb
	    update
#Создаем rootCA и keyCA
	    debug::msg "cmd::createDB"

#Добавить таблицы сертификатов, отозванных сертификатов, запросов
#Таблица с датой создания БД, текущего серийного номера и пароля (хэш от пароля)
#createDBTable
#status - в работе, утверждена, выпущен сертификат
#Main Table
#    array set db  [array get ::cafl63::db]
#    set c [$this widget clientArea]

	    certdb eval {create table mainDB (dateCreateDB integer primary key, serNumCert text, serNumReq text, serNumCRL text, certCA, keyCA, pasDB text, profilesReq text, configReq text) }
	    set hash256 [::sha2::sha256 $wizData(capassword)]
#puts "HASH256=$hash256"
#	set dateDB [clock seconds]
    	    set dateDB [clock format [clock seconds]  -format {%y%m%d%H%M%S}]
	    set db(dateCreateDB) $dateDB
	    certdb eval {begin transaction}
	    certdb eval {insert into mainDB values( $dateDB, $db(serNumCert), $db(serNumReq), $db(serNumCRL),"rootCA", "keyCA", $hash256, "", "")}
    	    certdb eval {end transaction} 
#set col [certdb eval {select mainDB.dateCreateDB, mainDB.serNumCert, mainDB.serNumReq, mainDB.serNumCRL, mainDB.certCA, mainDB.keyCA, mainDB.pasDB, mainDB.profilesReq from mainDB}]
#puts "mainDB=$col"
#Либо так
#	certdb eval {select * from mainDB} vals {
#	    parray vals
#	    set passdb $vals(pasDB)
#	    set sernumdb $vals(serNum)
#	    set datedb $vals(dateCreateDB)
#	    set sernumreq $vals(serNumReq)
#	}
#Таблица сертификатов
#autoincrement
	    update
    	    certdb eval {create table certDB(  ckaID text primary key ,  
    	    nick text,  sernum text,  certPEM text, subject text, 
    	    notAfter text,  notBefore text, dateRevoke text,  state text )}
	    update
    	    certdb eval {create table certDBRev( ckaID text primary key )}
	    update
    	    certdb eval {create table certDBNew( ckaID text primary key )}
	    update

	    certdb eval {create table reqDB (ckaID text primary key, nick  text,  sernum text, subject text, type text, datereq text, status text, reqpem text, pkcs7 text)}
	    update
	    certdb eval {create table reqDBAr (ckaID text primary key, nick  text,  sernum text, subject text, type text, datereq text, status text, reqpem text, pkcs7 text)}
	    update
    	    certdb eval {create table crlDB(ID integer primary key autoincrement, signtype text, issuer text, publishdate text, nextdate text, crlpem text)}
	    set tt1 [clock seconds]
	    updatewait $tt1
	    variable ttw
	    set ttw 0
	    vwait ttw
	    after cancel updatewait
	    destroy .cm.topwait
#База для ключей
if { 0} {
	    set filedb [file join $db(dir) "keydb.cadb"]
	    puts $filedb
	    if {[file exist $filedb] != 0} {
		file delete -force $filedb
	    }
	    sqlite3 keydb $filedb
#Добавить таблицу ключей
#createDBTable
	    catch {keydb close}
	    set keydb ""
}
##################Создание БД УЦ#####################            
	} elseif {$currentStep == "type"} {
            if {$wizData(type)== "pers"} {
                $this configure -nextstep pers_attr
            } elseif {$wizData(type)== "org"} {
                $this configure -nextstep org_attr
            } elseif {$wizData(type)== "ssl"} {
                $this configure -nextstep ssl_attr
            }
        } elseif {$currentStep == "ca_name"} {
            if {$wizData(CN) == ""} {
                tk_messageBox -title $tt -message "Укажите наименование организацию (CN)." -icon error  -parent .cm
                return -code break;
            }
        } elseif {$currentStep == "ca_attr"} {
            if {$wizData(O) == ""} {
                tk_messageBox -title $tt -message "Укажите наименование организации (O)." -icon error  -parent .cm
                return -code break;
            }
    	    if {$wizData(OGRN) != "" &&  [string length $wizData(OGRN)] != 13} {
                tk_messageBox -title $tt -message "Вы неполностью ввели ОГРН" -icon error  -parent .cm
                return -code break;
    	    }
    	    if {$wizData(INN) != "" &&  [string length $wizData(INN)] != 12} {
                tk_messageBox -title $tt -message "Вы неполностью ввели ИНН" -icon error  -parent .cm
                return -code break;
    	    }
            if {$wizData(emailAddress) == ""} {
                tk_messageBox -title $tt -message "Вы забыли электронную почту." -icon error  -parent .cm
                return -code break;
            } else {
        	set mail [verifyemail $wizData(emailAddress)]
        	if {$mail != "OK" } {
            	    tk_messageBox -title $tt -message "Вы неверно указали электронную почту." -icon error  -parent .cm
            		return -code break;
        	}
            }
        } elseif {$currentStep == "defaultfolder"} {
            # check default folder
            if {$wizData(defaultfolder) == ""} {
                tk_messageBox -title $tt -message "Пожалуйста, укажите путь к папке,\nв которой по умолчанию будут храниться сертификаты." -icon error  -parent .cm
                return -code break;
            }
            # check if folder exists
            set wizData(defaultfolder) [file normalize $wizData(defaultfolder)]
            if {![file exists $wizData(defaultfolder)]} {
                set buttonpress [tk_messageBox -title $tt -message "Папки не существует.\nСоздать папку ?" -icon question -type okcancel -parent .cm]
                if {$buttonpress == "ok"} {
                    file mkdir $wizData(defaultfolder)
                } else {
                    return -code break;
                }
            }
            
        } elseif {$currentStep == "opensslexec"} {
            # check default folder
            if {$wizData(opensslexec) == "" || ![file exists $wizData(opensslexec)]} {
                tk_messageBox -title "OpenSSL Program" -message "Please specify the OpenSSL program to use." -icon error  -parent .cm
                return -code break;
            }
            # check if program exists and works
            if {![file isfile $wizData(opensslexec)] || ![file executable $wizData(opensslexec)]} {
                tk_messageBox -title "OpenSSL Program" -message "This file is not an OpenSSL Program." -icon error  -parent .cm
                return -code break;
            }
            set v [exec $wizData(opensslexec) version]
            set ver [lindex $v 0]
#            if {[lindex $v 0] != "OpenSSL" && [lindex $v 0] != "LirSSL-CSP"} {}
            if { [string first "OpenSSL" $ver] == -1 && [string first "LirSSL" $ver] == -1} {
                tk_messageBox -title "OpenSSL Program" -message "This program is not OpenSSL." -icon error  -parent .cm
#                return -code break;
            }
            
        }
        set name ".cm.setupwizard"
#        puts "tkwizard::cmd=$currentStep";
        tkwizard::handleEvent $name "<<WizNextStep>>";
#        puts "tkwizard::=.cm.setupwizard"

    }
    
    
}

#wm minsize .setupwizard 600 380

######################################
# CertificateWizard
#
# Wizard that collects information to generate a certificate
#
#

lappend auto_path .
package require tkwizard
package require openssl
package require cagui

package provide CertificateWizard 1.0

tkwizard::tkwizard .cm.certificatewizard -title {Содержимое сертификата}

.cm.certificatewizard eval {

    variable wizData
    # default values
    catch {unset wizData}
    array set wizData {
        type "pers"
        O ""
        OU ""
        C ""
        ST ""
        L ""
        CN ""
        INN ""
        street ""
        OGRN ""
        OGRNIP ""
        unstructuredName ""
        emailAddress ""
        capassword ""
        capassword2 ""
        opensslexec ""
        exit "cancel"
        dir_ca ""
	system.ckzi ""
	system.kc12 ""
	system.cafl63 ""
	system.certckzi ""
	system.certca ""
	ckzip11 0
	type "Personal"
    }
    [namespace current]::originalWidgetCommand configure  -text "Создание запроса на сертификат" -font {Times 11 bold}
}

bind .cm.certificatewizard <<WizFinish>> {[%W namespace]::finalize}
bind .cm.certificatewizard <<WizCancel>> {[%W namespace]::cancel}
bind .cm.certificatewizard <<WizNextStep>> {[%W namespace]::nextStep %W}

# ***

.cm.certificatewizard step {type} -layout basic {
    variable wizData
    global defaultkey
    global defaultpar
    # use nice icon
    $this widget icon configure -image img_cert  -background #eff0f1
    #cdc7c2
#    $this widget icon configure -image img_cert  -background #c0bab4

    set c [$this widget clientArea]

    set subt {Запрос на новый сертификат, с сохранением запроса в файле пользователя}
    if {$wizData(wizardtype) == "csrdb"} {
	set subt {Запрос на новый сертификат с сохранением запроса в БД УЦ}
    }

    $this stepconfigure \
        -title {Запрос на получение сертификата} \
        -subtitle $subt \
        -pretext {Пожалуйста, укажите профиль сертификата, в соответствии с которым будет затребована информация. Определитесь также где вы собираетесь создавать\
        ключевую пару: токен или файл.} \
        -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
    #$this configure -nextstep "cert_name"

    label $c.l0  -image logobook_60x41 -compound left -bg white
    grid $c.l0 -row 0 -column 0 -columnspan 2 -sticky w -padx 4 -pady 8

#################
    label $c.lf1 -text "Тип СКЗИ:" -pady 0
    frame $c.type -bg #eff0f1
    eval "ttk::radiobutton $c.type.rb1 -text OpenSSL -value 0 -variable [namespace current]::wizData(ckzip11)"
    eval "ttk::radiobutton $c.type.rb2 -text \"PKCS#11\" -value 1 -variable [namespace current]::wizData(ckzip11)"

    pack $c.type.rb2 -side left -ipadx 10 -padx 0 -pady 0 
    pack $c.type.rb1 -side left -ipadx 10 -padx 0 -pady 0 


    grid $c.lf1 -row 1 -column 0  -sticky new -padx 8 -pady {3mm 1mm}
    grid $c.type -row 1 -column 1  -sticky w -padx 4 -pady 1mm

###############
    # combo box
    label $c.l1 -text "Профиль сертификата:"
    set listCert {}
    # insert existing profiles
    foreach v [openssl::Profile_List] {
	lappend listCert $v
    }
    ttk::combobox $c.c1 -width 36 -textvariable [namespace current]::wizData(type) -values $listCert
    grid $c.l1 -row 2 -column 0 -sticky w -padx 8 -pady 4
    grid $c.c1 -row 2 -column 1 -sticky w -padx 4 -pady 4

    set ww .cm.certificatewizard
#tk_messageBox -title "Информация о заявителе" -message "Окно=\n$c" -icon info  -parent .cm.certificatewizard
    $ww.layoutFrame configure -padx 0 -pady 0 -bg #c0bab4

    raise $ww

}
            
.cm.certificatewizard step {cert_name} -layout basic {
    variable wizData
    
    set c [$this widget clientArea]

    array set profdata [openssl::Profile_GetData $wizData(type)]
        
    #
    # set default text for unfamiliar subject types
    set pretext "Пожалуйста, укажите имя, идентифицирующее владельца сертификата.
    
Для личных сертификатов вы должны дать значимое имя
(то есть полное имя человека или псевдоним).

Для сертификата SSL веб-сервера общее имя должно быть
идентично доменному имени вашего веб-сервера (например, www.yourdomain.com).

Эта информация будет храниться в поле \"Common Name\" сертификата."


    set l1text "Common Name"

    #
    # override text for know subject types
    array set profdata [openssl::Profile_GetData $wizData(type)]
    if {$profdata(other.subjecttype) == "Personal"} {
        #puts "pers wizData(type)=$wizData(type)"
        set pretext "Введите полное имя будущего владельца сертификата.
Для физического лица это ФИО как в паспорте.
Для юридического лица это наименование компании из ЕГРЮЛ.
        
Эта информация будет размещена в поле \"Common Name\" сертификата."
        set l1text "Common Name"
    } elseif {$profdata(other.subjecttype) == "Server"} {
        #puts "not  wizData(type)=$wizData(type)"
        set pretext "Пожалуйста, введите доменное имя вашего сервера / SSL веб-сервера.
        
Эта информация будет храниться в поле \"Common Name\" сертификата."
        set l1text "domain name (e.g. www.yourdomain.com)"
    }

    $this stepconfigure \
            -title {Common Name} \
            -subtitle {Введите имя владельца сертификата} \
            -pretext $pretext \
            -posttext {Нажмите "След>" для продолжения или "Отмена", если вы передумали. Нажав кнопку "<Пред" вы вернетесь на предыдущий шаг.} 
    $this configure -nextstep "cert_attr"

    label $c.l1 -text "$l1text :"
    ttk::entry $c.e1 -textvariable [namespace current]::wizData(CN) 
    grid $c.l1 -row 0 -column 0 -sticky w -padx {4 0} -pady {5mm 4}
    grid $c.e1 -row 0 -column 1 -sticky nwse -padx {0 5mm} -pady {5mm 4}
    grid columnconfigure $c 0 -weight 0
    grid columnconfigure $c 1 -weight 1
}

.cm.certificatewizard step {cert_attr} -layout basic {
    variable wizData
    global rfregions
    
    set c1 [$this widget clientArea]
    
    $this stepconfigure \
            -title {Содержимое сертификата} \
            -subtitle {Пожалуйста, предоставьте некоторую информацию о будущем владельце сертификата} \
            -pretext {Пожалуйста, заполните следующие поля. Эта информация будет помещена в сертификат. Поля для обязательного заполнения помечены звездочкой (*)} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали. Нажав кнопку "<Пред" вы вернетесь на предыдущий шаг.} 
    $this configure -nextstep "passwd"

#scrollframe
    set com2 "ttk::scrollbar $c1.vs -command {$c1.sf yview}"
    set com1     "scrolledframe $c1.sf -yscroll {$c1.vs set} -background #e0e0da"
    set com [subst $com1]
    eval $com1
    set com [subst $com2]
    eval $com

    pack $c1.vs -side right -fill y 
    pack $c1.sf  -side top -fill both -expand 1
    $c1.sf.scrolled configure -background white
$c1.sf.scrolled configure -padx 10
# -pady 10 
    set c $c1.sf.scrolled

    # all optional and required fields
    set i 1 ;# field counter for widgets
    array set profdata [openssl::Profile_GetData $wizData(type)]
    global profile_options
    array set opts [array get profile_options]
    array set fieldlabels $opts(req.dn_fields)
    set wizData(libp11) $profdata(req.default_libp11)
    set wizData(default_key) $profdata(req.default_key)
    set wizData(default_param) $profdata(req.default_param)

    global rfregions
    set oidO 0
    set oidCN -1
    set pp 1
    foreach {field dflt} $profdata(req.dn_fields) {
        # label
        if {$pp < 10} {
    	    set attrlabel "  $pp. $fieldlabels($field)"
        } else {
    	    set attrlabel "$pp. $fieldlabels($field)"
        }

        #puts "creating field : $field / $dflt"
        set label "$attrlabel:\n     ($field)"
        
        # if required
        if {[lsearch -exact $profdata(req.dn_fields.required) $field] != -1} {
            append label " *"
        }
        if {$field == "O"} {
	    incr oidO
        } elseif {$field == "CN"} {
	    set oidCN $i
        }
        if {$field == "C"} {
            label $c.l$i -text "$label"
	    set listISO {}
            foreach v $::openssl::iso3166 {
		lappend listISO $v
            }
            ttk::combobox $c.e$i -textvariable [namespace current]::wizData($field) -width 40 -values $listISO
            if {$wizData($field) == ""} {
                set wizData($field) $dflt
            }
#puts "listISO=$wizData($field)"
	    set tekC [lsearch $listISO $wizData($field)]
	    $c.e$i delete 0 end
	    $c.e$i insert 0 [lindex $listISO $tekC]

        } elseif {$field == "ST"} {
            label $c.l$i -text "$label"
            ttk::combobox $c.e$i -textvariable [namespace current]::wizData($field) -width 40 -values $rfregions
            if {$wizData($field) == ""} {
                set wizData($field) $dflt
            }
	    set tekC [lsearch $rfregions $wizData($field)]
	    $c.e$i delete 0 end
	    $c.e$i insert 0 [lindex $rfregions $tekC]

        } else  {
    	    global atrkval
#Здесь добавить обработку ИНН и т.д.
#puts "LABEL=\"$label\""
	    set klab $fieldlabels($field)
            label $c.l$i -text "$label"
    	    if {[info exists atrkval($klab)]} {
    		set len $atrkval($klab)
#puts "LEN==$len"
        	set com "ttk::entry $c.e$i -textvariable [namespace current]::wizData($field) -validate key -validatecommand {Digit $c.e$i %i %P $len}  -style white.TEntry"
		set com1 [subst $com]
		eval $com1
	    } else {
        	ttk::entry $c.e$i -textvariable [namespace current]::wizData($field) 
	    }
            if {$wizData($field) == ""} {
                set wizData($field) $dflt
            }
        }
        grid $c.l$i -row $i -column 0 -sticky w -padx 0 -pady {1mm 0}
        grid $c.e$i -row $i -column 1 -sticky we -padx 0 -pady {1mm 0}
        incr i
        incr pp
    }
    
    if {$oidO == 1 && $oidCN > -1} {
	$c.l$oidCN configure -text "  $oidCN. Организация:\n     (CN)"
    }
    grid columnconfigure $c 1 -weight 1
    if {$i < 7} {
	pack forget $c1.vs
    }
}


.cm.certificatewizard step {passwd} -layout basic {
    variable wizData
    
    set c [$this widget clientArea]
    
    label $c.l1 -text "Пароль:" -width 12
    ttk::entry $c.e1 -width 40 -show * -textvariable [namespace current]::wizData(keypassword)
    if {$wizData(libp11) == "" } {
	set ::ProfileDialog::input(formatKey.override)  0
    } else {
	set ::ProfileDialog::input(formatKey.override)  1
    }
    grid $c.l1 -row 0 -column 0 -sticky w -padx {4 0} -pady {5mm 1mm}
    grid $c.e1 -row 0 -column 1 -sticky w -padx {0 5mm} -pady {5mm 1mm}

    if {$wizData(ckzip11) == 0 } {
	$this stepconfigure \
            -title {Пароль для ключа} \
            -subtitle {Пожалуйста, введите пароль для закрытого ключа} \
            -pretext {Ваш ключ будет защищен путем его шифрования на вашем пароле. \
Позже закрытый ключ можно будет использовать только, если вы помните этот пароль. \
Храните ключ и пароль в глубокой тайне.} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
	$this configure -nextstep "filename"
	label $c.l2 -text "Повторите пароль:"
	ttk::entry $c.e2 -width 40  -show * -textvariable [namespace current]::wizData(keypassword2)
	grid $c.l2 -row 1 -column 0 -sticky w -padx {4 0} -pady 1mm
	grid $c.e2 -row 1 -column 1 -sticky w -padx {0 5mm} -pady 1mm
	$this configure -nextstep "filename"
    } else {
	$c.l1 configure -text "PIN-код:"
	$this stepconfigure \
            -title {PIN-код токена} \
            -subtitle {Пожалуйста, введите PIN-код для вашего токена} \
            -pretext {Ваш ключ будет сгенирирован на вашем токене. \
Закрытый ключ будет храниться на токене, а доступ к ключу защищен PIN-кодом. \
Надежно храните сам токен, а PIN-код к нему в глубокой тайне.} \
            -posttext {Нажмите "След>" для продолжения или "Отмена", если вы передумали.} 
	$this configure -nextstep "final"
    }

#    grid columnconfigure $c 1 -weight 1
}

.cm.certificatewizard step {filename} -layout basic {
    variable wizData
    
    set c [$this widget clientArea]
    
if {$wizData(wizardtype) != "csrdb"} {
    $this stepconfigure \
            -title {Имя файла} \
            -subtitle {Пожалуйства, введите имена файлов для сохранения вашего запроса} \
            -pretext {Пожалуйства, введите требуемые имена файлов.

Файл с расширением .csr содержит запрос на сертификат, который в последующем должен будет представлен в УЦ.

Файл с расширением .key содержит ваш закрытый ключ, защищенный паролем. Этот файл должен хранится в секрете.} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
} else {
    $this stepconfigure \
            -title {Имя файла} \
            -subtitle {Пожалуйста, введите имя файла для хранения ключа к создаваемому запросу} \
            -pretext {Пожалуйста, введите имя файла.

Создаваемый запрос будет сохранен в БД данного УЦ.
Генерируемый вместе с запросом ключ, не будет сохранен в БД УЦ. Это ваш Ключ.
В файле *.key, защищенном паролем, будет хранится ваш закрытый ключ. Надежно храните его.} \
            -posttext {Нажмите "След" для продолжения..} 
}
    
    # suggest a file name for the certificate
    # for personal certs - based on email address
    # for server certs - based on common name (domain name)
    # this is configured however in the options
    array set profdata [openssl::Profile_GetData $wizData(type)]
    set wizData(csr_fn) [file join [Config::Get folder.requests] $wizData(CN).csr]
    set wizData(key_fn) [file join [Config::Get folder.keys] $wizData(CN).key]
    if {[info exists profdata(other.suggestfilename)]} {
        if {$profdata(other.suggestfilename) == "Email"} {
            set wizData(csr_fn) [file join [Config::Get folder.requests] $wizData(emailAddress).csr]
            set wizData(key_fn) [file join [Config::Get folder.keys] $wizData(emailAddress).key]
        } elseif {$profdata(other.suggestfilename) == "Common Name"}  {
            set wizData(csr_fn) [file join [Config::Get folder.requests] $wizData(CN).csr]
            set wizData(key_fn) [file join [Config::Get folder.keys] $wizData(CN).key]
        }
    }
    if {$wizData(type) == "Personal"} {
        set wizData(csr_fn) [file join [Config::Get folder.requests] $wizData(emailAddress).csr]
        set wizData(key_fn) [file join [Config::Get folder.keys] $wizData(emailAddress).key]
    } elseif {$wizData(type) == "SSL Server"}  {
        set wizData(csr_fn) [file join [Config::Get folder.requests] $wizData(CN).csr]
        set wizData(key_fn) [file join [Config::Get folder.keys] $wizData(CN).key]
    }
    
if {$wizData(wizardtype) != "csrdb"} {
    label $c.l1 -text "Файл для запроса (*.csr)"
    cagui::FileEntry $c.e1 -dialogtype save \
            -variable [namespace current]::wizData(csr_fn) \
            -title "Введите имя файла для сохранения запроса" \
            -defaultextension .csr \
            -initialdir [Config::Get folder.requests] \
            -filetypes [Config::Get filetype.request]
}
    
    set commandnotrequired "namespace eval [namespace current] {if {\$wizData(key_fn) == \"\"} then {set wizData(key_fn) \[file rootname \$wizData(csr_fn)\].key}}"
    label $c.l2 -text "Файл для закрытого ключа (*.key)"
    cagui::FileEntry $c.e2 \
            -dialogtype save \
            -variable [namespace current]::wizData(key_fn) \
            -title \"Введите имя файла для сохранения закрытого ключа\"\]" \
            -initialdir [Config::Get folder.keys] \
            -defaultextension .key \
            -filetypes [Config::Get filetype.key]
    $c.e2.but configure -background white
    set zz "5mm"
if {$wizData(wizardtype) != "csrdb"} {
    grid $c.l1 -row 0 -column 0 -sticky w -padx {4 0} -pady {5mm 1mm}
    grid $c.e1 -row 0 -column 1 -sticky nwse -padx {0 5mm} -pady {5mm 1mm}
    set zz 0
}
    eval "grid $c.l2 -row 1 -column 0 -sticky w -padx {4 0} -pady {$zz 1mm}"
    eval "grid $c.e2 -row 1 -column 1 -sticky nwse -padx {0 5mm} -pady {$zz 1mm}"
    grid columnconfigure $c 0 -weight 0
    grid columnconfigure $c 1 -weight 1
}

.cm.certificatewizard step {p12name} -layout basic {
    variable wizData
    
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Filename} \
            -subtitle {Please enter the filenames to save your PKCS12 file} \
            -pretext {Please enter following filename.} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
    # default file names
    if {$wizData(type) == "Personal"} {
        set wizData(p12_fn) [file join [Config::Get folder.p12] $wizData(emailAddress).p12]
    } elseif {$wizData(type) == "SSL Server"}  {
        set wizData(csr_fn) [file join [Config::Get folder.p12] $wizData(CN).p12]
    }
    set wizData(username) $wizData(CN)
    # friendly name for CA
    set wizData(caname) [Config::Get system.caname]

    label $c.l1 -text "PKCS#12 Filename"
    cagui::FileEntry $c.e1 \
            -dialogtype save \
            -variable [namespace current]::wizData(p12_fn) \
            -title "Enter file name to save PKCS#12" \
            -initialdir [Config::Get folder.p12] \
            -defaultextension .p12 \
            -filetypes [Config::Get filetype.p12]
    
    label $c.l2 -text "Friendly User Name"
    entry $c.e2 -textvariable [namespace current]::wizData(username)
    label $c.l3 -text "Friendly CA Name"
    entry $c.e3 -textvariable [namespace current]::wizData(caname)
    grid $c.l1 -row 0 -column 0 -sticky nw -padx 4 -pady 4
    grid $c.e1 -row 0 -column 1 -sticky nwse -padx 4 -pady 4
    grid columnconfigure $c 1 -weight 1
}

.cm.certificatewizard step {capassword} -layout basic {
    variable wizData
    
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Пароль} \
            -subtitle {Пожалуйста, введите пароль УЦ для доступа к закрытому ключу УЦ.} \
            -pretext {Закрытый ключ УЦ будет использован для подписания сертификата. \
                Пароль необходим для доступа к ключу, который необходим для генерации сертификата.} \
            -posttext {Нажмите "next" для продолжения.}
    
    label $c.l1 -text "Пароль УЦ"
    ttk::entry $c.e1 -width 40 -show * -textvariable [namespace current]::wizData(capassword)
    grid $c.l1 -row 0 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e1 -row 0 -column 1 -sticky w -padx 4 -pady 4
    grid columnconfigure $c 0 -weight 0
    grid columnconfigure $c 1 -weight 0
    grid columnconfigure $c 2 -weight 1
    grid rowconfigure $c 0 -weight 0
    grid rowconfigure $c 1 -weight 1
}

.cm.certificatewizard step {final} -layout basic {
    variable wizData
    global defaultkey
    global defaultpar
    global g_iso3166_codes

    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Создание запроса на сертификат} \
            -subtitle {Генерация ключевой пары и запроса на сертификат} \
            -pretext {Вы собираетесь создать запрос со следующими значениями полей:} \
        -posttext {Нажмите "Готово" для генерации Запроса на Сертификат. Если передумали нажмите "Отмена"}
# -width 60
    text $c.t1 -relief flat -heigh 15 \
            -yscrollcommand [list hidescroll  $c.yscroll]  -font {Times 10 bold italic} -bg white -bd 0
#            -yscrollcommand [list $c.yscroll set]  -font {Times 10 bold italic} -bg skyblue -bd 0

    ttk::scrollbar $c.yscroll -orient vertical -command [list $c.t1 yview]

    set fnt(std) [$c.t1 cget -font]
    set fnt(bold) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] bold]
    $c.t1 tag configure bold -font $fnt(bold)

    $c.t1 insert end "Профиль сертификата:\n" bold
    $c.t1 insert end "\t$wizData(type)\n"
    $c.t1 insert end "Subject Distinguished Name:\n" bold
    
    array set profdata [openssl::Profile_GetData $wizData(type)]
    global profile_options
    array set opts [array get profile_options]
    array set fieldlabels $opts(req.dn_fields)
#    set wizData(dn) ""
    set wizData(dncsr) {}
    foreach {field dflt} $profdata(req.dn_fields) {
        if {$wizData($field) == ""} {
    	    continue
	}
####################
        if {$field == "C" } {
    	    foreach {country who} $g_iso3166_codes  {
        	if {$country == $wizData($field) } {
        	    lappend wizData(dncsr) $field
        	    lappend wizData(dncsr) $who
        set label $fieldlabels($field)
        $c.t1 insert end "\t$label = $wizData($field) ($who)\n"
	break
        	}
    	    }
	continue
        } elseif {$field == "E" || $field == "emailAddress"} {
    	    lappend wizData(dncsr) email
    	    lappend wizData(dncsr) $wizData($field)
        } else {
    	    lappend wizData(dncsr) $field
    	    lappend wizData(dncsr) $wizData($field)
        }
        set label $fieldlabels($field)
        $c.t1 insert end "\t$label = $wizData($field)\n"
    }

#puts "dncsr=$wizData(dncsr)"

    $c.t1 insert end "Сведения о ключе:\n" bold
        $c.t1 insert end "\tТип ключа = $profdata(req.default_key) \n"
        $c.t1 insert end "\tПараметры ключа = $profdata(req.default_param) \n"
#puts "::OptionsDialog::input(library.pkcs11)=[Config::Get library.pkcs11]"
    set wizData(libp11) [Config::Get library.pkcs11]
    if {$wizData(ckzip11) == 0} {
	set typckzi "OpenSSL"
	set libp11 ""
    } else {
#	set ::OptionsDialog::input(library.pkcs11) [Config::Get library.pkcs11]
	if {$wizData(libp11) == ""} {
    	    tk_messageBox -icon error -type ok -title "Генерация запроса" -message "У вас не указана библиотека PKCS#11" \
    	     -detail "Выберите библиотеку:\nСредства->Настройки->Типы сертификатов->Редактировать->Key Pair->Библиотека PKCS#11"  -parent .cm
	    return
	}
	set typckzi "PKCS#11"
    }

#puts "::OptionsDialog::input(library.pkcs11)=[Config::Get library.pkcs11]"
#puts "wizData(libp11)=$wizData(libp11)"
    $c.t1 insert end "\tТип СКЗИ = $typckzi\n"
    if { $wizData(ckzip11) == 1} {
	$c.t1 insert end "\tБиблиотека PKCS#11 = $wizData(libp11)\n"
        $c.t1 insert end "\tУбедитесь, что ваш токен подключен!!!\n\n" bold
    }
    $c.t1 insert end "Если вы хотите сменить ключ или СКЗИ для генерации ключа, то воспользуйтесь меню:\n" bold
    $c.t1 insert end "Средства->Настройки->Типв Сертификатов->Редактировать->Key Pair\n"

#        $c.t1 insert end "\tИспользуемое СКЗИ = $wizData(ckzi)\n"
#    $c.t1 insert end "Назначение сертификата = $wizData(role)\n" bold

    $c.t1 configure  -state disabled
#    pack $c.vsb -side right -fill y
#    pack $c.t1 -side top -fill both -expand 1
#    $c.t1 config -yscrollcommand {hidescroll  $c.yscroll}
    grid $c.yscroll -row 0 -column 1 -sticky nse -padx {0 1mm} -pady {1mm 0}
    grid $c.t1 -row 0 -column 0 -sticky nwse -padx {1mm 0} -pady {1mm 0}
    grid columnconfigure $c 0 -weight 1

}

.cm.certificatewizard eval {

    proc initwizard { this wizardtype} {
        variable wizData
        
        array set wizData {
            type "Personal"
            O ""
            OU ""
            C ""
            ST ""
            SN ""
            GN ""
            L ""
            CN ""
            INN ""
            OGRN ""
    	    OGRNIP ""
            SNILS ""
            emailAddress ""
            street ""
            title ""
            unstructuredName ""
            keypassword ""
            keypassword2 ""
            capassword ""
            exit "cancel"
            username ""
            caname ""
            wizardtype ""
            libp11 ""
            type "Personal"
        }
        set wizData(wizardtype) $wizardtype
        set  wizData(libp11)   [Config::Get library.pkcs11]
	if {$wizData(libp11) == ""} {
	    catch {set  wizData(libp11) $::OptionsDialog::input(library.pkcs11)}
	}

        if {$wizardtype=="p12"} {
            $this order type cert_name cert_attr passwd p12name capassword final
        } else  {
            $this order type cert_name cert_attr passwd filename final
        }
    }
    
    proc finalize {} {
        variable wizData
        global db
        if {$wizData(wizardtype)=="p12"} {
            # create certificate request & convert to pkcs12
            array set attr [array get wizData]
            set profile $attr(type)
            
            openssl::CreatePKCS12 $profile attr
            ::CertificateManager_Update .cm $db(treeCert)
            
        } elseif {$wizData(wizardtype)=="csrdb"} {
            # only create certificate request to db
            array set attr [array get wizData]
            set profile $attr(type)
	    set wizData(libp11) [Config::Get library.pkcs11]

	    if {$wizData(ckzip11) && $wizData(libp11) != "" } {
		set reqok "Запрос сохранен в БД.\nКлюч находится на токене. Заберите его."
#                tk_messageBox -title "Создание запроса в БД" -message "Пожалуйств, проверьте, что токен подключен."  -detail "ПОДПИСЬ ПОКА НЕ РЕАЛИЗОВАНА на токене!!!" -icon info  -parent  .cm
                set ret [CreateRequestTCL $profile attr]
                if {$ret == ""} {
            	    tk_messageBox -title "Создание запроса в БД" -message "Ошибка создания запроса."  -detail "Проверьте DN и настройки" -icon info  -parent  .
        	    return -code break
                }
		foreach {req labk} $ret {}
		append detok "\nМетка ключевой пары:\n$labk"
#puts "req=$req"
		importRequest $req ""
		set err 0
#                set err -1
	    } else {
		set reqok "Запрос сохранен в БД.\nКлюч сохранен в файле:\n$attr(key_fn)"
        	set err [openssl::CreateRequestDB $profile attr]
            }
            if {$err !=0 } {
                tk_messageBox -title "Создание запроса в БД" -message "Не удалось создать запрос." -icon error  -parent  .cm
        	return -code break
            } else {
                tk_messageBox -title "Создание запроса в БД" -message "Запрос успешно создан" -detail $reqok -icon info  -parent  .cm
            }
        } else  {
            # only create certificate request to file
            array set attr [array get wizData]
            set profile $attr(type)
	    if {$wizData(libp11) != "" } {
		set reqok "Запрос успешно создан и сохранен в файле:\n$attr(csr_fn)\nКлюч находится на токене. Заберите его."
                tk_messageBox -title "Создание запроса в файле" -message "Пожалуйств, проверьте, что токен подключен." -detail "ПОДПИСЬ ПОКА НЕ РЕАЛИЗОВАНА на токене!!!" -icon info  -parent  .cm
                set err -1
	    } else {
		set reqok "Запрос успешно создан и сохранен в файле:\n$attr(csr_fn)\nКлюч сохранен в файле:\n$attr(key_fn)"
        	set err [openssl::CreateRequest $profile attr]
            }
            if {$err !=0 } {
                tk_messageBox -title "Создание запроса в файле" -message "Не удалось создать запрос." -icon error  -parent  .cm
        	return -code break
            } else {
                tk_messageBox -title "Создание запроса в файле" -message "Запрос успешно создан" -detail $reqok -icon info  -parent  .cm
            }
        }
	cancel
    }
    proc cancel {} {
	place forget .cm.certificatewizard
	catch {tk busy forget .cm.mainfr}
	catch {menu_enable}
    }

    proc nextStep {this} {
        global db
        variable wizData
#puts "nextStep=.cm.certificatewizard"
        set currentStep [$this cget -step]
        
        if {$currentStep == "type"} {
            
            # nothing to check

        } elseif {$currentStep == "passwd"} {
            if {$wizData(ckzip11)} {
        	set typep "Пожалуйста, укажите PIN-код." 
            } else {
        	set typep "Пожалуйста, укажите пароль." 
            }
            
            if {$wizData(keypassword) == ""} {
                tk_messageBox -title "Пароль/PIN" -message $typep -icon error  -parent  .cm
                return
            }
            if { $::ProfileDialog::input(formatKey.override) == 0  && !$wizData(ckzip11)} {
    		if { $wizData(keypassword) != $wizData(keypassword2) } {
            	    tk_messageBox -title "Пароль" -message "Пароли разные - повторите еще раз." -icon error  -parent  .cm
            	    return
            	}
            }
        } elseif {$currentStep == "capassword"} {
            global db
            if {$wizData(capassword) == ""} {
                tk_messageBox -title "Пароль" -message "Пожалуйста, укажите пароль УЦ." -icon error  -parent .cm
                return 
            }
	    set hash256 [::sha2::sha256 $wizData(capassword)]
	    if {$db(pasDB) != $hash256} {
        	tk_messageBox -title "Пароль" -icon error -message "Вы ошиблись с паролем\n" -parent  .cm
        	return 
	    }

        } elseif {$currentStep == "cert_name"} {
set wizData(libp11) [Config::Get library.pkcs11]
	    if { $wizData(ckzip11) && $wizData(libp11) == "" } {
#puts "::OptionsDialog::input(library.pkcs11)=[Config::Get library.pkcs11]"
#puts "wizData(libp11)=$wizData(libp11)"

        	tk_messageBox -title "Создание запроса в БД" -message "Не выбрана библиотека PKCS11.\n" -detail "Средства->Настройки->Типы Сертификатов->Редактировать->KeyPair" -icon error  -parent  .cm
        	return
	    }
            
            if {$wizData(CN) == ""} {
                tk_messageBox -title "Сведения об ошибках" -message "Пожалуйста, укажите владельца (CN) сертификата." -icon error  -parent .cm
                return 
            }
            
        } elseif {$currentStep == "cert_attr"} {
            
            set missingvalue 0
            set missinglist {}
            array set profdata [openssl::Profile_GetData $wizData(type)]
            foreach {field dflt} $profdata(req.dn_fields) {
                # if required
                if {[lsearch -exact $profdata(req.dn_fields.required) $field] != -1} {
                    #check if we have value
                    if {$wizData($field) == ""} {
                        set missingvalue 1
                        lappend missinglist "$field"
                        #break
                    }
                }
                
            }
            if {$wizData(emailAddress) != ""} {
        	set mail [verifyemail $wizData(emailAddress)]
        	if {$mail != "OK" } {
            	    tk_messageBox -title "Электронная почта" -message "Вы неверно указали электронную почту." -icon error  -parent .cm
            		return 
        	}
            }

            if {$missingvalue} {
                tk_messageBox -title "Сведения об ошибках" -message "Вы не заполнили следующие обязательные поля: [join $missinglist {, }]." -icon error  -parent .cm
                return
            }
            
        }
        set name ".cm.certificatewizard"
        tkwizard::handleEvent $name "<<WizNextStep>>"

    }
    
    
}

#wm minsize .certificatewizard 650 400

######################################
# SelfSignedWizard
#
# Wizard to generate a self signed certificate
#
#

lappend auto_path .
package require tkwizard
package require openssl
package require Config

package provide SelfSignedWizard 1.0


tkwizard::tkwizard .selfsignedwizard -title SelfSignedWizard

.selfsignedwizard eval {
    variable wizData

}

bind cm.selfsignedwizard <<WizFinish>> {[%W namespace]::finalize}
bind cm.selfsignedwizard <<WizNextStep>> {[%W namespace]::nextStep %W}

# i have to get this to work
# ***
#wm protocol .setupwizard WM_DELETE_WINDOW {}

.selfsignedwizard step {type} -layout basic {
    variable wizData
    
    # use nice icon
    $this widget icon configure -image img_cert  -background #eff0f1
    #cdc7c2
    
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Self Signed Certificate} \
            -subtitle {Create a self signed certificate} \
            -pretext {Please select the type of certificate you want to create} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.}     
    
    # combo box
    label $c.l1 -text "Certificate Type"
    # insert choices
    set listType {}
    foreach v [openssl::Profile_List] {
	lappend listType $v
    }
    ttk::combobox $c.c1 -width 12  -textvariable [namespace current]::wizData(type) -values $listType
    $c.c1 delete 0 end
    $c.c1 insert 0 [lindex $listType 0]

    grid $c.l1 -row 0 -column 0 -sticky w -padx 4 -pady 4
    grid $c.c1 -row 0 -column 1 -sticky w -padx 4 -pady 4
    grid columnconfigure $c 0 -weight 0
    grid columnconfigure $c 1 -weight 0
    grid columnconfigure $c 2 -weight 1
    grid rowconfigure $c 0 -weight 0
    grid rowconfigure $c 1 -weight 1
    
}

            
.selfsignedwizard step {cert_name} -layout basic {
    variable wizData
    
    set c [$this widget clientArea]
    
    
    $this stepconfigure \
            -title {Common Name} \
            -subtitle {Enter subject name} \
            -pretext {Please enter the Common Name to appear in your certificate.} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
    
    label $c.l1 -text "Common Name"
    entry $c.e1 -width 40 -textvariable [namespace current]::wizData(CN)
    grid $c.l1 -row 0 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e1 -row 0 -column 1 -sticky w -padx 4 -pady 4
    grid columnconfigure $c 0 -weight 0
    grid columnconfigure $c 1 -weight 0
    grid columnconfigure $c 2 -weight 1
    grid rowconfigure $c 0 -weight 0
    grid rowconfigure $c 1 -weight 1
    
}

.selfsignedwizard step {cert_dn} -layout basic {
    variable wizData
    
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Distinguished Name} \
            -subtitle {Please give some information about the certificate owner} \
            -pretext {Please enter following information. This information will be stored in the certificate. Mandatory fields are marked with *} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
    
    # all optional and required fields
    set i 1 ;# field counter for widgets
    array set profdata [openssl::Profile_GetData $wizData(type)]
    global profile_options
    array set opts [array get profile_options]
    array set fieldlabels $opts(req.dn_fields)
    foreach {field dflt} $profdata(req.dn_fields) {
        
        #puts "creating field : $field / $dflt"
        # label
        set label $fieldlabels($field)
        
        # if required
        if {[lsearch -exact $profdata(req.dn_fields.required) $field] != -1} {
            append label " *"
        }
        
        if {$field == "C"} {
            label $c.l$i -text "$label"
	    set listC1 {}
            foreach v $::openssl::iso3166 {
		lappend listC1 $v
            }
            ttk::combobox $c.e$i -textvariable [namespace current]::wizData($field) -width 40 -values $listC1
            if {$wizData($field) == ""} {
                set wizData($field) $dflt
            }
#puts "listC1=$wizData($field)"
	    set tekC [lsearch $listC1 $wizData($field)]
	    $c.e$i delete 0 end
	    $c.e$i insert end [lindex $listC1 $tekC]
        } else  {
            label $c.l$i -text "$label"
            entry $c.e$i -width 40 -textvariable [namespace current]::wizData($field)
            if {$wizData($field) == ""} {
                set wizData($field) $dflt
            }
        }
        grid $c.l$i -row $i -column 0 -sticky w -padx 4 -pady 4
        grid $c.e$i -row $i -column 1 -sticky w -padx 4 -pady 4
        grid rowconfigure $c $i -weight 0
        incr i
    }
    grid rowconfigure $c $i -weight 1
    grid columnconfigure $c 0 -weight 0
    grid columnconfigure $c 1 -weight 0
    grid columnconfigure $c 2 -weight 1
    
    
}


.selfsignedwizard step {password} -layout basic {
    
    variable wizData
    
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Password} \
            -subtitle {Please enter a password to protect the key} \
            -pretext {The key will be protected by encrypting \
                it using your password. Later on, the private key can only be used \
                if you remember the password.} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
    
    label $c.l1 -text "Password"
    entry $c.e1 -width 40 -show * -textvariable [namespace current]::wizData(keypassword)
    label $c.l2 -text "Type again to verify"
    entry $c.e2 -width 40 -show * -textvariable [namespace current]::wizData(keypassword2)
    grid $c.l1 -row 0 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e1 -row 0 -column 1 -sticky w -padx 4 -pady 4
    grid $c.l2 -row 1 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e2 -row 1 -column 1 -sticky w -padx 4 -pady 4
    grid columnconfigure $c 0 -weight 0
    grid columnconfigure $c 1 -weight 0
    grid columnconfigure $c 2 -weight 1
    grid rowconfigure $c 0 -weight 0
    grid rowconfigure $c 1 -weight 0
    grid rowconfigure $c 2 -weight 1
    
}

.selfsignedwizard step {filename} -layout basic {
    
    variable wizData
    
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Filename} \
            -subtitle {Please enter the filenames to save your request} \
            -pretext {Please enter following filenames. The .csr file will containt the\
                certificate request to be submitted to the CA. The .key file will\
                contain your private key, protect it well.} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 

    set wizData(crt_fn) [file join [Config::Get folder.certificates] $wizData(CN).crt]
    set wizData(key_fn) [file join [Config::Get folder.keys] $wizData(CN).key]

    label $c.l1 -text "Certificate Filename"
    cagui::FileEntry $c.e1 -dialogtype save \
            -variable [namespace current]::wizData(crt_fn) \
            -title "Enter file name to save certificate" \
            -width 40 \
            -defaultextension .crt \
            -initialdir [Config::Get folder.certificates] \
            -filetypes [Config::Get filetype.certificate]
    
    label $c.l2 -text "Private Key Filename"
    cagui::FileEntry $c.e2 -dialogtype save \
            -variable [namespace current]::wizData(key_fn) \
            -title "Enter file name to save Private Key" \
            -width 40 \
            -initialdir [Config::Get folder.keys] \
            -defaultextension .key \
            -filetypes [Config::Get filetype.key]
            
    grid $c.l1 -row 0 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e1 -row 0 -column 1 -sticky w -padx 4 -pady 4
    grid $c.l2 -row 1 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e2 -row 1 -column 1 -sticky w -padx 4 -pady 4
    grid columnconfigure $c 0 -weight 0
    grid columnconfigure $c 1 -weight 0
    grid columnconfigure $c 2 -weight 1
    grid rowconfigure $c 0 -weight 0
    grid rowconfigure $c 1 -weight 0
    grid rowconfigure $c 2 -weight 1
    
    
}

.selfsignedwizard step {final} -layout basic {
    variable wizData
    
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Create Certificate} \
            -subtitle {Generate the key pair and the self signed certificate} \
            -pretext {You are about to generate a self signed certificate with these properties:} \
            -posttext {Click "Готово" to generate the "Certificate"}
    
    text $c.t1 -width 60 -heigh 10 \
            -yscrollcommand [list $c.vsb set]  -font {Times 10 bold italic}
    ttk::scrollbar $c.vsb -orient vertical -command [list $c.t1 yview]
    
    set fnt(std) [$c.t1 cget -font]
    set fnt(bold) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] bold]
    $c.t1 tag configure bold -font $fnt(bold)
    
    $c.t1 insert end "Certificate Profile:\n" bold
    $c.t1 insert end "\n"
    $c.t1 insert end "\t$wizData(type)\n"
    $c.t1 insert end "\n"
    $c.t1 insert end "Distinguished Name:\n" bold
    $c.t1 insert end "\n"
    
    array set profdata [openssl::Profile_GetData $wizData(type)]
    global profile_options
    array set opts [array get profile_options]
    array set fieldlabels $opts(req.dn_fields)
    foreach {field dflt} $profdata(req.dn_fields) {
        if {$wizData($field)!= ""} {
            #puts "creating field : $field / $dflt"
            # label
            set label $fieldlabels($field)
            $c.t1 insert end "\t$label = $wizData($field)\n"
        }
    }
    $c.t1 insert end "\n"
    $c.t1 insert end "File Names:\n" bold
    $c.t1 insert end "\n"
    $c.t1 insert end "\tPrivate Key: $wizData(key_fn)\n"
    $c.t1 insert end "\n"
    $c.t1 insert end "\tCertificate: $wizData(crt_fn)\n"
    $c.t1 insert end "\n"
    $c.t1 configure  -state disabled
    grid $c.t1 -row 0 -column 0 -sticky w ;# -padx 4 -pady 4
    grid $c.vsb -row 0 -column 1 -sticky ns
    grid columnconfigure $c 0 -weight 0
    grid columnconfigure $c 1 -weight 0
    grid columnconfigure $c 2 -weight 1
    grid rowconfigure $c 0 -weight 0
    grid rowconfigure $c 1 -weight 1

}



.selfsignedwizard eval {
        
    proc initwizard { this } {
        variable wizData
        
        array set wizData {
            type "Personal"
            O ""
            OU ""
            C ""
            ST ""
            L ""
            CN ""
            INN ""
            emailAddress ""
            keypassword ""
            keypassword2 ""
            crt_fn ""
            key_fn ""
        }
        
        
    }
    
    proc finalize {} {
        variable wizData
        
        array set dn [array get wizData]
        set profile $dn(type)
        
        openssl::CreateSelfSigned $profile dn
        
            
    }

    proc nextStep {this} {
        
        variable wizData
        
        set currentStep [$this cget -step]
        
        if {$currentStep == "type"} {
            if {$wizData(type)== "pers"} {
                $this configure -nextstep pers_attr
            } elseif {$wizData(type)== "org"} {
                $this configure -nextstep org_attr
            } elseif {$wizData(type)== "ssl"} {
                $this configure -nextstep ssl_attr
            }
        } elseif {$currentStep == "password"} {
            if {$wizData(keypassword) == ""} {
                tk_messageBox -title "Password" -message "Please specify a password." -icon error -parent .cm
                return -code break;
            }
            if {$wizData(keypassword) != $wizData(keypassword2)} {
                tk_messageBox -title "Password" -message "Passwords differ - please type again." -icon error  -parent .cm
                return -code break;
            }
        } elseif {$currentStep == "cert_name"} {
            if {$wizData(CN) == ""} {
                tk_messageBox -title "Информация об ошибке" -message "Please specify a name identifying the certificate owner." -icon error  -parent .cm
                return -code break;
            }
        } elseif {$currentStep == "cert_dn"} {
            set missingvalue 0
            set missinglist {}
            array set profdata [openssl::Profile_GetData $wizData(type)]
            foreach {field dflt} $profdata(req.dn_fields) {
                # if required
                if {[lsearch -exact $profdata(req.dn_fields.required) $field] != -1} {
                    #check if we have value
                    if {$wizData($field) == ""} {
                        set missingvalue 1
                        lappend missinglist "$field"
                        #break
                    }
                }
            }
            if {$missingvalue} {
                tk_messageBox -title "Информация об ошибке" -message "Please complete the following required fields: [join $missinglist {, }]." -icon error  -parent .cm
                return -code break;
            }
        }
    }
    
}

#wm minsize .selfsignedwizard 450 350

######################################
# SignWizard
#
# Wizard that collects information to generate a certificate
#
#

lappend auto_path .
package require tkwizard
package require openssl
package require Config


package provide SignWizard 1.0

tkwizard::tkwizard .cm.signwizard -title {Выпуск сертификата}

.cm.signwizard eval {
    variable wizData
    [namespace current]::originalWidgetCommand configure  -text "Выпуск сертификата" -font {Times 11 bold}

}

bind .cm.signwizard <<WizFinish>> {[%W namespace]::finalize}
bind .cm.signwizard <<WizCancel>> {[%W namespace]::cancel}
bind .cm.signwizard <<WizNextStep>> {[%W namespace]::nextStep %W}


.cm.signwizard step {type} -layout basic {
    variable wizData
    
    # use nice icon
    $this widget icon configure -image img_cert -background #eff0f1
    #cdc7c2
    
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Выпуск сертификата} \
            -subtitle {Профиль сертификата} \
            -pretext {Пожалуйста, укажите профиль, которому должен соответствовать сертификат. Сертификат будет сохранен в БД УЦ} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
    
    # combo box
    label $c.l1 -text "Профиль сертификата:"
    # insert choices
    set listCertT {}
    foreach v [openssl::Profile_List] {
	lappend listCertT $v
    }
    ttk::combobox $c.c1 -width 36  -textvariable [namespace current]::wizData(type) -values $listCertT
#    $c.c1 delete 0 end
#    $c.c1 insert 0 [lindex $listCertT 0]

    grid $c.l1 -row 0 -column 0 -sticky w -padx {5mm } -pady 5mm
    grid $c.c1 -row 0 -column 1 -sticky w -padx 0 -pady 5mm
    grid columnconfigure $c 0 -weight 0
    grid columnconfigure $c 1 -weight 0
    grid columnconfigure $c 2 -weight 1
    grid rowconfigure $c 0 -weight 0
    grid rowconfigure $c 1 -weight 1
    
}


.cm.signwizard step {cert_attr} -layout basic {
    global atrkval
    global rfregions
    variable wizData
    variable ::openssl::iso3166
    variable ::openssl::iso3166_map
    set c1 [$this widget clientArea]
#scrollframe
    set com2 "ttk::scrollbar $c1.vs -command {$c1.sf yview}"
    set com1     "scrolledframe $c1.sf -yscroll {$c1.vs set} -background #e0e0da"
    set com [subst $com1]
    eval $com1
    set com [subst $com2]
    eval $com

    pack $c1.vs -side right -fill y
    pack $c1.sf  -side top -fill both -expand 1 
    $c1.sf.scrolled configure -background white
    $c1.sf.scrolled configure -padx 10 -pady 10 
    set c $c1.sf.scrolled

    $this stepconfigure \
            -title {Подтвердите информацию для сертификата} \
            -subtitle {Проверьте информацию о владельце сертификата} \
            -pretext {Пожалуйста, проверьте следующую информацию. Эта информация будет помещена в сертификат.} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 

    if {$wizData(wizardtype) == "signreq" } {
#puts "SIGNWIZ-file-ckaid"
#puts "$wizData(crt_fn)"
#puts "$wizData(ckaid)"
	set csr_attr [openssl::CSR_GetSubjectDB "$wizData(crt_fn)"]
    } else {
	set csr_attr [openssl::CSR_GetSubject "$wizData(csr_fn)"]
    }
    foreach {attr value} $csr_attr {
        set wizData($attr) $value
    }
    
    # all optional and required fields
    set i 1 ;# field counter for widgets
    array set profdata [openssl::Profile_GetData $wizData(type)]
    global profile_options
    array set opts [array get profile_options]
    array set fieldlabels $opts(req.dn_fields)
    set pp 1
    foreach {field dflt} $profdata(req.dn_fields) {
            
        #puts "creating field : $field / $dflt"
        # label
        set label $fieldlabels($field)
        
        # if required
        if {[lsearch -exact $profdata(req.dn_fields.required) $field] != -1} {
            append label " *"
        }
        if {$pp < 10} {
    	    set label "  $pp. $label"
        } else {
    	    set label "$pp. $label"
        }
        if {$field == "C"} {
            set cc $[namespace current]::wizData($field)
            label $c.l$i -text "$label:\n     ($field)"
	    set listC2 {}
            foreach v $::openssl::iso3166 {
		lappend listC2 $v
            }
            ttk::combobox $c.e$i -width 100 -textvariable [namespace current]::wizData($field) -values $listC2
            if {$wizData($field) == ""} {
                set wizData($field) $dflt
            } else {
		set wizData($field) $iso3166_map($wizData($field))
            }
	    set tekC [lsearch $listC2 $wizData($field)]
	    $c.e$i delete 0 end
	    $c.e$i insert end [lindex $listC2 $tekC]
        } elseif {$field == "ST"} {
            label $c.l$i -text "$label:\n     ($field)"
            ttk::combobox $c.e$i -textvariable [namespace current]::wizData($field) -width 80 -values $rfregions
            if {$wizData($field) == ""} {
                set wizData($field) $dflt
            }
	    set tekC [lsearch $rfregions $wizData($field)]
	    $c.e$i delete 0 end
	    $c.e$i insert 0 [lindex $rfregions $tekC]
        } else  {
    	    global atrkval
	    set klab $fieldlabels($field)
            label $c.l$i -text "$label:\n     ($field)"
    	    if {[info exists atrkval($klab)]} {
    		set len $atrkval($klab)
        	set com "ttk::entry $c.e$i -textvariable [namespace current]::wizData($field) -validate key -validatecommand {Digit $c.e$i %i %P $len}  -style white.TEntry"
		set com1 [subst $com]
		eval $com1
	    } else {
        	ttk::entry $c.e$i -textvariable [namespace current]::wizData($field)
	    }
	    if {[info exists wizData($field)]} { 
        	if { $wizData($field) == ""} {
            	    set wizData($field) $dflt
        	}
            }
        }
        grid $c.l$i -row $i -column 0 -sticky w -padx 0 -pady 1mm
        grid $c.e$i -row $i -column 1 -sticky we -padx {0 5mm} -pady 1mm
#set cc $wizData($field)
#puts "FIELD=$cc"
	incr pp
        incr i
    }
    grid columnconfigure $c 1 -weight 1
#Прячем scrollbar
    if {$i < 7} {
	pack forget $c1.vs
    }

}

.cm.signwizard step {capassword} -layout basic {
    variable wizData
    
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Пароль} \
            -subtitle {Пожалуйста, введите пароль УЦ для доступа к закрытому ключу УЦ.} \
            -pretext {Закрытый ключ УЦ будет использован для подписания сертификата. \
                Пароль необходим для доступа к ключу, который необходим для генерации сертификата.} \
            -posttext {Нажмите "next" для продолжения.}
    
    label $c.l1 -text "Пароль УЦ"
    ttk::entry $c.e1 -width 40 -show * -textvariable [namespace current]::wizData(capassword)
    grid $c.l1 -row 0 -column 0 -sticky w -padx 4 -pady {5mm 1mm}
    grid $c.e1 -row 0 -column 1 -sticky w -padx 4 -pady {5mm 1mm}
    grid columnconfigure $c 0 -weight 0
}


.cm.signwizard step {final} -layout basic {
    variable wizData
    global db
    
    set c [$this widget clientArea]
    $this stepconfigure \
            -title {Выпуск сертификата} \
            -subtitle {Выпуск этого сертификата} \
            -pretext {Вы собираетесь издать сертификат со следующими свойствами:} \
            -posttext {Нажмите "Готово" для выпуска сертификата.}

    text $c.t1  -width 100 -heigh 15 \
            -yscrollcommand [list $c.vsb set]  -font {Times 10 bold italic} -background white
    ttk::scrollbar $c.vsb -orient vertical -command [list $c.t1 yview]
    
    set fnt(std) [$c.t1 cget -font]
    set fnt(bold) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] bold]
    $c.t1 tag configure bold -font $fnt(bold)
    
    $c.t1 insert end "Владелец сертификата:\n" bold
#    $c.t1 insert end "\n"
    $c.t1 insert end "\t$wizData(type)\n"
#    $c.t1 insert end "\n"
    $c.t1 insert end "Данные сертификата:\n" bold
#    $c.t1 insert end "\n"
    
    array set profdata [openssl::Profile_GetData $wizData(type)]
    global profile_options
    array set opts [array get profile_options]
    array set fieldlabels $opts(req.dn_fields)
    foreach {field dflt} $profdata(req.dn_fields) {
        if {$wizData($field)!= ""} {
            set label $fieldlabels($field)
            $c.t1 insert end "\t$label = $wizData($field)\n"
        }
    }
    
    $c.t1 configure  -state disabled
    pack $c.vsb -side right -fill y
    pack $c.t1 -side top -fill both 
}


.cm.signwizard eval {
        
    proc initwizard {wizardtype {initialfilename {}} ckaid treeID} {
        variable wizData
        
        array set wizData {
            csr_fn ""
            crt_fn ""
            type "Personal"
            O ""
            OU ""
            C ""
            ST ""
            L ""
            CN ""
            INN ""
            emailAddress ""
            capassword ""
            exit "cancel"
        }
    	set wizData(wizardtype) $wizardtype
        if {$wizardtype == "signreq"} {
    	    set wizData(crt_fn) $initialfilename
    	    set wizData(csr_fn) $initialfilename
#puts "SignWizard=$wizData(crt_fn)"
    	    set wizData(ckaid) $ckaid
    	    set wizData(cka_id) $ckaid
    	    set wizData(treeID) $treeID
	} 
#    [namespace current]::originalWidgetCommand configure  -text "Выпуск сертификата" -font {Times 11 bold}
    }

    proc finalize {} {
	global db
	global certdb
        variable wizData
        global certID
	global dbca

        #set wizData(exit) "ok"

        # issue the certificate
        array set attr [array get wizData]
        set profilename $attr(type)
	set err 0
        if {$wizData(wizardtype) == "signreq"} {
    	    set err [openssl::SignRequestByIndex $profilename attr]
	} else {
    	    set err [openssl::SignRequest $profilename attr]
	}
	if {$err != 0} {
        	return -code break;
	}
################
	certdb eval {select * from reqDB  where ckaID=$db(ckaID)} r {
	    certdb eval {begin transaction}
	    certdb eval {insert into reqDBAr values ($r(ckaID), $r(nick), $r(sernum), $r(subject), $r(type), $r(datereq), $r(status), $r(reqpem), $r(pkcs7))}
	    certdb eval {delete from reqDB where ckaID=$r(ckaID)}
	    certdb eval {end transaction}
	    $db(treeReq) delete $wizData(treeID)
	    RequestArManager_Update .cm $db(treeReqAr)
    	}
###############
        set l {}
	certdb eval {select * from certDB where ckaID=$db(ckaID)} vals {
#	parray vals
	    lappend l $vals(state)	    
	    lappend l $vals(notAfter)	    
	    lappend l $vals(dateRevoke)	    
	    lappend l $vals(sernum)	    
	    lappend l "unknown"	    
	    lappend l $vals(subject)	    
	    lappend l $vals(ckaID)
	}
	
	insertTree $l $db(treeCert) 0
	if {$certID != 0 } {
	    set num [expr $certID -1]
	    $db(treeCert) selection set $num
	} 
        tk_messageBox -title "Выпуск сертификата" -message "Сертификат выпущен и сохранен в БД УЦ.\nВы можете его экспортировать в файл и\nпередать заявителю." -icon info  -parent .cm
	place forget .cm.signwizard
	tk busy forget .cm.mainfr
	menu_enable
	set dbca ".cm"
    }
    proc nextStep {this} {
        
        variable wizData
        
        set currentStep [$this cget -step]
        
        if {$currentStep == "type"} {

        } elseif {$currentStep == "capassword"} {
            global db
            if {$wizData(capassword) == ""} {
                tk_messageBox -title "Пароль" -message "Пожалуйста, укажите пароль УЦ." -icon error  -parent .cm
                return -code break;
            }
	    set hash256 [::sha2::sha256 $wizData(capassword)]
	    if {$db(pasDB) != $hash256} {
        	tk_messageBox -title "Пароль" -icon error -message "Вы ошиблись с паролем\n" -parent .cm
        	return -code break;
	    }

        } elseif {$currentStep == "cert_attr"} {
            
            set missingvalue 0
            set missinglist {}
            array set profdata [openssl::Profile_GetData $wizData(type)]
            foreach {field dflt} $profdata(req.dn_fields) {
                # if required
                if {[lsearch -exact $profdata(req.dn_fields.required) $field] != -1} {
                    #check if we have value
                    if {$wizData($field) == ""} {
                        set missingvalue 1
                        lappend missinglist "$field"
                        #break
                    }
                }
            }
            if {$missingvalue} {
                tk_messageBox -title "Информация об ошибке" -message "Пожалуйста, заполните обязательные поля: [join $missinglist {, }]." -icon error  -parent .cm
                return -code break;
            }

        } elseif {$currentStep == "filename" &&  $wizData(wizardtype) != "signreq" } {
            if {$wizData(csr_fn) == "" || ![file exists $wizData(csr_fn)]} {
                tk_messageBox -title "Filename" -message "Please select a certificate request (.csr) file.\nThis should be a valid PKCS#10 certificate signing request file." -icon error 
                 -parent .cm
                return -code break;
            }
            if {$wizData(crt_fn) == ""} {
                tk_messageBox -title "Filename" -message "Please specify a filename to save the certificate." -icon error -parent .cm
                return -code break;
            }
        }
        set name ".cm.signwizard"
#        puts "tkwizard::cmd=$currentStep";
        tkwizard::handleEvent $name "<<WizNextStep>>";
#        puts "tkwizard::=.cm.signwizard"
    }
    
    
}

######################################
# RevokeWizard
#
# Wizard that collects information to revoke a certificate
#
#

tkwizard::tkwizard .cm.opendb -title "Открытие БД УЦ"

.cm.opendb eval {
    variable wizData
        array set wizData {
            dir_ca ""
        }

    [namespace current]::originalWidgetCommand configure  -text "Выбор существующей БД УЦ" -font {Times 11 bold}

}
bind .cm.opendb <<WizFinish>> {[%W namespace]::finalize}
bind cm.opendb <<WizNextStep>> {[%W namespace]::nextStep %W}

.cm.opendb step {dirname} -layout basic {
    variable wizData
    global env
    global home
    # use nice icon
    $this widget icon configure -image img_cert -background #eff0f1
    #cdc7c2
#    $this widget icon configure -image img_cert -background #c0bab4
        
    set c [$this widget clientArea]
    
#puts ".cm.opendb this=$this $c"

    $this stepconfigure \
            -title {Выберите каталог с БД УЦ} \
            -subtitle {Пожалуйста, укажите каталог, в котором находится БД УЦ} \
            -pretext {Пожалуйста, выберите каталог и введите пароль для БД.} \
            -posttext {После заполнения полей нажмите "Готово" для продолжения или "Отмена", если передумали.} 
    label $c.l0  -image db_ca_40x40 -compound left -bg white
    grid $c.l0 -row 0 -column 0 -columnspan 2 -sticky w -padx 2mm -pady 2mm
    label $c.l1 -text "Каталог с БД УЦ:" -bg white
#            -width 40 
    cagui::FileEntry $c.e1 \
            -dialogtype directory \
            -variable [namespace current]::wizData(dir_ca) \
            -title "Выберите каталог с БД УЦ" \
            -initialdir $env(HOME) \
            -parent .cm
    $c.e1 configure  -background white
    eval "$c.e1.but configure -command {feselect dir $c window {Выберите каталог с БД УЦ} $home {[namespace current]::wizData(dir_ca)} {}}"

    label $c.l2 -text "Введите пароль для БД УЦ:" -highlightbackground #cdc7c2
    ttk::entry $c.e2 -width 40 -show * -textvariable [namespace current]::wizData(password)
    # -highlightbackground #cdc7c2
    $c.e2 delete 0 end
bind $c.e2 <Key-Return> {tkwizard::cmd Finish .cm.opendb}
    grid $c.l1 -row 1 -column 0 -sticky w -padx 4 -pady 3mm
    grid $c.e1 -row 1 -column 1 -sticky news -padx {0 5mm} -pady 0
    grid columnconfigure $c 1 -weight 1
    grid $c.l2 -row 2 -column 0 -sticky w -padx 4 -pady 5
    grid $c.e2 -row 2 -column 1 -sticky w -padx {0 5mm} -pady 5

    focus $c.e2
}

.cm.opendb eval {
    global db
    proc initwizard { this } {
        variable wizData
        array set wizData {
            dir_ca ""
            password ""
        }
    }

    proc finalize {} {
	global certID
	global reqID
	global crlID
	global certIDRev
	global reqIDAr
	global keyID
	set certID 0
	set reqID 0
	set crlID 0
	set certIDRev 0
	set reqIDAr 0
	set keyID 0
	global dbca

	global profile_template
	global db
	global certdb
	global keydb
	global sernumdb
	global sernumreq
	global passdb
        variable wizData
        #set wizData(exit) "ok"
        array set attr [array get wizData]
	set dir $wizData(dir_ca)
	if {$wizData(dir_ca) == "" } {
            tk_messageBox -title "Выбор каталога БД УЦ" -icon error -message "Вы не выбрали каталога БД\n" -parent .cm
            return;
	}
#Exist DB	
	if { [file exists $wizData(dir_ca)] != 1 }  { 
        	tk_messageBox -title "Выбор каталога БД УЦ" -icon error -parent .cm \
        	-message "Не существует каталога $dir ."
        	return
	}
	if {$wizData(password) == "" } {
            tk_messageBox -title "Выбор каталога БД УЦ" -icon error -message "Вы ошиблись с паролем\n" -parent .cm
            return 
	}
#База для сертификатов
	set filedb [file join $dir "certdb.cadb"]
	set db(filedb) $filedb
	puts $filedb
	if {[file exist $filedb] == 0} {
    	    tk_messageBox -title "Выбор каталога БД УЦ" -icon error -message "Это не каталог БД УЦ. Отсутствует БД certdb.cadb.\n" -parent .cm
    	    return        
	}
	sqlite3 certdb $filedb
#Читаем главную таблицу 
#	set col [certdb eval {select mainDB.serNum, mainDB.dateCreateDB, mainDB.pasDB from mainDB}]

	array set db  [array get ::cafl63::db]
	if {[catch {
	    certdb eval {select * from mainDB} vals {
#		parray vals
		set db(certCA) $vals(certCA)
		set db(keyCA) $vals(keyCA)
		set db(pasDB) $vals(pasDB)
		set db(serNumCert) $vals(serNumCert)
		set db(serNumReq) $vals(serNumReq)
		set db(serNumCRL) $vals(serNumReq)
		set db(dateCreateDB) $vals(dateCreateDB)
		set df(profilesReq) $vals(profilesReq)
		set df(configReq) $vals(configReq)
	    }}]
	} {
        	tk_messageBox -title "Выбор каталога БД УЦ" -icon error -parent .cm -message "База данных $filedb испорчена.\n"
        	return -code break;        
	}
	set db(dir) $wizData(dir_ca)
	set file [file join $db(dir) rootca.pem]
	set fd [open $file w]
	puts $fd $db(certCA)
	close $fd
	set file [file join $db(dir) rootca.key]
	set fd [open $file w]
	puts $fd $db(keyCA)
	close $fd

	set hash256 [::sha2::sha256 $wizData(password)]
	if {$db(pasDB) != $hash256} {
            tk_messageBox -title "Выбор каталога БД УЦ" -icon error -message "Вы ошиблись с паролем\n" -parent .cm
            return -code break;
	}
if {0} {
	set filedb [file join $dir "keydb.cadb"]
	if {[file exist $filedb] == 0} {
        	tk_messageBox -title "Database CA with keys" -icon error -parent .cm
        	-message "Not exist database $filedb.\n"
		catch {certdb close}
		set certdb ""
		set keydb ""
        	return -code break;        
	}
	sqlite3 keydb $filedb
}
	for {set i 0} {$i <  5} {incr i} {
	    .cm.mainfr.ff.notbok tab $i -state normal
	}

	CertificateManager_Update .cm $db(treeCert)
	RequestManager_Update .cm $db(treeReq)
	RequestArManager_Update .cm $db(treeReqAr)
	CertificateRevoke_Update .cm $db(treeCertRev)
	CRLManager_Update .cm $db(treeCRL)

	openssl::Profile_Load
# load config if exists
# При открытии БД
	Config::LoadConfig
	if {[Config::Get system.openssl] != ""} {
    	    openssl::set_executable [Config::Get system.openssl]
	}
	set ca [lsearch $profile_template "CA.certificate"]
#	puts "CA=$ca"
	incr ca
	set rcert [file join $dir rootca.pem]
	set prof [lreplace $profile_template $ca $ca $rcert]
#	puts "PROFILE_TEMPLATE=$prof"
###PRIVATE_KEY
	set keyca [lsearch $profile_template "CA.private_key"]
	incr keyca
	set rkey [file join $dir rootca.key]
	set prof [lreplace $prof $keyca $keyca $rkey]
##DATABASE
	set indexdb [lsearch $profile_template "CA.database"]
	incr indexdb
	set rdb [file join $dir index.txt]
	set prof [lreplace $prof $indexdb $indexdb $rdb]

	set list [Config::Get system.tools]
        set i 0
        foreach {label varname} $list {
#puts "LABEL=$label"
#puts "VARNAME=$varname"

    	    if {$i == 0 } {
    		incr i
    		continue
    	    }
	    set indexdb [lsearch $profile_template "$varname"]
	    incr indexdb
	    set rdb  [Config::Get $varname]
#puts "rdb=$rdb"
	    set prof [lreplace $prof $indexdb $indexdb $rdb]
	}
	
	set indexdb [lsearch $profile_template "system.smime"]
	incr indexdb
	set prof [lreplace $prof $indexdb $indexdb "GOST 28147-89"]

	openssl::Template_SetData "profile_template" $prof
    
#Прячем стартовую страницу
	.cm.mainfr.ff.notbok hide .cm.mainfr.ff.notbok.p5


        .cm.mainfr.ff.notbok select .cm.mainfr.ff.notbok.p2
#	catch { [.cm.menunew.options entryconfigure 0 -state normal] }
place forget .cm.opendb
tk busy forget .cm.mainfr
menu_enable
	set dbca ".cm"
    }
}

lappend auto_path .
package require tkwizard
package require openssl
package require cagui

package provide Exportp12Wizard 1.0

tkwizard::tkwizard .cm.exportp12wizard -title "Экспорт сертификата в защищенный контейнер PKCS#12"

.cm.exportp12wizard eval {
    variable wizData

}

bind .cm.exportp12wizard <<WizFinish>> {[%W namespace]::finalize}
bind .cm.exportp12wizard <<WizCancel>> {[%W namespace]::cancel}
bind .cm.exportp12wizard <<WizNextStep>> {[%W namespace]::nextStep %W}



.cm.exportp12wizard step {filename} -layout basic {
    variable wizData
    
    # use nice icon
    $this widget icon configure -image img_cert -background #eff0f1
    #cdc7c2
        
    set c [$this widget clientArea]
    if {$wizData(crt_fn) == ""} {
	set stit "Выберите файлы с сертификатом и закрытым ключом, которые вы хотите экспортировать в контейнер PKCS12 (.p12))"
    } else {
	set stit "Выберите файл с закрытым ключом к выбранному сертификату, которые вы хотите экспортировать в контейнер PKCS12 (.p12))"
    }
    
    $this stepconfigure \
        -title {Введите имя файла} \
        -subtitle $stit \
        -pretext {Пожалуйста, выберите файлы и введите пароль к закрытому ключу.} \
        -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 

    label $c.l1 -text "Имя файла с сертификатом:"
    cagui::FileEntry $c.e1 \
	    -width 80 \
            -dialogtype open \
            -variable [namespace current]::wizData(crt_fn) \
            -title "Выбор сертификата" \
            -defaultextension .crt \
            -initialdir [Config::Get folder.certificates] \
            -filetypes [Config::Get filetype.certificate] \
            -command "namespace eval [namespace current] {if {\$wizData(key_fn) == \"\"} then {set wizData(key_fn) \[file rootname \$wizData(crt_fn)\].key}}"
    if {$wizData(crt_fn) != ""} {
	$c.e1.entry configure -state readonly
    }

    label $c.l2 -text "Имя файла с закрытым ключом:"
    cagui::FileEntry $c.e2 \
            -dialogtype open \
            -variable [namespace current]::wizData(key_fn) \
            -title \"Выбор закрытого ключа\"\]" \
            -initialdir [Config::Get folder.keys] \
            -defaultextension .key \
            -filetypes [Config::Get filetype.key]
    
    label $c.l3 -text "Пароль для закрытого ключа:"
    ttk::entry $c.e3 -width 40 -show * -textvariable [namespace current]::wizData(keypassword)

    grid $c.l1 -row 0 -column 0 -sticky w -padx 4 -pady {3mm 4}
    grid $c.e1 -row 0 -column 1 -sticky nwse -padx {0 5mm} -pady {3mm 1mm}
    if {$wizData(crt_fn) != ""} {
	pack forget $c.e1.but
    }
    grid $c.l2 -row 1 -column 0 -sticky w -padx 4 -pady 1mm
    grid $c.e2 -row 1 -column 1 -sticky nwse -padx {0 5mm} -pady 1mm
    grid $c.l3 -row 2 -column 0 -sticky w -padx 4 -pady 1mm
    grid $c.e3 -row 2 -column 1 -sticky w -padx {0 5mm} -pady 1mm
    
    grid columnconfigure $c 1 -weight 1
}

.cm.exportp12wizard step {password} -layout basic {
    variable wizData
    
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Пароль} \
            -subtitle {Пожалуйста, введите пароль для защиты файла PKCS#12} \
            -pretext {Контейнер PKCS#12 будет защищен шифрованием \
                с использованием вашего пароля. Последнее, закрытый ключ может быть извлечен \
                из контейнера PKCS#12 только, если вы не забудите пароль.} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
    
    label $c.l1 -text "Пароль:"
    ttk::entry $c.e1 -width 40 -show * -textvariable [namespace current]::wizData(password)
    label $c.l2 -text "Повторите пароль:"
    ttk::entry $c.e2 -width 40 -show * -textvariable [namespace current]::wizData(password2)
    grid $c.l1 -row 0 -column 0 -sticky w -padx {5mm 0} -pady {5mm 1mm}
    grid $c.e1 -row 0 -column 1 -sticky w -padx 0 -pady {5mm 1mm}
    grid $c.l2 -row 1 -column 0 -sticky w -padx {5mm 0} -pady 1mm
    grid $c.e2 -row 1 -column 1 -sticky w -padx 0 -pady 1mm
#    grid columnconfigure $c 1 -weight 0
}


.cm.exportp12wizard step {p12name} -layout basic {
    variable wizData
    
    set c [$this widget clientArea]
    
    $this stepconfigure \
        -title {Имя файла} \
        -subtitle {Пожалуйста, введите имена файлов, содержимое которых будет сохранено в контейнере PKCS12} \
        -pretext {Пожалуйста, введите следующее имя файла.} \
        -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 

    if {$wizData(p12_fn)==""} {
        # default file name
        #regsub "\.crt" $wizData(crt_fn) ".p12" wizData(p12_fn)
        set wizData(p12_fn) "[file rootname $wizData(crt_fn)].p12"
    }
    # friendly names for user/ca
    # -> read this from cert
    if {$wizData(username)==""} {
      set attr11 [openssl::Certificate_GetInfo -filename $wizData(crt_fn) -get subject]
#puts "PKCS12=$attr11"
        array set attr [openssl::Certificate_GetInfo -filename $wizData(crt_fn) -get subject]
#parray attr
        set wizData(username) $attr(CN)
    }
    # friendly name for CA
    # -> from configuration
    if {$wizData(caname)==""} {
        set wizData(caname) [Config::Get system.caname]
    }
    
    
    label $c.l1 -text "Имя файла для контейнера PKCS#12:"
    cagui::FileEntry $c.e1 \
	    -width 80 \
            -dialogtype save \
            -variable [namespace current]::wizData(p12_fn) \
            -title "Введите имя файла для PKCS#12" \
            -initialdir [Config::Get folder.p12] \
            -defaultextension .p12 \
            -filetypes [Config::Get filetype.p12]
                
    label $c.l2 -text "Friendly для экспортируемого сертификата:"
    ttk::entry $c.e2 -textvariable [namespace current]::wizData(username)

    label $c.l3 -text "Friendly для корневого сертификата УЦ:"
    ttk::entry $c.e3 -textvariable [namespace current]::wizData(caname)
    
    grid $c.l1 -row 0 -column 0 -sticky w -padx 4 -pady {5mm 1mm}
    grid $c.e1 -row 0 -column 1 -sticky we -padx {0 5mm} -pady {5mm 1mm}
    grid $c.l2 -row 1 -column 0 -sticky w -padx 4 -pady 1mm
    grid $c.e2 -row 1 -column 1 -sticky we -padx {0 5mm} -pady 1mm
    grid $c.l3 -row 2 -column 0 -sticky w -padx 4 -pady 4
    grid $c.e3 -row 2 -column 1 -sticky we -padx {0 5mm} -pady 1mm
    grid columnconfigure $c 1 -weight 1
}



.cm.exportp12wizard step {final} -layout basic {
    variable wizData
    
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Экспорт сертификата} \
            -subtitle {Экспорт сертификата в формате/контейнере PKCS#12} \
            -pretext {Вы экспортируете следующий сертификат:} \
            -posttext {Нажмите "Готово" для создания файла/контейнера PKCS#12.}
    
    text $c.t1 -width 110 -heigh 15 \
            -yscrollcommand [list $c.vsb set]  -font {Times 10 bold italic}
    ttk::scrollbar $c.vsb -orient vertical -command [list $c.t1 yview]
    
    set fnt(std) [$c.t1 cget -font]
    set fnt(bold) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] bold]
    $c.t1 tag configure bold -font $fnt(bold)
    
    $c.t1 insert end "Создание PKCS#12 из:\n" bold
    $c.t1 insert end "\n"
    $c.t1 insert end "\tсертификат: $wizData(crt_fn)\n"
    $c.t1 insert end "\n"
    $c.t1 insert end "\tзакрытый ключ: $wizData(key_fn)\n"
    $c.t1 insert end "\n"
    $c.t1 insert end "Сохранть в:\n" bold
    $c.t1 insert end "\n"
    $c.t1 insert end "\tФайл PKCS#12: $wizData(p12_fn)\n"
    $c.t1 insert end "\n"
    
    $c.t1 configure  -state disabled
    grid $c.t1 -row 0 -column 0 -sticky nwse ;# -padx 4 -pady 4
    grid $c.vsb -row 0 -column 1 -sticky ns 
    grid columnconfigure $c 0 -weight 1
}


.cm.exportp12wizard eval {
        
    proc initwizard { this file} {
        variable wizData
        
        array set wizData {
            crt_fn ""
            key_fn ""
            keypassword ""
            p12_fn ""
            password ""
            password2 ""
            username ""
            caname ""
        }
        set wizData(crt_fn) $file
    }
    
    proc finalize {} {
	global dbca
        variable wizData
        #set wizData(exit) "ok"
        
        array set attr [array get wizData]
        #set profile $attr(type)
        set err [openssl::ExportPKCS12 attr]
        if { $err != 0 } {
                return -code break;
        }
        tk_messageBox -title "Экспорт в PKCS#12" -message "Ваш сертификат и закрытый ключ сохранены в файле:\n $wizData(p12_fn)." -icon info  -parent .cm
        file delete -force $wizData(crt_fn)
#        file delete $wizData(key_fn)
	set dbca ".cm"
#puts ".cm.exportp12wizard CANCEL"
	[namespace current]::cancel
    }
    proc cancel {} {
	place forget .cm.exportp12wizard
	catch {tk busy forget .cm.mainfr}
	catch {menu_enable}
    }

    proc nextStep {this} {
        
        variable wizData
        
        set currentStep [$this cget -step]
        
        if {$currentStep == "password"} {
            if {$wizData(password) == ""} {
                tk_messageBox -title "Пароль" -message "Пожалуйста, задайте пароль." -icon error  -parent .cm
                return 
            }
            if {$wizData(password) != $wizData(password2)} {
                tk_messageBox -title "Пароль" -message "Пароли разные - повторите." -icon error -parent .cm
                return 
            }
        } elseif {$currentStep == "filename"} {
            if {$wizData(crt_fn) == "" || ![file exists $wizData(crt_fn)]} {
                tk_messageBox -title "Имя файла" -message "Пожалуйста, выберите файл с сертификатом (.crt).\nЭто должен быть файл с валидным сертификатом." -icon error -parent .cm
                return
            }
            if {$wizData(key_fn) == "" || ![file exists $wizData(key_fn)]} {
                tk_messageBox -title "Имя файла" -message "Пожалуйста, выберите файл с закрытым ключом (.key).\nЭто должен быть файл с валидным ключом." -icon error -parent .cm
                return 
            }
            if {$wizData(keypassword) == ""} {
                tk_messageBox -title "Пароль" -message "Пожалуйста, задайте пароль для закрытого ключа." -icon error -parent .cm
                return 
            }
        } elseif {$currentStep == "p12name"} {
            if {$wizData(p12_fn) == ""} {
                tk_messageBox -title "Имя файла" -message "Пожалуйста, выберите файл для сохранения контейнера PKCS#12 (.p12)." -icon error -parent .cm
                return 
            }
            if {$wizData(username) == "" || $wizData(caname) == ""} {
                tk_messageBox -title "Filename" -message "Пожалуйста, задайте friendly user name для вашего сертификата и  friendly name для корневого сертификата." -icon error -parent .cm
                return 
            }
            
        }
        set name ".cm.exportp12wizard"
#        puts "tkwizard::cmd=$currentStep";
        tkwizard::handleEvent $name "<<WizNextStep>>";
#        puts "tkwizard::=.cm.exportp12wizard"
    }
    
    
}

#wm minsize .cm.exportp12wizard 450 350

######################################
# CRLWizard
#
# Wizard that collects information to generate a certificate revocation list
#
#

lappend auto_path .
package require tkwizard
package require openssl
package require Config

package provide CRLWizard 1.0

tkwizard::tkwizard .cm.crlwizard -title "Выпуск списка отозванных сертификатов (CRL)"

.cm.crlwizard eval {
    variable wizData

    # default values
    catch {unset wizData}
    array set wizData {
        crl_fn ""
        capassword ""
        exit "cancel"
    }
        
}

bind .cm.crlwizard <<WizFinish>> {[%W namespace]::finalize}
bind .cm.crlwizard <<WizCancel>> {[%W namespace]::cancel}
bind .cm.crlwizard <<WizNextStep>> {[%W namespace]::nextStep %W}


.cm.crlwizard step {capassword} -layout basic {
    variable wizData
    
    set c [$this widget clientArea]

    $this widget icon configure -image img_cert_bad -background #eff0f1

    $this stepconfigure \
            -title {Список отозванных сертификатов} \
            -subtitle {Пожалуйста, введите пароль УЦ для доступа к закрытому ключу УЦ.} \
            -pretext {Закрытый ключ УЦ будет использован для подписания списка отозванных сертификатов. \
                Пароль необходим для доступа к ключу, который необходим для генерации списка отозванных сертификатов.} \
            -posttext {Нажмите "След>" для продолжения или "Отмена", если передумали.}
    
    label $c.l1 -text "Пароль УЦ:"
    ttk::entry $c.e1 -width 40 -show * -textvariable [namespace current]::wizData(capassword)
    grid $c.l1 -row 0 -column 0 -sticky w -padx 4 -pady 5mm
    grid $c.e1 -row 0 -column 1 -sticky w -padx 4 -pady 5mm
#    grid columnconfigure $c 0 -weight 0
    focus $c.e1

}


.cm.crlwizard step {final} -layout basic {
    variable wizData
    
    set c [$this widget clientArea]
    
    $this stepconfigure \
            -title {Создание списка отозванных сертификатов} \
            -subtitle {Выпуск списка отозванных сертификатов} \
            -pretext {Вы собираетесь выпустить список отозванных сертификатов.} \
        -posttext {Нажмите "Готово" для выпуска СОС/CRL.}

    text $c.t1 -width 80 -heigh 14 \
            -yscrollcommand [list $c.vsb set] -font {Times 10 bold italic}
    ttk::scrollbar $c.vsb -orient vertical -command [list $c.t1 yview]
    
    set fnt(std) [$c.t1 cget -font]
    set fnt(bold) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] bold]
    $c.t1 tag configure bold -font $fnt(bold)
    
    $c.t1 insert end "Дата:\n" bold
    $c.t1 insert end "\n"
    $c.t1 insert end "\t[clock format [clock seconds] -format {%d %B %Y} ] \n"
    $c.t1 insert end "\n"
    $c.t1 insert end "Список отозванных сертификатов будет помещен в базу данных\n" bold
    $c.t1 insert end "\n"
    
    $c.t1 configure  -state disabled
    grid $c.t1 -row 0 -column 0 -sticky nwse ;# -padx 4 -pady 4
    grid $c.vsb -row 0 -column 1 -sticky ns
    grid columnconfigure $c 0 -weight 1
}


.cm.crlwizard eval {
        
    proc initwizard { this } {
        variable wizData
        
        array set wizData {
            crl_fn ""
            capassword ""
            exit "cancel"
        }
    
    }
    
    proc finalize {} {
        variable wizData
        set wizData(exit) "ok"
        
        array set attr [array get wizData]
        #set profile $attr(type)
        openssl::GenerateCRL attr
        #openssl::docommand gencrl profile_template attr
        
        # update gui
        #::CertificateManager_Update .cm
                
place forget .cm.crlwizard
tk busy forget .cm.mainfr
menu_enable
    }
    proc cancel {} {
	place forget .cm.crlwizard
	catch {tk busy forget .cm.mainfr}
	catch {menu_enable}
    }
    proc nextStep {this} {
        
        variable wizData
        
        set currentStep [$this cget -step]
        
        if {$currentStep == "capassword"} {
            global db
            if {$wizData(capassword) == ""} {
                tk_messageBox -title "Пароль" -message "Пожалуйста, укажите пароль УЦ." -icon error  -parent .cm
                return -code break;
            }
	    set hash256 [::sha2::sha256 $wizData(capassword)]
	    if {$db(pasDB) != $hash256} {
        	tk_messageBox -title "Пароль" -icon error -message "Вы ошиблись с паролем\n" -parent .cm
        	return -code break;
	    }

        } elseif {$currentStep == "filename"} {
            if {$wizData(crl_fn) == "" } {
                tk_messageBox -title "Имя файла" -message "Пожалуйста, выберите файл для сохранения СОС/CRL (*.crl)." -icon error -parent .cm
                return -code break;
            }
        }
        set name ".cm.crlwizard"
#        puts "tkwizard::cmd=$currentStep";
        tkwizard::handleEvent $name "<<WizNextStep>>";
#        puts "tkwizard::=.cm.crlwizard"
    }
    
    
}

image create photo img_cert -data {}
img_cert   copy iconCertKey_71x100   -subsample 2 2
image create photo img_cert_bad -data {}
img_cert_bad   copy CertStampBad_71x100   -subsample 2 2

#wm minsize .crlwizard 450 350

######################################
# RevokeWizard
#
# Wizard that collects information to revoke a certificate
#
#

lappend auto_path .
package require tkwizard
package require openssl

package provide RevokeWizard 1.0

tkwizard::tkwizard .cm.revokewizard -title "Certificate Revocation Wizard"

.cm.revokewizard eval {
    variable wizData

}

bind .cm.revokewizard <<WizFinish>> {[%W namespace]::finalize}
bind .cm.revokewizard <<WizCancel>> {[%W namespace]::cancel}
bind .cm.revokewizard <<WizNextStep>> {[%W namespace]::nextStep %W}

.cm.revokewizard step {cert_attr} -layout basic {
    variable wizData

    # use nice icon
    $this widget icon configure -image img_cert -background #eff0f1
    #cdc7c2
    
    set c1 [$this widget clientArea]
#scrollframe
if {1} {
    set com2 "ttk::scrollbar $c1.vs -command {$c1.sf yview}"
    set com1     "scrolledframe $c1.sf -yscroll {$c1.vs set} -background #e0e0da"
#      -height 500 -width 350
    set com [subst $com1]
    eval $com1
    set com [subst $com2]
    eval $com

    pack $c1.vs -side right -fill y
    pack $c1.sf  -side top -fill both -expand 1 -ipadx 0 -ipady 0
    $c1.sf.scrolled configure -background white
    $c1.sf.scrolled configure -padx 0 -pady 20 
    set c $c1.sf.scrolled
}
#set c $c1

    if {$wizData(wizardtype) == "examinebyindex"} {
	$this stepconfigure \
            -title {Данные из запроса} \
            -subtitle {Пожалуйста, просмотрите эти данные} \
            -pretext {Пожалуйста, проверьте запрос, который вы рассматриваете.} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
    } else {
	$this stepconfigure \
            -title {Данные из сертификата} \
            -subtitle {Пожалуйста, просмотрите эти данные} \
            -pretext {Пожалуйста, проверьте сертификат, который вы отзываете.} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.} 
    }
    
#puts "CHECK REVOKE=$wizData(wizardtype)"
    if {$wizData(wizardtype) == "examinebyindex"} {
	set attributes [openssl::Request_GetInfo -filename $wizData(crt_fn) -get subject]
	if {[lindex $attributes 1] == "" } {
	    set attributes [lrange $attributes 2 end]
	}
    } else {
	set attributes [openssl::Certificate_GetInfo -filename $wizData(crt_fn) -get subject]
    }
#puts "CHECK REVOKE END=$attributes"

    global profile_options
    array set opts [array get profile_options]
    array set fieldlabels $opts(req.dn_fields)
#puts "CHECK REVOKE2"
#parray fieldlabels
    set i 0
    set pp 1
    foreach {attr value} $attributes {
#puts "attr=$attr"
#set attr [string range $attr 1 end]
#puts "value=$value"
        if {$pp < 10} {
    	    set attrlabel " $pp. $fieldlabels($attr)"
        } else {
    	    set attrlabel "$pp. $fieldlabels($attr)"
        }
#        set attrlabel $fieldlabels($attr)
        set wizData($attr) $value

        label $c.l$i -text "$attrlabel:\n     ($attr)"
        ttk::entry $c.e$i -state readonly -textvariable [namespace current]::wizData($attr)
        
        grid $c.l$i -row $i -column 0 -sticky w -padx 0 -pady {0 1mm}
        grid $c.e$i -row $i -column 1 -sticky we -padx {1mm 2mm} -pady {0 1mm}
        grid rowconfigure $c $i -weight 1
                
        incr i
        incr pp
    }
#puts "CHECK REVOKE3"
    if {$wizData(wizardtype) == "examinebyindex"} {
	ttk::button $c.b$i -text "Подробности" -command "cmd::ViewByIndexReq \"$wizData(ckaid)\""
    } else {
	ttk::button $c.b$i -text "Подробности" -command "Dialog_ShowCertificate \"$wizData(crt_fn)\""
    }
#puts "CHECK REVOKE4"
    grid $c.b$i -row $i -column 1 -sticky e -padx 2mm -pady 2mm
    incr i
    grid columnconfigure $c 1 -weight 1
}


.cm.revokewizard step {capassword} -layout basic {
    variable wizData
    global
    
    set c [$this widget clientArea]
    
    if {$wizData(wizardtype) == "examinebyindex"} {
	$this stepconfigure \
            -title {Пароль} \
            -subtitle {Пожалуйста, введите пароль УЦ для доступа к закрытому ключу УЦ.} \
            -pretext {Закрытый ключ УЦ будет использован для проверки ваших полномочий. \
                Пароль необходим для доступа к ключу, который необходим для рассмотрения запроса.} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.}
    } else {
	$this stepconfigure \
            -title {Пароль} \
            -subtitle {Пожалуйста, введите пароль УЦ для доступа к закрытому ключу УЦ.} \
            -pretext {Закрытый ключ УЦ будет использован для отзыва сертификата. \
                Пароль необходим для доступа к ключу, который необходим для отзыва сертификата.} \
            -posttext {Нажмите "След" для продолжения или "Отмена", если вы передумали.}
    }    
    label $c.l1 -text "Пароль УЦ:"
    ttk::entry $c.e1 -width 40 -show * -textvariable [namespace current]::wizData(capassword)
    grid $c.l1 -row 0 -column 0 -sticky w -padx 4 -pady {5mm 2mm}
    grid $c.e1 -row 0 -column 1 -sticky w -padx 4 -pady {5mm 2mm}
    grid columnconfigure $c 0 -weight 0
    if {$wizData(wizardtype) == "examinebyindex"} {
	label $c.l2 -text "Примите решение:" -bg skyblue -font {Times 10 bold italic}
	grid $c.l2 -row 1 -column 0 -sticky w -padx {4 0} -pady 4
	ttk::radiobutton $c.r1 -text "Отклонить заявку" -value 0 -variable [namespace current]::wizData(solution)
	ttk::radiobutton $c.r2 -text "Утвердить заявку" -value 1 -variable [namespace current]::wizData(solution)
#	$c.r2 state selected
	grid $c.r1 -row 2 -column 1 -sticky w -padx 0 -pady 2mm
	grid $c.r2 -row 3 -column 1 -sticky w -padx 0 -pady 2mm
    }    
}


.cm.revokewizard step {final} -layout basic {
    variable wizData
    global solution
    
    set c [$this widget clientArea]
    
    if {$wizData(wizardtype) == "examinebyindex"} {
	$this stepconfigure \
            -title {Рассмотрение заявки} \
            -subtitle {Принятие решение по запросу} \
            -pretext {Вы принимаете решение по следующему запросу:} \
            -posttext {Нажмите "Готово" для принятия решения.}
    } else {
	$this stepconfigure \
            -title {Отзыв сертификата} \
            -subtitle {Отозвать этот сертификат} \
            -pretext {Вы желаете отозвать следующий сертификат:} \
            -posttext {Нажмите "Готово" для отзыва сертификата.}
    }
    
    text $c.t1  -width 100 -heigh 15 \
            -yscrollcommand [list $c.vsb set] -font {Times 10 bold italic} -bg white
    ttk::scrollbar $c.vsb -orient vertical -command [list $c.t1 yview]
    
    set fnt(std) [$c.t1 cget -font]
    set fnt(bold) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] bold]
    $c.t1 tag configure bold -font $fnt(bold)
    
    $c.t1 insert end "Distinguished Name:\n" bold
    if {$wizData(wizardtype) == "examinebyindex"} {
	set dn [openssl::Request_GetInfo -filename $wizData(crt_fn) -get subject]
    } else {
	set dn [openssl::Certificate_GetInfo -filename $wizData(crt_fn) -get subject]
    }
    foreach {field value} $dn {
        if {$value!= ""} {
            set label [::openssl::GetDialogFieldLabel $field]
            $c.t1 insert end "\t$label = $value\n"
        }
    }
    if {$wizData(wizardtype) == "examinebyindex"} {
	if {$wizData(solution) == 0 } {
	    $c.t1 insert end  "Ваше решение: Отклонить заяку"
	} else {
	    $c.t1 insert end  "Ваше решение: Принять заяку"
	}
    }    
        
    $c.t1 configure  -state disabled
    
    pack $c.t1 -side left -fill both -expand 1 
    pack $c.vsb -side right -fill y
if {0} {
    grid $c.t1 -row 0 -column 0 -sticky w ;# -padx 4 -pady 4
    grid $c.vsb -row 0 -column 1 -sticky ns
    grid columnconfigure $c 0 -weight 0
    grid columnconfigure $c 1 -weight 0
    grid columnconfigure $c 2 -weight 1
    grid rowconfigure $c 0 -weight 0
    grid rowconfigure $c 1 -weight 1
}
}


.cm.revokewizard eval {
        
    proc initwizard { this wizardtype {initialfilename {}} ckaid treeID} {
set name ".cm.revokewizard"
    upvar #0 [namespace current]::@$name-state wizState
        variable wizData
        
        array set wizData {
            csr_fn ""
            crt_fn ""
            type "Personal"
            O ""
            OU ""
            C ""
            ST ""
            L ""
            CN ""
            INN ""
            emailAddress ""
            capassword ""
            exit "cancel"
        }
        if {$wizardtype=="revokebyindex" || $wizardtype=="examinebyindex" } {
            $this order cert_attr capassword final
        } else  {
            $this order filename cert_attr capassword final
        }
        set wizData(crt_fn) $initialfilename
        set wizData(ckaid) $ckaid
        set wizData(cka_id) $ckaid
        set wizData(treeID) $treeID
        set wizData(wizardtype) $wizardtype
	if {$wizardtype == "examinebyindex"} {
	    [namespace current]::originalWidgetCommand configure  -text "Принятие решения по запросу" -font {Times 11 bold}
    	    set wizData(solution) 1
	} else {
	    [namespace current]::originalWidgetCommand configure  -text "Отзыв сертификата" -font {Times 11 bold}
	}
    }
    
    proc finalize {} {
        variable wizData
        global db
        
        array set attr [array get wizData]
	if {$wizData(wizardtype) == "examinebyindex"} {
    	    openssl::ExamineRequest attr
    	    cancel
	} else {
    	    openssl::RevokeCertificate attr
    	    cancel
	}
    }
    proc cancel {} {
	place forget .cm.revokewizard
	catch {tk busy forget .cm.mainfr}
	catch {menu_enable}
    }

    proc nextStep {this} {
        global db
        variable wizData
        array set attr [array get wizData]

        set currentStep [$this cget -step]
#puts ".cm.revokewizard: currentStep=$currentStep"
        if {$currentStep == "cert_attr"} {
	    set ll [$db(treeReq) item $attr(treeID) -values]
	    set status [lindex $ll 5]
#puts "STATUS=\"$status\""
	    if {$status != "рассматривается"} {
    		set answer [tk_messageBox -icon question \
            	    -message "Запрос уже утвержден\nБудете пересматривать решение?" \
            	    -parent .cm \
            	    -title "Обработка запроса" \
            	    -type yesno]

    		#puts "answer=$answer"
    		if {$answer != "yes"} {
    		    cancel
    		    return
    		} 
	    }
	}
        if {$currentStep == "capassword"} {
            global db
            if {$wizData(capassword) == ""} {
                tk_messageBox -title "Пароль" -message "Пожалуйста, укажите пароль УЦ." -icon error  -parent .cm
                return -code break;
            }
	    set hash256 [::sha2::sha256 $wizData(capassword)]
	    if {$db(pasDB) != $hash256} {
        	tk_messageBox -title "Пароль" -icon error -message "Вы ошиблись с паролем\n" -parent .cm
        	return -code break;
	    }

        }
        set name ".cm.revokewizard"
#        puts "tkwizard::cmd=$currentStep";
        tkwizard::handleEvent $name "<<WizNextStep>>";
#        puts "tkwizard::=$name"

    }
}

#wm minsize .revokewizard 500 400

proc showContextMenuReq {w x y rootx rooty} {
    set treeID {}
    set s {}
#puts "showContextMenuReq=\"$w\" \"rooty\""
#6 -ckaID
    foreach i [$w selection] {
        lappend s [lindex [$w item $i -value] 6]
        set tree [lindex [$w item $i -value] 0]
        lappend treeID [string range $tree 4 end]
    }
#puts "showContextMenuReq=$s"
#puts "treeID=$treeID" 

    if {$s != ""} {

        catch {destroy .contextMenu}
        menu .contextMenu -tearoff false

        .contextMenu configure -title "Certificate Request"
        .contextMenu add command \
                -label "Ознакомиться" \
                -command [list cmd::ViewByIndexReq $s]
        .contextMenu add command \
                -label "Принять решение" \
                -command [list cmd::WizardExamineRequestByIndex $s $treeID]
        .contextMenu add command \
                -label "Выпустить сертификат" \
                -command [list cmd::WizardSignRequestByIndex $s $treeID]
        .contextMenu add command \
                -label "Просмотреть сертификат" \
                -command [list cmd::ViewByIndexCertFromReq $s]

        tk_popup .contextMenu $rootx $rooty
	.contextMenu configure -activebackground #cdc7c2
	.contextMenu configure -background #e0e0da

    }

}

proc showContextMenuReqAr {w x y rootx rooty} {
    set treeID {}
    set s {}
#puts "showContextMenuReq=\"$w\" \"rooty\""
#6 -ckaID
    foreach i [$w selection] {
        lappend s [lindex [$w item $i -value] 6]
        set tree [lindex [$w item $i -value] 0]
    }
#puts "showContextMenuReqAr=$s"

    if {$s != ""} {

        catch {destroy .contextMenu}
        menu .contextMenu -tearoff false

        .contextMenu configure -title "Certificate Request Archiv"
        .contextMenu add command \
                -label "Просмотреть запрос" \
                -command [list cmd::ViewByIndexReq $s]
        .contextMenu add command \
                -label "Просмотреть сертификат" \
                -command [list cmd::ViewByIndexCertFromReq $s]

        tk_popup .contextMenu $rootx $rooty

	.contextMenu configure -activebackground #cdc7c2
	.contextMenu configure -background #e0e0da

    }
}


proc showContextMenuCRL {w x y rootx rooty} {
    set treeID {}
    set s {}
#puts "showContextMenuCRL=\"$w\" \"rooty\""
#1 -ckaID - ID
    foreach i [$w selection] {
        lappend s [lindex [$w item $i -value] 1]
    }
#puts "showContextMenuCRL=$s"
#puts "treeID=$treeID" 

    if {$s != ""} {

        catch {destroy .contextMenu}
        menu .contextMenu -tearoff false

        .contextMenu configure -title "CRL"
        .contextMenu add command \
                -label "Просмотреть CRL" \
                -command [list cmd::ViewByIndexCRL $s]
        .contextMenu add command \
                -label "Экспорт CRL" \
                -command [list cmd::PublishByIndex $s crl]

        tk_popup .contextMenu $rootx $rooty
	.contextMenu configure -activebackground #cdc7c2
	.contextMenu configure -background #e0e0da

    }

}


#destroy .



# a  few interesting variables
set app(name) "УЦ ФЗ-63"
set app(title) " УЦ ФЗ-63 - Удостоверяющий центр на базе OpenSSL, SQLITE3 и Tcl/Tk"

# keep state of certificate manager gui
set config(gui) Wizard
# debugging
set config(debug) 0

set MenuCommands_Wizard {
    
    #setup {Setup} {
        cmd {Setup Root CA} {cmd::SetupRootCA}
    }
    database {БД УЦ} {
        cmd {Создать новую БД} {cmd::CreateDB}
        - - -
        cmd {Открыть БД} {cmd::OpenDB}
        - - -
        cmd {Закрыть БД} {cmd::CloseDB}
        - - -
        #cmd {Delete DB} {cmd::DeleteDB}
        #- - -
        #cmd {Save DB} {cmd::SaveDB}
        #- - -
        cmd {Выход} {cmd::ExitDB}
    }
    certificates {Сертификаты} {
        cmd {Экспорт всех сертификатов} { exportCerts all}
        - - -
        cmd {Экспорт новых сертификатов} { exportCerts news}
        - - -
        cmd {Экспорт в контейнер PKCS12} {cmd::WizardExportPKCS12 ""}
        - - -
        cmd {Запрос на сертификат в файле} {cmd::WizardCreateRequest}
        #- - -
        #cmd {Create Self-Signed Certificate} {cmd::WizardCreateSelfSigned}
        - - -
        cmd {Просмотреть сторонний сертификат} {cmd::ViewCertificateInfo}
        - - -
        cmd {Просмотреть сторонний запрос} {cmd::ViewRequestInfo}
        - - -
        cmd {Просмотреть сторонний CRL} {cmd::ViewCRLInfo}
    }
    options {Средства} {
        cmd {Настройки} {cmd::Options}
        - - -
        cmd {Протокол} {Log::WindowToggle .log}
        #profile {Configure Certificate Type} {
            cmd {Personal Certificates} {cmd::SetupProfiles "Personal"}
            cmd {SSL Server Certificates} {cmd::SetupProfiles "SSL Server"}
        }
    }
    help {Справка} {
        cmd {О приложении} {About .about}
        #- - -
        #cmd {Help} {cmd::Help}
        #cmd {Readme} {cmd::ShowHelp doc/readme.html}
        #cmd {Usage Guide} {cmd::ShowHelp doc/usage-guide.html}
    }

}
image create photo creator -file [file join $myDir "orlov_250x339.png"]

image create photo creator_small -data {
R0lGODlhPABOAOf/ABQUHBwTExYVGBgUHhkVEh8UEB0WGygVFxkaIRkbGRwbFSAaFSQYHiQZFxgcHhwbHh8bGiQdFCgcFB8gJx8hHyUgGiMgIx0iIyofGyQhICkgISMj
HDIgHjcgGyskGTAjGjEiJy0kJC8kIDUjHColKSomJSwmICUoJzsoGEEnHjspHUAnIzItGDgqJzsqIzYsHi4tMTEtLDQtJzUsMi8vKDguLy8yL08qIkssJEUtL0MvJEcu
JEIvKTkyLEguKT4xKjY0KDczMjU1LTM1OlExKE4zKT43MTs5LUo2JTc7Ljo6MjU6QT86Kkc3MUs3K1szJE81Pl8yLkE5RFQ3Iz87OjU9STs9OlM3M0M9Jz48QDk+QFo3
Jlw2Llo2NUY8P1g5L2E2OD1BSGE9NmM9MWA9PFpANGc8PWw9N0VHSlFERUlHRUNIUGdBME1GTnE/MlRHQlRGT0tKQ2NFMFxGQXNBRGxFPGpFQ2JJPHJGMXpCR09OUVJP
TYZHOXpKQlpSV3ZMQnlNPXJOTXBQRIFNP2RTYV1XVntROlZaV19YUXZTP2xVT1hZY1laXY5TWIlWUYtXSYhbQG9gYH9eUGpjX2NlYIhcTWtkWHZhWZFbSHFhbGBna4Rg
TGZmbIZfXGtlcZViVpRnWmxybn1ubJBpaJVqUXZve5JsXnJ0d4tvYXJ0fpVuWnt0bmx4gX97jKR1ZK10X595WKF5X5p7bXyChJ97ZaF6boWBfJx7d32Di3iEk5CAfLiD
eqyJbKmIhayKcrCIe5qOiYmSoa2Lfa+NaI2Sm46TlqWOiKiPfrmTdrKWj8WShLeWhr2UibyYgZqfqJyho5mhsaefnL+dj7Khlrmgj7qfmMaio6WstMGmn8elmcKnmM6k
l6qvsbKuqL6tpKmywciun8+toMqupsyxtcW4r7S8zNq1o9i2qda2sNK4qdG5sNe5pb6+wLvAyb3E1N/BrN/DtOPDvd7GvcPM28zMzM7P2crT5OzQx9DZ4dHc7dfk9vrf
0+Pq6eDt/ebz+////yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAP8ALAAAAAA8AE4AAAj+ABMkeGBAAwYNGg5oCFEhw4YEDhxYsCBAAIUYMnrIMFGiB5AeIIGIBCKk
JJAjST4eYXLkCBAlQjYEMFDRQQIBDxJMzLAQoQYRIkqUoCAgwQaiFmnQiME0RpAeT0H2cFmyJUqVTE4eUQJkAwECRQVCTECBZwiEGESYCGEiwwMKZB9UpEBDho0YNIRI
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
}

#image create photo creator_small -data {}
#creator_small copy creator   -subsample 2 2
#Прячем или отображаем scrollbar у aboout

# С grid лучше, т.к. запоминается где был - grid remove
proc hidescroll {sb  first last} {
    if {($first <= 0.0) && ($last >= 1.0)} \
      then {
        # Since I used the grid manager above, I will here too.
        # The grid manager is nice since it remembers geometry when widgets are hidden.
        # Tell the grid manager not to display the scrollbar (for now).
        grid remove $sb
        } \
      else {
        # Restore the scrollbar to its prior status (visible and in the right spot).
        grid $sb
        }
    $sb set $first $last
}

image create photo frameFocusBorder -data {
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
}
image create photo frameBorder -data {
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
}

ttk::style element create RoundedFrame image \
    {frameBorder focus frameFocusBorder} \
    -border 16 -sticky nsew
ttk::style layout RoundedFrame {
    RoundedFrame -sticky nsew
}
ttk::style configure RoundedFrame -padding 10 


proc contentabout {w} {
  # Set up display styles.
  if {[winfo depth $w] > 1} {
    set bold "-background #43ce80 -relief raised -borderwidth 1"
    #	    set normal "-background {} -relief flat"
    set normal "-background {} -foreground red -relief flat -underline on"
  } else {
    set bold "-foreground white -background black"
    set normal "-foreground {} -background {}"
  }
  foreach tag {d1 d2 d3 d4 d5 d6 d7 d8 d9 d10 d11 d12 d13 d14 d15 } {
    $w.text tag configure $tag  -foreground red
  }

  $w.text configure -background white
  $w.text tag configure tagAbout -foreground blue -font {Times 10 bold italic}
  $w.text image create end -image creator_small
  $w.text insert end "\t\tПриложения для создания УЦ \"CAFL63\"\n\n" tagAbout

  $w.text insert end "       Приложение "
  $w.text insert end {CAFL63} d9
  $w.text insert end " предназначено для создания Удостоверяющих Центров (УЦ) на базе "
  $w.text insert end {OpenSSL с поддержкой российской криптографии} d3
  $w.text insert end ".\n       При разработке приложения учитывались требования \
  российского законодательства (ФЗ-63) и требования регулятора.\n"
  $w.text insert end "       Приложение разработано "
  $w.text insert end {Орловым В.Н.} d2
  $w.text insert end \n
  $w.text insert end \
  {        Утилита cryptoarmpkcs функционирует на ОС Linux, MS Windows, MacOS, Android и др.} tagLoad1
  $w.text insert end \n
  $w.text insert end \
  {        Загрузить дистрибуты для платформ Linux, MS Windows, OS X, Android можно }
  $w.text tag configure tagLoad -foreground blue -font {Times 12 bold italic}
  $w.text tag configure tagLoad1 -foreground blue -font {Times 10 bold italic}
  #     -font {Times 10 bold italic}
  $w.text insert end {здесь:}  tagLoad
  $w.text insert end "\n\t - "
  $w.text insert end {Linux32} d4
  $w.text insert end \n
  $w.text insert end "\t - "
  $w.text insert end {Linux64} d5
  $w.text insert end \n
  $w.text insert end "\t - "
  $w.text insert end {OS X} d6
  $w.text insert end \n
  $w.text insert end "\t - "
  $w.text insert end {WIN32} d7
  $w.text insert end \n
  $w.text insert end "\t - "
  $w.text insert end {WIN64} d8
  $w.text insert end \n
  $w.text insert end "\t - "
  $w.text insert end {AndroWishApp-debug.apk}
#  $w.text insert end {AndroWishApp-debug.apk} d15
  $w.text insert end \n
  $w.text insert end \
  {        При создании дистрибутивов были использованы пакеты }
  $w.text insert end {TclPKCS11} d10
  $w.text insert end { и }
  $w.text insert end {TkFileExplorer} d13
  $w.text insert end {, а такжe утилита }
  $w.text insert end {tclexecomp} d12
  $w.text insert end ".\n"
  $w.text insert end \
  {        При создании дистрибутива под Android использовался }
  $w.text insert end {AndroWish} d14
  $w.text insert end ".\n"
  $w.text insert end \
  {        Это программное обеспечение доступно в терминах GNU General Public License.}
  $w.text insert end \n
  $w.text insert end \
  {        email: vorlov@lissi.ru} tagLoad1
  $w.text insert end \n
  $w.text insert end "
    This program comes with ABSOLUTELY NO WARRANTY.
    This is free software, and you are welcome 
    to redistribute it under certain conditions.
    See the file COPYING for details.
    Copyright (c) 2017-2020 "
  $w.text insert end {Vladimir Orlov} d11
  $w.text insert end "\n    email: vorlov@lissi.ru"
  $w.text insert end \n

  # Create bindings for tags.
  array set url []
  set url(d1) "http://soft.lissi.ru/ls_product/skzi/PKCS11"
  set url(d2) "http://museum.lissi-crypto.ru"
  set url(d3) "http://soft.lissi.ru/ls_product/skzi/skzi_lirssl_csp"
  set url(d4) "https://github.com/a513/CAFL63/raw/master/distr/CAFL63_linux32.tar.bz2"
  set url(d5) "https://github.com/a513/CAFL63/raw/master/distr/CAFL63_linux64.tar.bz2"
  set url(d6) "https://github.com/a513/CAFL63/raw/master/distr/CAFL63_mac.tar.bz2"
  set url(d7) "https://github.com/a513/CAFL63/raw/master/distr/CAFL63_setup_win32.exe"
  set url(d8) "https://github.com/a513/CAFL63/raw/master/distr/CAFL63_setup_win64.exe"
  set url(d9) "https://github.com/a513/CAFL63"
  set url(d10) "https://github.com/a513/TclPKCS11"
  set url(d11) "http://soft.lissi.ru"
  set url(d12) "http://tclexecomp.sourceforge.net"
  set url(d13) "https://github.com/a513/TkFileExplorer"
  set url(d14) "https://www.androwish.org"
  set url(d15) "https://github.com/a513/CAFL63/raw/master/distr/AndroWishApp-debug.apk"

  foreach tag {d1 d2 d3 d4 d5 d6 d7 d8 d9 d10 d11 d12 d13 d14 d15} {
    #	    $w.text tag bind $tag <Any-Enter> ".about.butt.lab configure -text {$url($tag)} ;$w.text tag configure $tag $bold"
    #	    $w.text tag bind $tag <Any-Leave> ".about.butt.lab configure -text {}; $w.text tag configure $tag $normal"
    $w.text tag bind $tag <Any-Enter> "set ::entryd {$url($tag)};$w.text tag configure $tag $bold"
    #	    $w.text tag bind $tag <Any-Leave> "set ::entryd {}; $w.text tag configure $tag $normal"
    $w.text tag bind $tag <Any-Leave> "$w.text tag configure $tag $normal"
  }
  # Main widget program sets variable tk_demoDirectory
  $w.text tag bind d1 <1> {openURL "http://soft.lissi.ru/ls_product/skzi/PKCS11"}
  $w.text tag bind d2 <1> {openURL "http://museum.lissi-crypto.ru"}
  $w.text tag bind d3 <1> {openURL "http://soft.lissi.ru/ls_product/skzi/skzi_lirssl_csp"}
  eval "$w.text tag bind d4 <1> {readdistr https://github.com/a513/CAFL63/raw/master/distr/CAFL63_linux32.tar.bz2 $w}"
  eval "$w.text tag bind d5 <1> {readdistr https://github.com/a513/CAFL63/raw/master/distr/CAFL63_linux64.tar.bz2 $w}"
  eval "$w.text tag bind d6 <1> {readdistr https://github.com/a513/CAFL63/raw/master/distr/CAFL63_mac.tar.bz2 $w}"
  eval "$w.text tag bind d7 <1> {readdistr https://github.com/a513/CAFL63/raw/master/distr/CAFL63_setup_win32.exe $w}"
  eval "$w.text tag bind d8 <1> {readdistr https://github.com/a513/CAFL63/raw/master/distr/CAFL63_setup_win64.exe $w}"
  $w.text tag bind d9 <1> {openURL "https://github.com/a513/CAFL63"}
  eval "$w.text tag bind d15 <1> {readdistr https://github.com/a513/CAFL63/raw/master/distr/AndroWishApp-debug.apk $w}"
  $w.text tag bind d10 <1> {openURL "https://github.com/a513/TclPKCS11"}
  $w.text tag bind d11 <1> {openURL "http://soft.lissi.ru"}
  $w.text tag bind d12 <1> {openURL "http://tclexecomp.sourceforge.net"}
  $w.text tag bind d13 <1> {openURL "https://github.com/a513/TkFileExplorer"}
  $w.text tag bind d14 <1> {openURL "https://www.androwish.org"}
}

proc rect2window {w tw th} {
#Считываем размеры главного окна в пикселях
    set rw [winfo screenwidth $w]
    set rh [winfo screenheight $w]
    set geometr $tw
    append geometr "x"
    append geometr $th
    if { $rw <= $rh } {
       append geometr "+0+0"
    } else {
#Координаты главного окна
	set rgeom [wm geometry $w]
	set rgf [string first "x" $rgeom]
	set rw [string range $rgeom 0 $rgf-1]
	set rg [string first "+" $rgeom]
	set xx [string range $rgeom $rgf+1 $rg-1]
	set rg1 [string range $rgeom $rg+1 end]
	if {$rw <= $tw} {
    	    append geometr +$rg1
	} else {
	    set off [expr ($rw - $tw) / 2]
	    set rg2 [string first "+" $rg1]
	    incr rg
	    incr rg2 -1
	    set offw [string range $rg1 0 $rg2]
	    set offw1 [expr $offw + $off]
	    incr rg2 2
	    set offw2 [string range $rg1 $rg2  end]
	    set offw2 [expr $offw2 + ($xx - $th)/2]
    	    append geometr "+$offw1+$offw2"

        }
    }
#Возвращаем геометрию дляцентрируемого окна
    return $geometr
}

proc About {w} {
    set title {О приложении CAFL63}
    catch {destroy $w}
    toplevel $w -bg #cdc7c2 -bd 3
#Центрируем справочное окно в основном окне
    set geometr [rect2window "." "530" "480" ]
    wm geometry $w $geometr
#Окно не может перекрываться (yes)
    wm attributes $w -topmost yes   ;# stays on top - needed for Linux
    wm title $w $title
    wm iconphoto $w iconCert_32x32

############# new #######################
    frame $w.txt -bg skyblue -bd 0
    pack $w.txt -side top -expand 1 -fill both
#Для Win32, почему-то не видит сверху
    ttk::style layout RoundedFrame {
	RoundedFrame -sticky nsew
    }

    ttk::frame  $w.txt.frame1 -style RoundedFrame -padding 10
    pack $w.txt.frame1  -fill x 
    label $w.txt.frame1.label1 -text $title -bg white -font TkDefaultFontBold
    pack $w.txt.frame1.label1 -fill none -pady {0 1mm}

    ttk::frame  $w.butt -style RoundedFrame -padding 10
#  frame $w.butt -bg #f5f5f5 -highlightthickness 2 -highlightbackground skyblue -highlightcolor skyblue
    pack $w.butt -expand 0 -fill x -side bottom
    eval "ttk::button $w.butt.ok -text {Отмена} -command {destroy $w} -style MyBorder.TButton"
    set ::entryd ""
    entry $w.butt.lab -textvariable ::entryd -highlightthickness 1 -highlightbackground skyblue -highlightcolor skyblue
    pack $w.butt.lab -side top  -pady {0 0} -fill x -expand 1  -padx {0 5}

    pack $w.butt.ok -side right -padx {4 5} -pady 2

    set worig $w
    ttk::frame  $w.txt.frame2 -style RoundedFrame -padding 10
    pack $w.txt.frame2 -fill both -expand 1
    set w $w.txt.frame2

##########################

    text $w.text -autosep 1 -relief flat -wrap word -height 20  -bg #fcfefc -font {Times 10 bold italic}

    bind $w.text <ButtonPress-3> {showTextMenu %W %x %y %X %Y}
    ttk::scrollbar $w.yscroll -orient vertical -command [list $w.text yview]
    eval "    $w.text config -yscrollcommand {hidescroll  $w.yscroll}"
    contentabout $w
    grid $w.yscroll  -row 0 -column 1  -columnspan 1  -sticky ns   -pady 0
    grid $w.text  -row 0 -column 0  -columnspan 1  -sticky nwse  -pady 0 
    grid columnconfigure $w 0 -weight 1
    grid rowconfigure $w 0 -weight 1

    $w.text configure -state disabled
    
#tk busy здесь для красоты!!
    tk busy hold .cm
#    menu_disable
    set w $worig
    tkwait window $w
    tk busy forget .cm
#    menu_enable
}

proc CreateMenu {w label def} {
    global tcl_platform
    global config
    
    MakeMenu $w $label $def
    
    if { [string equal $tcl_platform(platform) windows] } {
        $w.$label add cascade -label System -menu $w.$label.system
        menu $w.$label.system -tearoff 0
        # Add the 'Show Log' item to the system menu
        $w.$label.system add checkbutton \
                -label {Show Message Log} \
                -variable ::Log::mapped(.log) \
                -command "::Log::WindowToggle .log"
    }
}

proc CreateMenuAqua {w label def} {
    global tcl_platform
    global config
    
#    MakeMenu $w $label $def
    catch {destroy $w.menumac}

    frame $w.label -height 26 -bd 2 -relief groove -bg #e0dfde
    MakeMenuAqua $w.label $label $def
    pack $w.label -side top -fill x -padx 0 -pady 0

}

proc  MakeMenu {w label def} {
    catch {destroy $w.$label}

    menu $w.$label -tearoff 0 -relief flat -bd 0 -bg #eff0f1
# puts "command: menu $w.$label -tearoff 0"
    
    foreach {wg text content} $def {
       	if {[string index $wg 0] == "#"} {
    	       # ignore
        } elseif {[string index $wg 0] == "-"} {
            # add separator line
            $w.$label add separator
        } elseif {$wg == "cmd"} {
            $w.$label add command -label $text -command $content
            # puts "command: $w.$label add command -label $text -command $content"
        } elseif {$wg == "radio"} {
            set variable [lindex $content 0]
            set value [lindex $content 1]
            set command [lindex $content 2]
            $w.$label add radiobutton -label $text \
                    -value $value -variable $variable -command $command
            #puts "radio: $w.$label add radiobuttion -label $text -value $value -variable $variable -command $content"
        } else {
       	    MakeMenu $w.$label $wg $content
       	    $w.$label add cascade -label $text -menu $w.$label.$wg
#       	     puts "command: $w.$label add cascade -label $text -menu $w.$label.$wg"
       	}
    }  
}

proc showContextMenuAqua {w x y rootx rooty } {
#    puts "showContextMenuAqua=$w, rootx=$rootx, rooty=$rooty, x=$x, y=$y"
    set i [string last "." $w]
    set menuaqua [string range $w 0 $i]menunew.[string range $w [expr $i + 1] end]
    set x1 [winfo rootx $w]
    set y1 [winfo rooty $w]
    incr y1 26
    tk_popup $menuaqua $x1 $y1
    return
}

proc showContextMenuAquaForget {w x y rootx rooty } {
#    puts "showContextMenuAqua=$w, rootx=$rootx, rooty=$rooty, x=$x, y=$y"
    set i [string last "." $w]
    set menuaqua [string range $w 0 $i]menunew.[string range $w [expr $i + 1] end]
    set x1 [winfo rootx $w]
    set y1 [winfo rooty $w]
    incr y1 26
#    tk_popup $menuaqua $x1 $y1 0
#    $w configure -background #e0dfde
    focus .
    return
}

proc  MakeMenuAqua {w label def} {
    catch {destroy $w.$label}

    menu $w.$label -tearoff 0
# puts "command: menu $w.$label -tearoff 0 ::aquamenu=$::aquamenu"
    
    foreach {wg text content} $def {
       	if {[string index $wg 0] == "#"} {
    	       # ignore
        } elseif {[string index $wg 0] == "-"} {
            # add separator line
            $w.$label add separator
        } elseif {$wg == "cmd"} {
            $w.$label add command -label $text -command $content
#             puts "command: $w.$label add command -label $text -command $content"
        } elseif {$wg == "radio"} {
            set variable [lindex $content 0]
            set value [lindex $content 1]
            set command [lindex $content 2]
            $w.$label add radiobutton -label $text \
                    -value $value -variable $variable -command $command
            #puts "radio: $w.$label add radiobuttion -label $text -value $value -variable $variable -command $content"
        } else {
	    ttk::button $w.$wg -text $text -style MenuAqua.TButton
	    pack $w.$wg -side left -fill y 
	    bind $w.$wg <Button-1> {showContextMenuAqua %W %x %y %X %Y }
       	    MakeMenuAqua $w.$label $wg $content
       	}
    }  
}

set CertListBox { {#0 "NickName" 120}
    {sort0 "NikName" 0 }
    {serial "Serial" 80 }
    {cn "CN" 170}
    {email "Email" 120}
    {status "Status" 40}
    {valid "Valid Until" 90}
    {revocationdate "Revocation Date" 90}
    {dn "Distinguised Name" 0}
    {ckaID "ckaID Certificate" 55}
}
set ReqListBox { {#0 "NickName" 120}
    {sort0 "NickName" 0 }
    {serial "Serial" 80 }
    {createdate "Date create" 100}
    {cn "CN" 120}
    {email "Type" 120}
    {status "Status" 40}
    {ckaID "ckaID Request" 0}
}
set CRLListBox { {#0 "NickName" 120}
    {sort0 "NickName" 0 }
    {serial "Serial" 0 }
    {cn "CN" 100}
    {signtype "SignType" 140}
    {createdate "Date create" 100}
    {nextdate "Date Next" 100}
    {ID "ckaID Request" 0}
}
#status - утвержден/проверен или нет, подпись администратора ЦР

proc ObjectListBox {w box type} {
    set ncol ""
    set dcol {}
    foreach coln $box {
	set colw [lindex $coln 2]
	set colname [lindex $coln 0]
	if {$colname != "#0" } {
    	    lappend ncol $colname
	    if {$colw != 0 } {
    		lappend dcol $colname
	    }
	}
    }
#puts "DCOL=$dcol"
    catch {destroy $w}

    # we want the listbox and two scrollbars to be embedded in a 
    ttk::frame $w -borderwidth 0 -relief flat   -width 550 -height 490 

    ttk::scrollbar $w.yscroll -orient vertical -command "$w.listbox yview"
    ttk::scrollbar $w.xscroll -orient horizontal -command "$w.listbox xview"

    set a [string last "." $w ]
    set a [expr {$a - 1}]
#puts "W=$w a=$a"
    set parent [string range $w 0 $a]
#Делаем убираемые scrollbar
    grid $w.yscroll  -row 0 -column 1  -columnspan 1  -sticky ns   -pady {6mm 0}
    grid $w.xscroll  -row 1 -column 0  -columnspan 1  -sticky we   -pady 0
    pack $w -in $parent -anchor center -expand 1 -fill both -padx 0  -side right -pady {1mm 0}
#puts $ncol

    set fontTV [ttk::style lookup Treeview -font]
    ttk::treeview $w.listbox -columns $ncol -displaycolumns  $dcol
    # -xscrollcommand "$w.xscroll set" -yscrollcommand "$w.yscroll set"
#Утанавливаем функцию работы со scrollbar-ом 
    eval "$w.listbox config -yscrollcommand {hidescroll  $w.yscroll} -xscrollcommand {hidescroll  $w.xscroll}"

    foreach tab $box {
#heading options.
#puts "TAB=$tab"
	set colname [lindex $tab 0]
#puts "COLNAME=$colname"
	set nn [lindex $tab 1]
	set aa "$w.listbox heading $colname -text \"$nn\" -anchor w -image upArrow -command {ObjectListBox_Sort $w.listbox $colname 0 $type}"
	set command [subst $aa]
#puts "COM=$aa"
	eval $aa
	$w.listbox column $colname  -width [lindex $tab 2] -minwidth 35
    } 
    
#    pack $w.listbox  -in $w -anchor center -expand 1 -fill both -ipadx 0 -ipady 83 -side top
    grid $w.listbox  -row 0 -column 0  -columnspan 1  -sticky nwse  -pady 0 
    grid columnconfigure $w 0 -weight 1
    grid rowconfigure $w 0 -weight 1

    if {$type == "cert" } {
	bind $w.listbox <ButtonPress-3> \
    	    {showContextMenu %W %x %y %X %Y}
	bind $w.listbox <Double-1> {viewDouble %W "cert"}

    } elseif {$type == "certrev" } {
	bind $w.listbox <ButtonPress-3> \
    	    {showContextMenuRev %W %x %y %X %Y}
	bind $w.listbox <Double-1> {viewDouble %W "cert"}
    } elseif {$type == "req"} {
	bind $w.listbox <ButtonPress-3> \
    	    {showContextMenuReq %W %x %y %X %Y}
	bind $w.listbox <Double-1> {viewDouble %W "req"}
    } elseif {$type == "reqar"} {
	bind $w.listbox <ButtonPress-3> \
    	    {showContextMenuReqAr %W %x %y %X %Y}
	bind $w.listbox <Double-1> {viewDouble %W "req"}
    } elseif {$type == "crl"} {
	bind $w.listbox <ButtonPress-3> \
    	    {showContextMenuCRL %W %x %y %X %Y}
	bind $w.listbox <Double-1> {viewDouble %W "crl"}
    } {
	puts "Type=$type Надо делать"
    }
    return $w.listbox
}

## Code to do the sorting of the tree contents when clicked on
proc ObjectListBox_Sort {tree col direction type} {
    global CertListBox
    global ReqListBox
    global CRLListBox
#puts "ObjectListBox_Sort col=$col direction=$direction"

    if {$type == "cert" || $type == "certrev"} {
	set box $CertListBox
    } elseif {$type == "req" || $type == "reqar" } {
	set box $ReqListBox
    } elseif {$type == "crl"} {
	set box $CRLListBox
    } else {
puts "CertificateListBox_Sort=$type unknown"
    }

    set ncol ""
    foreach coln $box {
	set colname [lindex $coln 0]
	if {$colname != "#0" } {
        lappend ncol $colname
	}
 
    }
    
#puts $ncol

    # Determine currently sorted column and its sort direction
    foreach c $ncol {
#puts "CertificateListBox_Sort=$c"
	if {$c == "#0"} {
	    set c "sort0"
	}
	set s [$tree heading $c state]
	if {("selected" in $s || "alternate" in $s) && $col ne $c} {
	    # Sorted column has changed
	    $tree heading $c -image noArrow state {!selected !alternate !user1}
	    set direction [expr {"alternate" in $s}]
	}
    }

    # Build something we can sort
    set data {}
    foreach row [$tree children {}] {
	if {$col == "#0"} {
	    lappend data [list [$tree set $row "sort0"] $row]
	} else {
	    lappend data [list [$tree set $row $col] $row]
	}
    }

    set dir [expr {$direction ? "-decreasing" : "-increasing"}]
    set r -1

    # Now reshuffle the rows into the sorted order
    foreach info [lsort -dictionary -index 0 $dir $data] {
	$tree move [lindex $info 1] {} [incr r]
    }

    # Switch the heading so that it will sort in the opposite direction
    $tree heading $col -command [list ObjectListBox_Sort $tree $col [expr {!$direction}] $type] \
	state [expr {$direction?"!selected alternate":"selected !alternate"}]

    if {[ttk::style theme use] eq "aqua"} {
	# Aqua theme displays native sort arrows when user1 state is set
	$tree heading $col state "user1"
    } else {
	$tree heading $col -image [expr {$direction?"upArrow":"downArrow"}]
    }
}

#Notebook
proc NotebookCA {w {pages}} {
    namespace import ::scrolledframe::scrolledframe
    global db
    global certdb
    global keydb
    global TekWin 
    global certID
    global reqID
    global crlID
    global certIDRev
    global reqIDAr
    global keyID
    set certdb ""
    set keydb ""
    set certID 0
    set reqID 0
    set crlID 0
    set certIDRev 0
    set reqIDAr 0
    set keyID 0
    global defaultkey
    global defaultpar
    set defaultkey "gost2012_256"
    set defaultpar "1.2.643.2.2.36.0"

    ttk::style configure TButton -background #c0bab4 -relief raise -borderwidth 2 -bordercolor   #cdc7c2 -highlightborderwidth 2 -highlightthickness 4

    ttk::style map TButton -background  [list active #e0e0da disabled #0000ff readonly green]
    ttk::style configure My.TFrame -background #eff0f1 -relief grooved -borderwidth 2
    set a [string last . $w]
    incr a -1
    set parent [string range $w 0 $a]

    ttk::style configure TNotebook -background #cbccce
    #cbccce
    ttk::style configure TNotebook.Tab -background #c0bab4
frame $parent.ff -padx 2 -pady 2 -relief flat -bd 0 -bg #cdc7c2
pack $parent.ff -in $parent -fill both -expand 1 -pady 1mm -padx 2mm
set w $parent.ff.notbok
    ttk::notebook $w    -width {682} -height {418} -takefocus {}
#     -padding 3 

    $w state {hover}
    set i 0
#    set textBut {"Просмотр" Экспорт Создать Удалить Импорт}
    set textBut {"Резерв 1" "Резерв 2" "Резерв 3" "Резерв 4" "Резерв 5" "Резерв 6"}
    foreach page $pages {
	set pageTek page$i
	set pageTek $pageTek[string range com 0 2]
#	frame $w.p$i -background skyblue -padx {0 } -pady 0 -relief flat -borderwidth 0
	frame $w.p$i -background #cdc7c2 -padx {0 } -pady 0 -relief flat -borderwidth 0
	if { $i == 5 } {
	    $w.p$i configure -background white -pady 20
#	    break
	    set w1 $w.p$i
	    label $w1.labtit -background white -height 2 -width 35 -text "Начните работу с открытия БД\nсуществующего УЦ"  -font {Times 16 bold italic}  -foreground blue
	    label $w1.labsub -height 2 -background white -width 35 -text "Либо создайте новый УЦ и БД для него"  -font {Times 16 bold italic}  -foreground green
	    label $w1.labicon -borderwidth 0 -image  creator -background white -anchor c
	    set labelfont [font actual [$w1.labtit cget -font]]
	    $w1.labtit configure -font [concat $labelfont -weight bold]
	    set tf $w1
	    grid configure $w1.labtit    -in $tf -row 3 -column 1 -sticky nsew
	    grid configure $w1.labsub -in $tf -row 4 -column 1 -sticky nsew
	    grid configure $w1.labicon    -in $tf -row 2 -column 0 -rowspan 4 -pady 0 -padx 10mm
	    pack $w1 -fill both -expand 1
	    #-pady 22 -ipady 10 -padx 5
	    $w add $w.p$i -padding 0 -sticky nsew -state normal -text $page
	    incr i
	    break
	}

	ttk::frame $w.p$i.right -borderwidth {0} -width {238} -height {405} -style {My.TFrame}
#	frame $w.p$i.right -borderwidth {0} -width {238} -height {405} -bg white
	ttk::frame $w.p$i.left -borderwidth {0} -relief {groove} -width {562} -height {496}
	$w.p$i.left state {}
#Create button for page
	for {set j 0} {$j <= 5} {incr j} {
	    set tekCom "$pageTek$j"
#	    puts "tekCom=$tekCom"
	    set cmd "button $w.p$i.right.but$j -command {catch $tekCom} -text \"[lindex $textBut $j]\" -width 24 -bg #c0bab4 -highlightthickness 2 -relief flat -highlightbackground {#cdc7c2} -activebackground #eff0f1 -activeforeground black"
	    set cmd1 [subst $cmd]
	    eval $cmd1

	    pack $w.p$i.right.but$j -anchor center -fill both -ipadx 0 -ipady 0 -padx 5 -pady 5 -side top
	}
	if { $i == 2 } {
	label $w.p$i.right.icon  -background {#eff0f1} -image CertStamp_71x100
	} elseif { $i == 3 || $i == 4 } {
	label $w.p$i.right.icon -activebackground {#f9f9f9} -activeforeground {black} -background {#eff0f1} \
	     -foreground {black} -highlightbackground {#eff0f1} -highlightcolor {black} -image CertStampBad_71x100
	} else {
	label $w.p$i.right.icon -activebackground {#f9f9f9} -activeforeground {black} -background {#eff0f1} \
	     -foreground {black} -highlightbackground {#eff0f1} -highlightcolor {black} -image iconCertKey_71x100
	}

	pack $w.p$i.right.icon -anchor center -expand 0 -fill none -padx {0} -pady {0 15mm} -side bottom
	$w add $w.p$i -padding 0 -sticky nsew -state normal -text $page -image {} -compound none -underline -1

	pack  $w.p$i.right  -in $w.p$i  -padx {1mm 0} -pady {1mm 0mm} -side right -fill y
#	-fill both -expand 1
	pack  $w.p$i.left -in $w.p$i  -padx 0 -pady 0 -side left -fill both -expand 1

	$w tab $i -state disabled
	incr i
#	puts $page
    }

pack $w -fill both -expand 1
# -pady 1mm -padx 2mm
#pack $w -fill both -expand 1 -pady 1mm -padx 2mm
}

image create photo exitCA_16x16 -data {
R0lGODlhEAAQAMYAAP///5gBAfz398+Hh6AVFdJSUsMAANMAAMYAANJRUdNVVcgA
ANAAANQAANRYWNFOTtBCQtBISNBEROmjo9A/P9VcXOq5ueuysuyKiuq4uOqwsJwH
B9E8POmpqe/Bwe6jo/jk5NxyctdiYs4aGuSFhfvw8NcaGuyFhdaamthqavHJycMJ
CeOJiccXF8kfH841Nfba2twaGtEuLtkpKeqYmPCUlLYYGONaWuJsbNciIt1KSt5C
Qvne3uFhYd57e8sqKrk2Nv//////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
/////////////////yH+EUNyZWF0ZWQgd2l0aCBHSU1QACwAAAAAEAAQAAAHgIAA
goOEhYaHhiUEi4yNAYQDFRUOlBoKBQUJHZAOCpcFAAkPo5uDA5kiAA8AAgAREaWC
A6MAKREAEoIQE5ARKrgSEBAUABy8phCCFCsGzQAGJJAUHM8GCNcAC9Gm2NkLCwAq
DCeQ3wyEHgwH5KYM7uoHDfIN7IMC9/j5rYj8/YaBADs=
}
image create photo addDB_16x16 -data {
iVBORw0KGgoAAAANSUhEUgAAAA4AAAAQCAYAAAAmlE46AAAABmJLR0QA/wD/AP+g
vaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAB3RJTUUH4gUTExYO+FTi0QAAAB1p
VFh0Q29tbWVudAAAAAAAQ3JlYXRlZCB3aXRoIEdJTVBkLmUHAAACwUlEQVQoz12S
zWtcZRTGf+d9782dj8xHJsnUJFVsQ2tMumi0tHRRFykutC4UXJSKlS7Uf0CQIgq6
d6WlbvzAlR8bFRcaBIsgKlZildZOTNpQM4mdNs1MMp/3zn2PixsreOAcOHCe8zwP
58gLz7xsB4eK97e2m89mJ0aPeUPZfelMZhznpN3trtLsrmzduHnBN+bjt9994wo7
IS8+/+prpaMzr48c2o9kBkAhKfLvDNoJ2bj4J5sLS2evn//yza/6P0R27ulTF0aP
H8QEHuoUUU1wqndTPEN6rATtcLf0+t8sLP98ywu3W2xfuUFQyiXzAiI7bE53KJWo
3qJVu6O2lBUAb3DvOLl942wvVhERHOCLRYFYXSLbCJn7RgHVTmUVAI9+jFccpDA7
edeTdYnF+D+bGM/SXl7HdaKkby6v0bi8gjEGMYIIOAvOJJJFBFRpVqrUf19BTbLN
S00MY6zH31//ghEDviX2BQW80CGxosaQmhghNzlBZ2k9AdpMiuyeMsGuIiJgVLCx
ggixBXUxG6uXuNOrYiNIFYIIwIQ364jvYVM+JvAh5RFnfeKMT0xI5eIHmOYSz83O
kSlsTG/MLL5y+q1TORO22tTmF9BeH3WKxi65pxj++u1zet1NsqlBZu6dIZfOYcSc
TvmZk15ucpyhw1Pc/vEPPLH0rTKQSRPTI+8pB6aOsat4D4Lw4O5p8uk812+tnJGz
5z7U8mOHwDl05xRRK6RbrzKbh8cfeoL/x/vfvhfZI0cffSQoF/bYdApUky8NPAgC
ercXUXU02nWGcyNU1q5yrXaNxbXKZ/ZgafontVLQXlToN1rFfrOL64SYULh6+Vfm
L31KbavG3IHjnJ8/xyfff7TVaDVeEoATPBCMPXXiyPDD+yclny6ng4GRvrooaje3
1uU7RkvlJ6fGpg8vrlXmq5ur7zR6jS/+ASJ5KZKbwD8+AAAAAElFTkSuQmCC
}
image create photo closeDB_16x16 -data {
iVBORw0KGgoAAAANSUhEUgAAAA4AAAAQCAYAAAAmlE46AAAABmJLR0QA/wD/AP+g
vaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAB3RJTUUH4gUUCC0glZR0DgAAAB1p
VFh0Q29tbWVudAAAAAAAQ3JlYXRlZCB3aXRoIEdJTVBkLmUHAAAClElEQVQoz02S
TWicVRSGn3Pvnf9MJpnOtM5E/AuNUhdGLFUXbqq7bhRcSMVCF+rGpSAiCrp3paAb
d27cSXGhpUjBhYqWKMVqNdGxaWyaaGaamW9mvp97j4tvjD1wD1w4733Py3Plpedf
s3OLC/dEw9ELtaX2E26xdrRSrXYJQcbT6XVG097+tZsXC8Z88v5H71xhVvLyi2++
1Xz8wbdbx1eQahEU8ib/zaCThH++/43+2vrrf3zw2bufZ1+n9uSzpy+2n1zFlBwa
FFHNdaoHR5yh0mnCOLlT4uzC2sZ3uy4ZRgyvXKPUrOfzAiIzt6AzSyUdREQ7e2qb
NQFwc/d1qR/tMvx1CxEhAAWxKOA15GsboXpXG1CdXL0OgCPzuIU5Gg8vH2SyIY/o
/4+JcZbxxg3CJM3vo42/uPVTD2MMYgQRCBaCyVcWEVBldHWLweUeavLXXHnpEMY6
tr+4hBEDBYsvCAq4JCBeUWMoL7WoLy8xWb+RC221TO3ew5SOLCACRgXrFUTwFkLw
9LcuM/K7qM8ozRdTAJfcHCAFhy3rQR6fI8bHEeuXPiaeDkAElGM8pG+cee/0KyaJ
xuycX0PjDA2K+pDzFMPmj58Sj/cQBZkxFuVM2VWec/XlLosnHuDvb37GiSWzSrFa
wZuE+sYmd49yNAdfTWHY1LMupB47X+HIU6voDEUaJcTRDndcMKxsCuE2LDYLrD/W
OO6SvdGX8Xb/ZLHVABQPmLkihXKLfrvE7z5G5TalCsN4eM6uNo99q1YaGqeN7Fa0
kI2mhEmCxLCV9PmltUuvq/Q60Osof3Zkf9AuvSoAp7i/1Hnm1KOHHllZlvnK4Uqp
2Mo0pMlktL9tvkKsPO1Tf0KMnMeaD3+o7Z77F6hWKSXOZA0iAAAAAElFTkSuQmCC
}

image create photo openDB_16x16 -data {
iVBORw0KGgoAAAANSUhEUgAAAA4AAAAQCAYAAAAmlE46AAAABmJLR0QA/wD/AP+g
vaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAB3RJTUUH4gUTEwU6uA9X9gAAAB1p
VFh0Q29tbWVudAAAAAAAQ3JlYXRlZCB3aXRoIEdJTVBkLmUHAAACtUlEQVQoz0WS
TWhcZRSGn/N938zcOz+Zn8RMO7WYNIaqlOJPqqhYKC4qiAuh4MK6ELp1ZVyEgtSN
O8Gd4kYXblyJUSxIqQVXVZoSkP6GmLbpzyS0k5nM3Jm5d+49XdzEntXhHF54n/cc
OXnqM1sslaa2g+CjQmPyLTOWn837fkOMSLfbW5dgsNa53byQNeanH7798go7JR9+
cvrzytzzX1RfPojks6A7G1UQSftBSOvyDbaWVxZufbf41V+dS5F988QHF2rHXsJk
HaqaClSfiFXBGvx6DQnCp20Yn/v3+qVNN+z2CK7dJlMrAZAAiCC7QoBEiTs9gs2W
SqUgAK443SD/bIPuyl0MQiKQwaDASBMEUBG8/U9RTlSHN9YBcIxibLnI2OGZHXvg
NEWNDf+XOMtw9T46iAAw3dV7dK+uYYxJwzBCbCAxqWVEEIX+zbu0r/yXzgHn7Z3A
GMvm+SUsglpDmE3TzESKHSmJFbJ7xylMNRis3kuFtpDDm6qTrVcBsCq4RBEVQqcg
hnCjSRwHOKLEEz8EcKONNsY5yOkuItEuWDzizvVfWPH/YZgZUKiWD+0/fmB+4e2v
P7WHXj96Jt4K8PbUUJGd24ERy4ObZ1kqnWVohsTE+MUMYab/iqhZc8XpfZSPHOTR
31dxYomskvF9HMqKdxErGZw4qtkKC8/N8/ODRdavtT52GifYks/4sRdT6BjC/hC3
3UW2YbrwDO/uOU7RlVhqXeZc80+O+G/MmXirez5stpAk/ZBIFJPPkVTHyIcVmuEG
da/Ow+FDvr/1Iy5x9INw0b4wPnuRjC3rcFSO2t1K3BuggxCNEsz9iFZ8h9/av7O8
vQwjYbK/r+21yvMC8A4zudrJ916rHJ6doeRNFnLeRJjEURwMOo/Ky9optd+Po+RV
5+wf5d7EN3NrR399DEo5KSGGFEpfAAAAAElFTkSuQmCC
}

proc ObjectManager {w} {
    global db
    global CertListBox
    global CRLListBox
    global ReqListBox
    global app
    global MenuCommands_Wizard
    global tcl_platform
    global argv
    global raca
    global typesys
    
    set caname [Config::Get system.caname]
    if {$w == ".cm"} {
	wm title . "$app(name) - $caname"
	wm iconphoto . iconCert_32x32
#Главное окно не изменяется
	wm resizable . 0 0
    }

    switch [tk windowingsystem] {
	classic - aqua  {
	    CreateMenuAqua $w menunew $MenuCommands_Wizard
	}
	default {
	    CreateMenu $w menunew $MenuCommands_Wizard
    	    . configure -menu $w.menunew
	    menu_disable
#	    $w.menunew.options entryconfigure 0 -state disabled
	    $w.menunew configure -activebackground #cdc7c2 -background #f6f5f4
	    #e0e0da
	    $w.menunew.database configure -activebackground #cdc7c2
	    $w.menunew.options configure -activebackground #cdc7c2
	    $w.menunew.help configure -activebackground #cdc7c2
	    $w.menunew.certificates configure -activebackground #cdc7c2
	}
    }

if {1} {
set w1 $w
    wm geometry . +200+100;

#    $parent configure -background #cdc7c2
    if {$raca == 1} {
        wm title . {Центр Регистрации УЦ-ФЗ-63}
    } else {
        wm title . {УЦ-ФЗ-63 на базе OpenSSL, SQLite3 и Tcl/Tk}
    }
#$w configure -bg #eff0f1 -padx 4 -pady 4
#c0bab4
#    frame $w.mainfr -relief groove -background #cdc7c2 -bd 4 -padx 5 -pady 5
    frame $w.mainfr -relief flat -bg #eff0f1 -bd 0 
#Внешняя рамка
$w configure -borderwidth 1
    pack $w.mainfr -fill both -pady 0 -expand 1 -padx 0 
    set w $w.mainfr

}

    set zag {    Добро пожаловать в Удостоверяющий Центр УЦ ФЗ-63 2020}
#    ttk::label $w.who -text $zag -justify center -image validcert_new -compound left -background #e0e0da -font {Times 11 bold italic}  -borderwidth 4 -relief groove
    ttk::label $w.who -text $zag -justify center -image validcert_new -compound left -background #eff0f1 -font {Times 11 bold italic}   -borderwidth 4 -relief flat
    pack $w.who    -padx 30 -pady 10 -ipadx 5
    $w.who configure -text $zag 
    NotebookCA $w.notbok {{Запросы на сертификаты} {Архив Запросов} Сертификаты {Отозванные X509} CRL/СОС Начало}

    frame $w.sep -height 2 -bd 0 -relief flat -background #cdc7c2
     #bdeaff
     #c0bab4
$w configure -borderwidth 1
    pack $w.sep -fill x -pady 1mm -padx 0

    ttk::button $w.bcr -text {Создать БД} -image addDB_16x16 -compound left -command {cmd::CreateDB}
    ttk::button $w.bop -text {Открыть БД} -image openDB_16x16 -compound left -command {cmd::OpenDB}
    ttk::button $w.bcl -text {Закрыть БД} -image closeDB_16x16 -compound left -command {cmd::CloseDB}
    ttk::button $w.bex -text {Выйти из УЦ} -image exitCA_16x16 -compound left -command {cmd::ExitDB}
    pack $w.bex $w.bcr $w.bcl $w.bop -side right -pady {1mm 2mm} -padx {0 2mm}

#puts "Wnotbok=$w"

#    Certificate Request
    set db(treeReq) [ObjectListBox $w.ff.notbok.p0.left $ReqListBox req]
	$w.ff.notbok.p0.right.but0 configure -text "Просмотр внешнего CSR"
	$w.ff.notbok.p0.right.but1 configure -text "Импорт запроса/CSR"
	$w.ff.notbok.p0.right.but2 configure -text "Создать запрос/CSR"
	$w.ff.notbok.p0.right.but3 configure -text "Просмотр выделенных CSR"
#    Certificate Request Archive
    set db(treeReqAr) [ObjectListBox $w.ff.notbok.p1.left $ReqListBox reqar]
	$w.ff.notbok.p1.right.but0 configure -text "Просмотр внешнего CSR"
	$w.ff.notbok.p1.right.but1 configure -text "Просмотр выделенных CSR"
#    CertificateList
    set db(treeCert) [ObjectListBox $w.ff.notbok.p2.left $CertListBox cert]
	$w.ff.notbok.p2.right.but0 configure -text "Просмотр внешнего X509"
	$w.ff.notbok.p2.right.but1 configure -text "Просмотр CA УЦ"
	$w.ff.notbok.p2.right.but2 configure -text "Экспорт корневого X509"
	$w.ff.notbok.p2.right.but3 configure -text "SQL-дамп таблицы X509"
	$w.ff.notbok.p2.right.but4 configure -text "SQL-дамп новых X509"
	$w.ff.notbok.p2.right.but5 configure -text "Просмотр выделенных X509"
#    CertificateList Revoke
    set db(treeCertRev) [ObjectListBox $w.ff.notbok.p3.left $CertListBox certrev]
	$w.ff.notbok.p3.right.but0 configure -text "Просмотр внешнего X509"
	$w.ff.notbok.p3.right.but1 configure -text "Создать CRL/СОС"
	$w.ff.notbok.p3.right.but2 configure -text "Экспорт отозванных X509"
	$w.ff.notbok.p3.right.but3 configure -text "Просмотр выделенных X509"
#	CRLList
    set db(treeCRL) [ObjectListBox $w.ff.notbok.p4.left $CRLListBox crl]
	$w.ff.notbok.p4.right.but0 configure -text "Просмотр внешнего CRL/СОС"
	$w.ff.notbok.p4.right.but1 configure -text "Создать CRL/СОС"


}

proc CertificateManager_Update {w tektree} {
    global db
    
    debug::msg "CertificateManager_Update $w $tektree"
        
    global certID
    if {$certID != 0 } {
	$tektree selection set {0}
	for {set j 0 } { $j < $certID} {incr j} {
	    $tektree delete $j
	}
	set certID 0
    }
    foreach v [openssl::GetCertificateDB] {
	insertTree $v $tektree 0
    }
        # valid or revoked
    # initial sorting
    ObjectListBox_Sort $tektree serial 0 "cert"
    if {$certID != 0 } {
	$tektree selection set {0}
    } 
}

proc CertificateRevoke_Update {w tektree} {
    global db
    global certIDRev
    #GetCertificates $w.main ca.db.index
    
    debug::msg "CertificateRevoke_Update $w $tektree"
        
    if {$certIDRev != 0 } {
	$tektree selection set {0}
	for {set j 0 } { $j < $certIDRev} {incr j} {
	    $tektree delete $j
	}
	set certIDRev 0
    }

    foreach rev [certdb eval {select certDBRev.ckaID from certDBRev}] {
#puts "REV=\"$rev\""
	certdb eval {select * from certDB where certDB.ckaID = $rev} vals {
	set o {}
#	parray vals
	lappend o $vals(state)	    
	lappend o $vals(notAfter)	    
	lappend o $vals(dateRevoke)	    
	lappend o $vals(sernum)	    
	lappend o "unknown"	    
	lappend o $vals(subject)	    
	lappend o $vals(ckaID)
    }
#puts "INDEX_DB=$l"
	insertTree $o $tektree 1
    }

        # valid or revoked
    # initial sorting
    ObjectListBox_Sort $tektree serial 0 "cert"
    if {$certIDRev != 0 } {
	$tektree selection set {0}
    } 
}


proc CRLManager_Update {w tektree} {
    global db
    global crlID
    
    debug::msg "CRLManager_Update $w $tektree"
        
    if {$crlID != 0 } {
	$tektree selection set {0}
	for {set j 0 } { $j < $crlID} {incr j} {
	    $tektree delete $j
	}
	set crlID 0
    }
    foreach v [openssl::GetCRLDB] {
	insertTreeCRL $v $tektree
    }
    # initial sorting
    ObjectListBox_Sort $tektree serial 0 "crl"
    if {$crlID != 0 } {
	$tektree selection set {0}
    } 
}


proc RequestManager_Update {w tektree} {
    global db
    global reqID
    
    debug::msg "RequestManager_Update $w $tektree"
        
    if {$reqID != 0 } {
	$tektree selection set {0}
	for {set j 0 } { $j < $reqID} {incr j} {
	    $tektree delete $j
	}
	set reqID 0
    }
    foreach v [openssl::GetRequestDB] {
#puts "RequestManager_Update=$v"
	insertTreeReq $v $tektree 0
    }
    # initial sorting
    ObjectListBox_Sort $tektree serial 0 "req"
    if {$reqID != 0 } {
	$tektree selection set {0}
    } 
}

proc RequestArManager_Update {w tektree} {
    global db
    global reqIDAr
#puts "RequestArManager_Update START"

    debug::msg "RequestManager_Update $w $tektree"
        
    global reqIDAr
    if {$reqIDAr != 0 } {
	$tektree selection set {0}
	for {set j 0 } { $j < $reqIDAr} {incr j} {
	    $tektree delete $j
	}
	set reqIDAr 0
    }
    foreach v [openssl::GetRequestArDB] {
	insertTreeReq $v $tektree 1
    }
        # valid or revoked
    # initial sorting
    ObjectListBox_Sort $tektree serial 0 "req"
    if {$reqIDAr != 0 } {
	$tektree selection set {0}
    } 
#puts "RequestArManager_Update END"
}

proc insertTree {v tektree typecert} {
    global certID
    global certIDRev
#typecert 0 - certificate 1 - revoke certificate
        # valid or revoked
        set status [lindex $v 0]
        # s/n
        set serial [lindex $v 3]
#puts "SERIAL=$serial"
        set hiddenserial [string repeat " " 64]$serial
        set hiddenserial [string range $hiddenserial [expr [string length $hiddenserial] - 64] end]
        # date
        set t [lindex $v 1]
        set date [clock format [clock scan "[string range $t 0 1]-[string range $t 2 3]-[string range $t 4 5] [string range $t 6 7]:[string range $t 8 9]"] -format "%d-%m-%Y %H:%M"]

        # date revoked
        set t [lindex $v 2]
        if {$t != ""} {
            set revokedate [clock format [clock scan "[string range $t 0 1]-[string range $t 2 3]-[string range $t 4 5] [string range $t 6 7]:[string range $t 8 9]"] -format "%d-%m-%Y %H:%M"]
        } else  {
            set revokedate ""
        }
#        set hiddenrevdate $t
        
        # distinguised name
        set dn [lindex $v 5]
        set ckaid [lindex $v 6]
#puts "ckaid=$ckaid"
        # common name -> find out from dn
	set cn ""
	set email ""
        if {[string first "/=" $dn] != -1} {
    	    set v [lrange [split $dn /=] 1 end]
        } else {
	    set lsub [split $dn ","]
	    foreach com $lsub {
		set cn1 [string trim $com]
		if { "CN=" == [string range $cn1 0 2]} {
		    set cn [string  range $cn1 3 end]
		} 
		if { "EMAIL=" == [string range $cn1 0 5]} {
		    set email [string  range $cn1 6 end]
		} 
	    }
        }
	if {$cn == ""} {
        # cn contains now common name
    	    foreach {label cn} $v { if {$label == "CN"} break}
        # email -> retrieve from dn
    	    foreach {label email} $v { if {$label == "Email"} break}
        # email contains now email
        }

    if {$typecert == 0 } {
	if {$revokedate == "" } {
    	    $tektree insert {} end -id $certID -values [list "Nick$certID" $serial $cn $email $status $date $revokedate $dn $ckaid] \
    	    -image validcert  -text "Nick$certID";
    	} else {
    	    $tektree insert {} end -id $certID -values [list "Nick$certID" $serial $cn $email $status $date $revokedate $dn $ckaid] \
    	    -image invalidcert  -text "Nick$certID";
    	}
	incr certID
    } else {
        $tektree insert {} end -id $certIDRev -values [list "Nick$certIDRev" $serial $cn $email $status $date $revokedate $dn $ckaid] \
    	    -image invalidcert  -text "Nick$certID";
	incr certIDRev
    } 
}

proc insertTreeReq {v tektree typereq} {
    global db
#typereq = 0
    global reqID
#typereq = 1
    global reqIDAr
    global certdb
#puts "insertTreeReq=$v"

        set nick [lindex $v 0]
        # import/locale
        set type [lindex $v 2]
#на рассмотрении/утвержден/выпущен сертификат
        set status [lindex $v 1]
        # s/n
        set serial [lindex $v 4]
#puts "REQ SERIAL=$serial"
        # date
        set t [lindex $v 3]
        set date [clock format [clock scan "[string range $t 0 1]-[string range $t 2 3]-[string range $t 4 5] [string range $t 6 7]:[string range $t 8 9]"] -format "%d/%m/%Y %H:%M"]
        # distinguised name
        set dn [lindex $v 5]
        set ckaid [lindex $v 6]
#puts "REQ ckaid=$ckaid"
        # common name -> find out from dn
	set cn ""
	set email ""
        if {[string first "/=" $dn] != -1} {
    	    set v [lrange [split $dn /=] 1 end]
        } else {
	    set lsub [split $dn ","]
	    foreach com $lsub {
		set cn1 [string trim $com]
		if { "CN=" == [string range $cn1 0 2]} {
		    set cn [string  range $cn1 3 end]
		} 
		if { "EMAIL=" == [string range $cn1 0 5]} {
		    set email [string  range $cn1 6 end]
		} 
	    }
        }
	if {$cn == ""} {
        # cn contains now common name
    	    foreach {label cn} $v { if {$label == "CN"} break}
        # email -> retrieve from dn
    	    foreach {label email} $v { if {$label == "Email"} break}
        # email contains now email
        }

	set imgcsr csr_40x19
	if {$status == "Утвержден"} {
	    set imgcsr csr_ok_40x19
	} elseif {$status == "Отклонен" } {
	    set imgcsr csr_refuze_40x19
	}

	if {$typereq == 0} {
    	    $tektree insert {} end -id $reqID -values [list "Nick$reqID" $serial $date $cn $type $status $ckaid] \
    		-image $imgcsr  -text "Nick$reqID";
	    incr reqID        
	} else {
    	    $tektree insert {} end -id $reqIDAr -values [list "Nick$reqID" $serial $date $cn $type $status $ckaid] \
    		-image $imgcsr  -text "Nick$reqID";
	    incr reqIDAr
	}
}

proc insertTreeCRL {v tektree } {
    global db
    global crlID
    global certdb
#puts "insertTreeCRL=$v"
        set nick [lindex $v 0]
        # import/locale
        set signtype [lindex $v 1]
        if {$signtype == ""} {return}
#        set signtype [string map {" " "."} $signtype]
	set signtype $::pki::oids($signtype)
        # date
        set t [lindex $v 3]

        set pubdate [clock format [clock scan "[string range $t 0 1]-[string range $t 2 3]-[string range $t 4 5] [string range $t 6 7]:[string range $t 8 9]"] -format "%d-%m-%Y %H:%M"]
        set t [lindex $v 4]
        set nextdate [clock format [clock scan "[string range $t 0 1]-[string range $t 2 3]-[string range $t 4 5] [string range $t 6 7]:[string range $t 8 9]"] -format "%d-%m-%Y %H:%M"]
        # distinguised name
        set dn [lindex $v 2]
        set ckaid [lindex $v 0]
#puts "REQ ckaid=$ckaid"
        # common name -> find out from dn
	set cn ""
        if {[string first "/=" $dn] != -1} {
    	    set v [lrange [split $dn /=] 1 end]
        } else {
	    set lsub [split $dn ","]
	    foreach com $lsub {
		set cn1 [string trim $com]
		if { "CN=" == [string range $cn1 0 2]} {
		    set cn [string  range $cn1 3 end]
		} 
		if { "EMAIL=" == [string range $cn1 0 5]} {
		    set email [string  range $cn1 6 end]
		} 
	    }
        }
	if {$cn == ""} {
        # cn contains now common name
    	    foreach {label cn} $v { if {$label == "CN"} break}
        # email -> retrieve from dn
    	    foreach {label email} $v { if {$label == "Email"} break}
        # email contains now email
        }

	set imgcsr csr_40x19

    	    $tektree insert {} end -id $crlID -values [list "CRL $ckaid" $ckaid $cn $signtype $pubdate $nextdate] \
    		-image $imgcsr  -text "CRL $ckaid";
	    incr crlID        
}

proc viewDouble {w type} {
#puts "viewDouble w=$w"
    set s {}
#1 - поле серийного номера а надо ckaID или сам сертификат
#    foreach i [$w curselection] 
    foreach i [$w selection] {
#Это серийный номер
#        lappend s [lindex [$w item $i -value] 1]
#А Это ckaID сертификата
	switch -- $type {
	    "cert"        { 
    		set s [lindex [$w item $i -value] 8]
		cmd::ViewByIndexCert $s
	    }
	    "req" { 
    		set s [lindex [$w item $i -value] 6]
		cmd::ViewByIndexReq $s
	    }
	    "crl" { 
    		set s [lindex [$w item $i -value] 1]
		cmd::ViewByIndexCRL $s
	    }
	    default { 
		break
	    }
	}
    }
}

proc showContextMenu {w x y rootx rooty} {
    
    set s {}
    set treeID {}
#1 - поле серийного номера а надо ckaID или сам сертификат
#    foreach i [$w curselection] 
    foreach i [$w selection] {
#Это серийный номер
#        lappend s [lindex [$w item $i -value] 1]
#А Это ckaID сертификата
        lappend s [lindex [$w item $i -value] 8]
        set tree [lindex [$w item $i -value] 0]
        lappend treeID [string range $tree 4 end]
    }
#puts "showContextMenu=$s"
#puts "treeID=$treeID" 

    if {$s != ""} {
        
        catch {destroy .contextMenu}
        menu .contextMenu -tearoff false
        
        .contextMenu configure -title "Certificate"
        .contextMenu add command \
                -label "Просмотр сертификата" \
                -command [list cmd::ViewByIndexCert $s]
        .contextMenu add command \
                -label "Просмотр запроса" \
                -command [list cmd::ViewByIndexReq $s]
        .contextMenu add command \
                -label "Экспорт сертификата" \
                -command [list cmd::PublishByIndex $s cert]
        .contextMenu add command \
                -label "Экспорт в PKCS#12" \
                -command [list cmd::PKCS12ByIndex $s]
        .contextMenu add separator
        .contextMenu add command \
                -label "Отзыв сертификата" \
                -command [list cmd::WizardRevokeCertificateByIndex $s $treeID]
        
        tk_popup .contextMenu $rootx $rooty
	.contextMenu configure -activebackground #cdc7c2
	.contextMenu configure -background #e0e0da

    }
    
}

proc showContextMenuRev {w x y rootx rooty} {
    
    set s {}
    set treeID {}
#1 - поле серийного номера а надо ckaID или сам сертификат
#    foreach i [$w curselection] 
    foreach i [$w selection] {
#Это серийный номер
#        lappend s [lindex [$w item $i -value] 1]
#А Это ckaID сертификата
        lappend s [lindex [$w item $i -value] 8]
        set tree [lindex [$w item $i -value] 0]
        lappend treeID [string range $tree 4 end]
    }
#puts "showContextMenu=$s"
#puts "treeID=$treeID" 

    if {$s != ""} {
        
        catch {destroy .contextMenu}
        menu .contextMenu -tearoff false
        
        .contextMenu configure -title "Certificate"

        .contextMenu add command \
                -label "Просмотр сертификата" \
                -command [list cmd::ViewByIndexCert $s]
        .contextMenu add separator
        .contextMenu add command \
                -label "Просмотр запроса" \
                -command [list cmd::ViewByIndexReq $s]
        
        tk_popup .contextMenu $rootx $rooty
	.contextMenu configure -activebackground #cdc7c2
	.contextMenu configure -background #e0e0da
        
    }
}



#
# Logging Window
#

namespace eval Log {
    
    #namespace export LogWindow;		# Initialization
    
    namespace export toggle;	# Command to map/unmap the
    
    variable mapped;		# Flag == 1 iff the 
#    console
    array set mapped {}
    
    
    variable logwindow
    variable filename
    variable logchannel
    
}



proc Log::CreateWindow {w} {
    variable mapped
    
    # this lets us be reentrant...
    catch {destroy $w}
    toplevel $w -bd 2  -relief flat -background #cdc7c2 -padx 0 -pady 0 
    wm title $w "Протокол работы УЦ"
    wm iconphoto $w iconCert_32x32
    wm geometry $w +200+100
#    $w configure -background #eff0f1
#Окно протокола не изменяется
    wm resizable $w 0 0

    pack [frame $w.f -bd 0 -relief sunken] -expand 1 -fill both -pady 0 -padx 0

    pack [frame $w.b -bd 0 -bg #eff0f1 ] -expand 1 -fill both -pady {2 0} -padx 0


    # frame so they look like a single widget
    ttk::scrollbar $w.f.vsb -orient vertical -command [list $w.f.text yview]
    ttk::scrollbar $w.f.hsb -orient horizontal -command [list $w.f.text xview]

    text $w.f.text \
      -bd 0 \
      -background white \
      -height 25 \
      -width 80 \
      -wrap none \
      -font TkFixedFont \
      -xscrollcommand [list $w.f.hsb set] \
      -yscrollcommand [list $w.f.vsb set]
#    eval "    $w.f.text config -yscrollcommand {hidescroll  $w.f.vsb}"
#    eval "    $w.f.text config -xscrollcommand {hidescroll  $w.f.hsb}"
    
    grid $w.f.vsb -in $w.f -row 0 -column 1 -sticky ns
    grid $w.f.hsb -in $w.f -row 1 -column 0 -sticky ew
    grid $w.f.text -in $w.f -row 0 -column 0 -sticky nwse -padx 0 -pady 0
    grid columnconfigure $w.f 0 -weight 1
    grid columnconfigure $w.f 1 -weight 1
    grid rowconfigure    $w.f 0 -weight 1
    grid rowconfigure    $w.f 1 -weight 1
    ttk::button $w.b.but -text "Закрыть" -command {Log::WindowToggle .log} -style MyBorder.TButton
    pack $w.b.but -side right -padx 10 -pady 5
    eval "ttk::button $w.b.clear -text {Очистить} -command {$w.f.text delete 0.0 end} -style MyBorder.TButton"
    pack $w.b.clear -side right -padx 10 -pady 5
    
    # hide window in stead of closing.
    #wm protocol $w WM_DELETE_WINDOW "wm withdraw $w"
    wm protocol $w WM_DELETE_WINDOW "Log::WindowToggle $w"
    
    # start hidden
#puts "Log=$w"
    wm withdraw $w
    set mapped($w) 0
    
    #tags
#    $w.f.text tag configure normal -font {{MS Sans Serif} 8}
    $w.f.text tag configure normal -font TkFixedFont
#    $w.f.text tag configure bold -font TkFixedFont
    $w.f.text tag configure bold -font {courier 10 bold}
    $w.f.text tag configure blue -foreground {blue}
    return $w
}

proc Log::WindowToggle {w} {

    variable mapped
    
    if {[wm state $w] != "normal"} {
	wm deiconify $w
	set mapped($w) 1
	raise $w
    } else {
	wm withdraw $w
	set mapped($w) 0
    }
}
proc Log::LogMessage {msg {option ""} } {

    variable logwindow
    variable logchannel
    if {[info exists logwindow]} {
	set w $logwindow
	if {$option == ""} {
	    $w.f.text insert end "$msg\n" normal
	} elseif {$option == "bold"} {
	    $w.f.text insert end "$msg\n" bold
	} elseif {$option == "blue"} {
	    $w.f.text insert end "$msg\n" blue
	}
	$w.f.text see end
    }
    
    if {[info exists logchannel]} {
	puts $logchannel $msg
	flush $logchannel
    }

}

proc Log::ToWindow {w} {
    variable logwindow
    
    CreateWindow $w
    set logwindow $w
}

proc Log::ToFile {fn} {
    variable filename
    variable logchannel
    
    set filename $fn
    
    if {[info exists logchannel]} {
	close $logchannel
    }

    
    set logchannel [open $filename "a"]

}

proc Log::Cleanup {} {
    variable logwindow
    variable logchannel
    
    if {[info exists logchannel]} {
	close $logchannel
    }    
}

#
# debugging utilities
# 
namespace eval debug {
    
    namespace export msg      ; # log debug message
    variable level
    set level 0               ; # level :
                                # 0 no debug
                                # 1 medium debug
                                # 2 high debug
}

proc debug::msg {msg {lvl 1}} {
    variable level
    #::LogWindow::LogMessage .log "debug::msg $msg $lvl (level = $level)" blue
    if {$lvl <= $level} {
	::Log::LogMessage "\[DEBUG\] $msg" blue
    }
}

proc Dialog_ShowCertificate {filename} {
    
    set crt_fn $filename
    set crtdetails [openssl::Certificate_GetInfo -filename $crt_fn -get details]
    set crttext [openssl::Certificate_GetInfo -filename $crt_fn -get text]
    set crtextensions [openssl::Certificate_GetInfo -filename $crt_fn -get extensions]
    set publickey [openssl::Certificate_GetInfo -filename $crt_fn -get publickey]
    #debug::msg "publickey=\n"
    #debug::msg "$publickey"
    set allfields [concat $crtdetails $crtextensions $publickey]
    set crtstatus [openssl::Certificate_IsValid -filename $crt_fn]
set certhex ""
#    set attr(exit) [Dialog_ShowCertificateInfo .popup {Certificate} $allfields $crttext $crtstatus]
    set attr(exit) [Dialog_ShowCertificateInfo .popup {Certificate} $allfields $crttext $certhex $crtstatus]

}

proc Dialog_ShowCertificateInfo {w title fieldvalues text certhex crtstatus} {
    
#    debug::msg "Dialog_ShowCertificateInfo $w $title $fieldvalues $text"
    
    global input_values
    array unset input_values
    array set input_values {}
    
    catch {destroy $w}
    toplevel $w -bd 3  -relief flat -background #cdc7c2 -padx 0 -pady 0
#    wm minsize $w 550 400
    set geometr [rect2window "." "550" "400" ]
    wm geometry $w $geometr
  #Окно не может перекрываться (yes)
    wm attributes $w -topmost yes   ;# stays on top - needed for Linux
    if {$title == "ViewCA"} {
	wm title $w "Просмотр корневого сертификата УЦ"
    } else {
	wm title $w $title
    }
    wm iconphoto $w iconCert_32x32
    

    set w1 $w
    frame $w.mainfr -relief flat -background #eff0f1 -bd 0

    pack $w.mainfr -fill both -pady 0 -expand 1
    set w $w.mainfr

#    Notebook:create $w.nb -pages {"Certificate" "Details" "Text"}
#ttk::style configure TNotebook -background #c0bab4 -relief flat -borderwidth 0
    ttk::notebook $w.nb  -width 400 -height 300 -pad 0
    $w.nb add [ttk::frame $w.nb.cert] -text "О сертификате" 
    $w.nb add [ttk::frame $w.nb.det] -text "Детали "
    $w.nb add [ttk::frame $w.nb.text] -text "Текст от OpenSSL"
    $w.nb add [ttk::frame $w.nb.textme] -text "Текст сертификата"

    pack $w.nb -expand 1 -fill both -padx 3 -pady 3
    
    frame $w.sep -height 2 -bd 0 -relief flat -background #cdc7c2
    pack $w.sep -fill x -pady 1mm

    ttk::button $w.buttclose -text "Отмена" -command "set input_values(exit) ok; destroy $w1" 
    pack $w.buttclose -side right -padx 3 -pady 6

    # Certificate Information
    set f $w.nb.cert
    
    text $f.text -wrap none  -font {Times 10 bold italic}  -background white

    grid $f.text -in $f -row 0 -column 0 -sticky nsew -padx 0 -pady 0
    grid columnconfigure $f 0 -weight 1
    grid rowconfigure    $f 0 -weight 1
    
    # now nicely display certificate information
    array set info $fieldvalues

    set fnt(std) [$f.text cget -font]

    set fnt(bold) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] bold]
    set fnt(italic) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] italic]
    
    $f.text tag configure bold -font $fnt(bold)
    $f.text tag configure italic -font $fnt(italic)

    frame $f.text.f1 -width 530 -height 2 -bg #e0e0da
    frame $f.text.f2 -width 530 -height 2 -bg #e0e0da
    
    openssl::Certificate_ParseDN $info(subject) info_subject
    openssl::Certificate_ParseDN $info(issuer) info_issuer
    
    #set crtstatus [openssl::Certificate_IsValid -serial $info(serial)]
    
    set valid [lindex $crtstatus 0]
    set validmessage [lindex $crtstatus 1]
    if {$valid} {
        set validtext "Этот сертификат действителен."
        set validmessage "\n"
	$f.text image create end -image img_cert
    } else  {
        set validtext "Этот сертификат не действителен."
        set validmessage "\tПричина: $validmessage\n"
	$f.text image create end -image img_cert_bad
    }
    
    if {$title == "ViewCA"} {
	$f.text insert end "  Информация о корневом сертификате вашего УЦ" bold
    } else {
	$f.text insert end "  Информация о сертификате" bold
    }
    
    $f.text insert end "\n"
    $f.text window create end -window $f.text.f1
    $f.text insert end "\n"
    
    $f.text insert end "    $validtext\n"
    $f.text insert end "\n"
    $f.text insert end "$validmessage\n"
    $f.text insert end "\n"
    
    $f.text insert end "\n"
    $f.text window create end -window $f.text.f2
    $f.text insert end "\n"
    
    $f.text insert end "    Этот сертификат\n"
    $f.text insert end "\n"
    $f.text insert end "\tвыдан: " bold
    $f.text insert end "$info_subject(CN)\n"

    $f.text insert end "\n"
    $f.text insert end "\tиздан в: " bold
    $f.text insert end "$info_issuer(CN)\n"
    $f.text insert end "\n"
    $f.text insert end "\tДействителен с " bold
    $f.text insert end "[clock format [clock scan $info(notBefore)] -format {%d %B %Y}]"
    $f.text insert end " по " bold
    $f.text insert end "[clock format [clock scan $info(notAfter)] -format {%d %B %Y}]"
    $f.text insert end "\n"
    
    $f.text configure -state disabled
    
    set f $w.nb.det
        
    # frame so they look like a single widget
    ttk::scrollbar $f.vsb -orient vertical -command [list $f.listbox yview]
    ttk::scrollbar $f.hsb -orient horizontal -command [list $f.listbox xview]
    
    # we will purposefully make the width less than the sum of the
    # columns so that the scrollbars will be functional right off
    # the bat.
    
    # add the columns we want to see
    ttk::treeview $f.listbox -columns {Field Value} -show headings -xscroll [list $f.hsb set] -yscroll [list $f.vsb set]
    $f.listbox heading Field -text Параметр 
    $f.listbox heading Value -text Значение 
    
    # screen to show details
    
    text $f.text -height 8 -width 20  -background white
    $f.text configure -state disabled
    
    grid $f.vsb -in $f -row 0 -column 1 -sticky ns
    grid $f.hsb -in $f -row 1 -column 0 -sticky ew
    grid $f.listbox -in $f -row 0 -column 0 -sticky nsew -padx 0 -pady 0
    grid $f.text -in $f -row 2 -column 0 -columnspan 2 -sticky nsew -padx 0 -pady 0
    grid columnconfigure $f 0 -weight 1
    grid columnconfigure $f 1 -weight 0
    grid rowconfigure    $f 0 -weight 1
    grid rowconfigure    $f 1 -weight 0
    grid rowconfigure    $f 2 -weight 0
    
    #$w.main.listbox delete 0 end
    foreach {field value} $fieldvalues {
        set fieldlabel [::openssl::GetDialogFieldLabel $field]
#        $f.listbox insert {} end -values  [list $fieldlabel $value]
        set vv [string map {"\n" "\\n"} $value]
#puts ("FIELDLABEL=$fieldlabel")
#puts ("VV=$vv")
        $f.listbox insert {} end -values  [list $fieldlabel $vv]
    }
    
    bind $f.listbox <ButtonRelease-1> \
            "Dialog_ShowCertificateInfo_clicked $f.listbox $f.text"
    
    
    # Text details from openssl
    set f $w.nb.text

    text $f.text -wrap none -font {courier 8} \
            -xscrollcommand [list $f.hsb set] \
            -yscrollcommand [list $f.vsb set] -background white
    # frame so they look like a single widget
    ttk::scrollbar $f.vsb -orient vertical -command [list $f.text yview]
    ttk::scrollbar $f.hsb -orient horizontal -command [list $f.text xview]
    grid $f.vsb -in $f -row 0 -column 1 -sticky ns
    grid $f.hsb -in $f -row 1 -column 0 -sticky ew
    grid $f.text -in $f -row 0 -column 0 -sticky nsew -padx 0 -pady 0
    grid columnconfigure $f 0 -weight 1
    grid columnconfigure $f 1 -weight 0
    grid rowconfigure    $f 0 -weight 1
    grid rowconfigure    $f 1 -weight 0
    
    #pack $f.text -expand 1 -fill both
    
    $f.text insert end $text
    $f.text configure -state disabled
    
    # Text details from Orlov V.
    set f $w.nb.textme 

    cert2text $w.nb.textme $certhex $certhex
  $w.nb.textme.text configure -state disabled

#tk busy здесь для красоты!!
    tk busy hold .cm
    menu_disable
    tkwait visibility $w
    grab  $w
    tkwait window $w1
    grab release $w
    tk busy forget .cm
    catch {menu_enable}
}
proc Dialog_ShowRequestInfo {w title fieldvalues text addbut fileimport} {
    
#    debug::msg "Dialog_ShowRequestInfo $w $title $fieldvalues $text $fileimport"
#puts "Dialog_ShowRequestInfo addbut=$addbut"
    global certdb
    global input_values
    array unset input_values
    array set input_values {}
    
    catch {destroy $w}
    toplevel $w -bd 3  -relief flat -background #cdc7c2 -padx 0 -pady 0 
    set geometr [rect2window "." "550" "400" ]
    wm geometry $w $geometr
  #Окно не может перекрываться (yes)
    wm attributes $w -topmost yes   ;# stays on top - needed for Linux
    wm title $w $title
    wm iconphoto $w iconCert_32x32

    set w1 $w
    frame $w.mainfr -relief flat -background #eff0f1 -bd 0 -padx 0 -pady 0

    pack $w.mainfr -fill both -pady 0 -expand 1
    set w $w.mainfr
#ttk::style configure TNotebook -background #c0bab4 -relief flat -borderwidth 0
    ttk::notebook $w.nb -width 400 -height 300 -pad 0
    $w.nb add [ttk::frame $w.nb.cert] -text "О запросе" 
    $w.nb add [ttk::frame $w.nb.det] -text "Детали "
    $w.nb add [ttk::frame $w.nb.text] -text "Текст"

    pack $w.nb -expand 1 -fill both -padx 3 -pady 3
    
#    frame $w.sep -height 2 -bd 2 -relief groove -background #c0bab4
    frame $w.sep -height 2 -bd 0 -relief flat -background #cdc7c2
    pack $w.sep -fill x -pady 1mm

    set createReq ""
    set reqstatus {Рассматривается Import "Не известно" }
#Просмотр из БД
    if {$addbut == 0 } {
	ttk::button $w.buttclose -text "Отмена" -command "set input_values(exit) ok; destroy $w1" 
	pack $w.buttclose -side right -padx 5 -pady 6
	set createReq "Запрос создан в данном УЦ"
	set ss [catch {certdb eval {select reqDB.status, reqDB.type, reqDB.datereq from reqDB where reqDB.ckaID=$fileimport}} reqstatus]
	if {$reqstatus == ""} {
	    set ss [catch {certdb eval {select reqDBAr.status, reqDBAr.type, reqDBAr.datereq from reqDBAr where reqDBAr.ckaID=$fileimport}} reqstatus]
	}	
	if {$reqstatus == ""} {
    	    tk_messageBox -icon error -type ok -title "Просмотр запроса" -message "Не могу найти запрос (status и т.д)"  -parent .cm
    	    return
	}
	if {[lindex $reqstatus  1] == "Import" } {
	    set createReq "Запрос был импортирован"
	}
#	puts "regDB=$reqstatus"
#Просмотр при импорте
    } elseif {$addbut == 1} {
	global typeimport
	set typeimport 1
	
	ttk::button $w.buttclose -text "Отмена" -command "set input_values(exit) ok; destroy $w1" 
	ttk::button $w.buttimport -text "Импорт" -command "importRequest \"$fileimport\" $w1" 
	labelframe $w.tzap -text {Запрос создан} -bg #bee9fd -bd 2 -labelanchor w  -font {Times 11 bold italic} -relief flat -highlightthickness 2 -highlightbackground #c0bab4
	ttk::style configure TRadiobutton -background #bee9fd 
	ttk::radiobutton $w.tzap.timp -text "в УЦ" -variable typeimport -value 0
	# -background #ff9060
	ttk::radiobutton $w.tzap.timp1 -text "заявителем" -variable typeimport -value 1
	# -background #ff9060
	pack $w.tzap.timp $w.tzap.timp1 -in $w.tzap -side right -padx 5 
	pack $w.buttclose $w.buttimport $w.tzap -side right -padx 5 -pady 6
	set createReq "Запрос создан пользователем"
#Просмотр сторонннкго запроса из файла
    } else {
	ttk::button $w.buttclose -text "Отмена" -command "set input_values(exit) ok; destroy $w1"
	pack $w.buttclose -side right -padx 5 -pady 6
	set createReq "Запрос создан пользователем"
    }

    # Certificate Information
    set f $w.nb.cert
    
    text $f.text -wrap none  -font {Times 10 bold italic}  -background white

    grid $f.text -in $f -row 0 -column 0 -sticky nsew -padx 0 -pady 0
    grid columnconfigure $f 0 -weight 1
    grid rowconfigure    $f 0 -weight 1
    
    # now nicely display certificate information
    array set info $fieldvalues

    set fnt(std) [$f.text cget -font]

    set fnt(bold) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] bold]
    set fnt(italic) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] italic]
    
    $f.text tag configure bold -font $fnt(bold)
    $f.text tag configure italic -font $fnt(italic)

    frame $f.text.f1 -width 530 -height 2 -bg #e0e0da
    frame $f.text.f2 -width 530 -height 2 -bg #e0e0da
    
    openssl::Certificate_ParseDN $info(subject) info_subject
    
    $f.text image create end -image img_cert
    $f.text insert end "   Информация о запросе" bold
    
    $f.text insert end "\n"
    $f.text window create end -window $f.text.f1
    $f.text insert end "\n"
    
    $f.text insert end "    Статус: [lindex $reqstatus 0]\n"
    $f.text insert end "\n"
    $f.text insert end "\n"
    set t [lindex $reqstatus 2]
    set date [clock format [clock scan "[string range $t 0 1]-[string range $t 2 3]-[string range $t 4 5] [string range $t 6 7]:[string range $t 8 9]"] -format "%d/%m/%Y %H:%M"]
    $f.text insert end "    Дата создания: "
    $f.text insert end $date

    $f.text insert end "\n"
    $f.text insert end "\n"
    $f.text window create end -window $f.text.f2
    $f.text insert end "\n"
    
    $f.text insert end "     Этот запрос\n"
    $f.text insert end "\n"
    $f.text insert end "\tПринадлежит (CN): " bold
    $f.text insert end "$info_subject(CN)\n\n"
    $f.text insert end "\tСоздан: " bold
    $f.text insert end "$createReq\n"

    $f.text insert end "\n"
    
    $f.text configure -state disabled
    
    set f $w.nb.det
        
    # frame so they look like a single widget
    ttk::scrollbar $f.vsb -orient vertical -command [list $f.listbox yview]
    ttk::scrollbar $f.hsb -orient horizontal -command [list $f.listbox xview]
    
    # we will purposefully make the width less than the sum of the
    # columns so that the scrollbars will be functional right off
    # the bat.
    ttk::treeview $f.listbox -columns {Field Value} -show headings -xscroll [list $f.hsb set] -yscroll [list $f.vsb set]
    $f.listbox heading Field -text Параметр 
    $f.listbox heading Value -text Значение 
    
    
    # screen to show details
    
    text $f.text -height 8 -width 20  -background white
    $f.text configure -state disabled
    
    # set up bindings to sort the columns.
    #$f.listbox label bind serial <ButtonPress-1> "sort %W serial"
    #$f.listbox label bind value <ButtonPress-1> "sort %W value"
    
    grid $f.vsb -in $f -row 0 -column 1 -sticky ns
    grid $f.hsb -in $f -row 1 -column 0 -sticky ew
    grid $f.listbox -in $f -row 0 -column 0 -sticky nsew -padx 0 -pady 0
    grid $f.text -in $f -row 2 -column 0 -columnspan 2 -sticky nsew -padx 0 -pady 0
    grid columnconfigure $f 0 -weight 1
    grid columnconfigure $f 1 -weight 0
    grid rowconfigure    $f 0 -weight 1
    grid rowconfigure    $f 1 -weight 0
    grid rowconfigure    $f 2 -weight 0
    
    foreach {field value} $fieldvalues {
        set fieldlabel [::openssl::GetDialogFieldLabel $field]
        $f.listbox insert {} end -values  [list $fieldlabel $value]
    }
    
    bind $f.listbox <ButtonRelease-1> \
            "Dialog_ShowCertificateInfo_clicked $f.listbox $f.text"
    #bindtags $f.listbox "Mclistbox $f.listbox .popup all"
    
    # Text details
    set f $w.nb.text

    text $f.text -wrap none -font {courier 8} \
            -xscrollcommand [list $f.hsb set] \
            -yscrollcommand [list $f.vsb set] -background white
    # frame so they look like a single widget
    ttk::scrollbar $f.vsb -orient vertical -command [list $f.text yview]
    ttk::scrollbar $f.hsb -orient horizontal -command [list $f.text xview]
    grid $f.vsb -in $f -row 0 -column 1 -sticky ns
    grid $f.hsb -in $f -row 1 -column 0 -sticky ew
    grid $f.text -in $f -row 0 -column 0 -sticky nsew -padx 0 -pady 0
    grid columnconfigure $f 0 -weight 1
    
    $f.text insert end $text
    $f.text configure -state disabled

#tk busy здесь для красоты!!
    tk busy hold .cm
    menu_disable
    tkwait visibility $w
    grab  $w
    tkwait window $w1
    grab release $w
    tk busy forget .cm
    catch {menu_enable}
    
}

proc Dialog_ShowCRLInfo {w title fieldvalues text fileimport} {
    
#    debug::msg "Dialog_ShowRequestInfo $w $title $fieldvalues $text $fileimport"
#puts "Dialog_ShowRequestInfo addbut=$addbut"
    global certdb
    global input_values
    array unset input_values
    array set input_values {}
    set ss [certdb eval {select crlDB.publishdate, crlDB.nextdate, crlDB.signtype from crlDB where crlDB.ID=$fileimport}]
    if {$ss == ""} {
	set f [open $fileimport r]
	chan configure $f -translation binary
	set crl [read $f]
	close $f
#	puts "CRL=$crl"
	array set b [parse_crl $crl]
#    parray b
	lappend ss $b(publishDate)
	lappend ss $b(nextDate)
	lappend ss $b(signtype)
#	puts "CRL=$ss"
    }
    catch {destroy $w}
    toplevel $w -bd 3  -relief flat -background #cdc7c2 -padx 0 -pady 0 
#Центрируем окно
    set geometr [rect2window "." "550" "400" ]
    wm geometry $w $geometr
#Окно не может перекрываться (yes)
    wm attributes $w -topmost yes   ;# stays on top - needed for Linux
    wm title $w $title
    wm iconphoto $w iconCert_32x32
    
    set w1 $w
    frame $w.mainfr -relief flat -background #eff0f1 -bd 0

    pack $w.mainfr -fill both -pady 0 -expand 1
    set w $w.mainfr

#ttk::style configure TNotebook -background #c0bab4 -relief flat -borderwidth 0
    ttk::notebook $w.nb -width 400 -height 300 -pad 0
    $w.nb add [ttk::frame $w.nb.cert] -text "О CRL/СОС" 
    $w.nb add [ttk::frame $w.nb.det] -text "Детали"
    $w.nb add [ttk::frame $w.nb.text] -text "Текст"

    pack $w.nb -expand 1 -fill both -padx 3 -pady 3
    
    set reqstatus {Рассматривается Import "Не известно" }

    frame $w.sep -height 2 -bd 0 -relief flat -background #cdc7c2
    pack $w.sep -fill x -pady 2

    ttk::button $w.buttclose -text "Отмена" -command "set input_values(exit) ok; destroy $w1" 
    pack $w.buttclose -side right -padx 5 -pady 6

    # Certificate Information
    set f $w.nb.cert
    
    text $f.text -wrap none  -font {Times 10 bold italic}  -background white

    grid $f.text -in $f -row 0 -column 0 -sticky nsew -padx 0 -pady 0
    grid columnconfigure $f 0 -weight 1
    #grid columnconfigure $f 1 -weight 0
    grid rowconfigure    $f 0 -weight 1
    
    # now nicely display certificate information
    array set info $fieldvalues
#parray info

    set fnt(std) [$f.text cget -font]

    set fnt(bold) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] bold]
    set fnt(italic) [list [lindex $fnt(std) 0] [lindex $fnt(std) 1] italic]
    
    $f.text tag configure bold -font $fnt(bold)
    $f.text tag configure italic -font $fnt(italic)

    frame $f.text.f1 -width 530 -height 2 -bg #e0e0da
    frame $f.text.f2 -width 530 -height 2 -bg #e0e0da
    
    openssl::Certificate_ParseDN $info(issuer) info_subject
    
    $f.text image create end -image img_cert
    $f.text insert end "   Информация о CRL/СОС" bold
    
    $f.text insert end "\n"
    $f.text window create end -window $f.text.f1
    $f.text insert end "\n"
    set t [lindex $ss 0]
    set date [clock format [clock scan "[string range $t 0 1]-[string range $t 2 3]-[string range $t 4 5] [string range $t 6 7]:[string range $t 8 9]"] -format "%d-%m-%Y %H:%M"]
    $f.text insert end "    Дата создания CRL: $date\n"
    $f.text insert end "\n"
    $f.text insert end "\n"
    set t [lindex $ss 1]
    set date [clock format [clock scan "[string range $t 0 1]-[string range $t 2 3]-[string range $t 4 5] [string range $t 6 7]:[string range $t 8 9]"] -format "%d-%m-%Y %H:%M"]
    $f.text insert end "    Очередная дата выпуска CRL: $date "

    $f.text insert end "\n"
    $f.text insert end "\n"
    $f.text window create end -window $f.text.f2
    $f.text insert end "\n"
    
    $f.text insert end "    Список отозванных сертификатов\n"
    $f.text insert end "\n"
    $f.text insert end "\tВыпущен (CN): " bold
    $f.text insert end "$info(CN)\n\n"
    $f.text insert end "\tАлгоритм электронной подписи: " bold
    set sign [string map {" " "."} [lindex $ss 2]]
    set signtype $::pki::oids($sign)

    $f.text insert end "$signtype \n\t\t\t\t\t($sign)\n\n"

    $f.text insert end "\n"
    
    $f.text configure -state disabled
    
    set f $w.nb.det
        
    # frame so they look like a single widget
    ttk::scrollbar $f.vsb -orient vertical -command [list $f.listbox yview]
    ttk::scrollbar $f.hsb -orient horizontal -command [list $f.listbox xview]
    
    # we will purposefully make the width less than the sum of the
    # columns so that the scrollbars will be functional right off
    # the bat.
    ttk::treeview $f.listbox -columns {Field Value} -show headings -xscroll [list $f.hsb set] -yscroll [list $f.vsb set]
    $f.listbox heading Field -text Параметр 
    $f.listbox heading Value -text Значение 
    
    
    # screen to show details
    
    text $f.text -height 8 -width 20  -background white
    $f.text configure -state disabled
    
    grid $f.vsb -in $f -row 0 -column 1 -sticky ns
    grid $f.hsb -in $f -row 1 -column 0 -sticky ew
    grid $f.listbox -in $f -row 0 -column 0 -sticky nsew -padx 0 -pady 0
    grid $f.text -in $f -row 2 -column 0 -columnspan 2 -sticky nsew -padx 0 -pady 0
    grid columnconfigure $f 0 -weight 1
    grid columnconfigure $f 1 -weight 0
    grid rowconfigure    $f 0 -weight 1
    grid rowconfigure    $f 1 -weight 0
    grid rowconfigure    $f 2 -weight 0
    
    foreach {field value} $fieldvalues {
        set fieldlabel [::openssl::GetDialogFieldLabel $field]
        $f.listbox insert {} end -values  [list $fieldlabel $value]
    }
    
    bind $f.listbox <ButtonRelease-1> \
            "Dialog_ShowCertificateInfo_clicked $f.listbox $f.text"
    
    # Text details
    set f $w.nb.text

    text $f.text -wrap none -font {courier 8} \
            -xscrollcommand [list $f.hsb set] \
            -yscrollcommand [list $f.vsb set] -background white
    # frame so they look like a single widget
    ttk::scrollbar $f.vsb -orient vertical -command [list $f.text yview]
    ttk::scrollbar $f.hsb -orient horizontal -command [list $f.text xview]
    grid $f.vsb -in $f -row 0 -column 1 -sticky ns
    grid $f.hsb -in $f -row 1 -column 0 -sticky ew
    grid $f.text -in $f -row 0 -column 0 -sticky nsew -padx 0 -pady 0
    grid columnconfigure $f 0 -weight 1
    grid columnconfigure $f 1 -weight 0
    grid rowconfigure    $f 0 -weight 1
    grid rowconfigure    $f 1 -weight 0
    
    #pack $f.text -expand 1 -fill both
    
    $f.text insert end $text
    $f.text configure -state disabled
#tk busy здесь для красоты!!
    tk busy hold .cm
    menu_disable
    tkwait visibility $w
    grab  $w
    tkwait window $w1
    grab release $w
    tk busy forget .cm
    catch {menu_enable}
}

proc Dialog_ShowCertificateInfo_clicked {w target} {
    set num [$w selection]
#puts "SELECT=$num"
    #puts "curselection :\n$s"
    set s [$w item $num -value]
#puts "TekStr=$s"

    set splitlist {
        "Issued By"
        "Subject"
        {Basic Constraints}
        {Key Usage}
        {Netscape Cert Type}
        {Ext. Key Usage}
    }
    set nonsplitlist {
        "Serial #"
        "Valid From"
        "Valid Until"
        {MD5 Fingerprint}
        {Subject Key ID}
        {Authority Key ID}
        {Netscape Comment}
    }
    
    if {$s != ""} {
	set s [string map {"\\n" "\n"} $s]

        set text [lindex $s 1]
        if {[lsearch $splitlist [lindex $s 0]] != -1} {
    	    set text [string trimleft $text /]
            set text [string map {"/" ","} $text]
            set text [join [split $text ,] \n]
        }
        #puts "text=$text"
        $target configure -state normal
        $target delete 1.0 end
        $target insert end $text
        $target configure -state disabled
                
    }
    
}

proc importRequest {fileimport w} {
    global typeimport
    global db
    global certdb
    global reqID
    global input_values
    array unset input_values
    array set input_values {}
#puts "typeImport=$typeimport"
    set typereq ""
    if {$fileimport == ""} {rerturn}
    if { [string range $fileimport 0 9 ] != "-----BEGIN" } {
	set fd [open $fileimport]
	chan configure $fd -translation binary
	set req [read $fd]
	close $fd
	set typereq "Import"
    } else {
	set req $fileimport
	set typereq "Locale"
    }
    if {$typeimport == 1} {
	set typereq "Import"
    } else {
	set typereq "Locale"
    }
    array    set b [parse_csr_gost $req]
#    puts "A=$b(pem)"
    set pem $b(pem)
    set subject $b(subject)
    set pubkey $b(pubkey)
    set key1 [binary format H* $pubkey]
    set ckaID [::sha1::sha1 $key1]
    set serReq $db(serNumReq)
    set datereq [clock format [clock seconds]  -format {%y%m%d%H%M%S}]
    set sn [format %x $serReq]
    set nick "Nick$sn"
   
#type - imported2
    certdb eval {begin transaction}
	set err [catch {certdb eval {insert into reqDB values( $ckaID, $nick, $sn, $subject, $typereq, $datereq, "рассматривается", $pem, "")}} result]
    certdb eval {end transaction} 
    Log::LogMessage "\[importReq\] error=$err"
    Log::LogMessage "ACTION=inportReq : \[$result\]"
    # check for common error conditions
    set errmsg [openssl::CheckCommonErrors $result]
    if {$errmsg != ""} {
        tk_messageBox -icon error -type ok -title "Импорт запроса запрещен" -message "$errmsg"  -parent .cm
    } elseif {$err == 0} {
	incr db(serNumReq)
	certdb eval {begin transaction}
	certdb eval {update mainDB set serNumReq=$db(serNumReq) where dateCreateDB=$db(dateCreateDB)}
	certdb eval {end transaction} 
	set db(ckaID) $ckaID

#puts "NEW_SER=$db(serNumReq)"
	set l {}
	certdb eval {select * from reqDB where ckaID=$db(ckaID)} vals {
#	parray vals
	    lappend l $vals(nick)	    
	    lappend l $vals(status)	    
	    lappend l $vals(type)	    
	    lappend l $vals(datereq)	    
	    lappend l $vals(sernum)	    
	    lappend l $vals(subject)	    
	    lappend l $vals(ckaID)
	}

	insertTreeReq $l $db(treeReq) 0
	if {$reqID != 0 } {
	    set num [expr $reqID -1]
	    $db(treeReq) selection set $num
	} 
    }
    set input_values(exit) ok; 
    if {$w != "" } {
        destroy $w
    }
}

proc insertCert {cert incrserial} {
    global db
    global certdb
#puts "insertCert=$cert"
    array    set b [parse_cert_gost $cert]
#	parray b
    set pubkey $b(pubkey)
    set key1 [binary format H* $pubkey]
    set ckaID [::sha1::sha1 $key1]

    set subject $b(subject)
    set notAfter [clock format $b(notAfter) -format {%y%m%d%H%M%S}]
    set notBefore [clock format $b(notBefore) -format {%y%m%d%H%M%S}]
        set ser_num $b(serial_number) 
	set sn [format %x $ser_num]
#puts "SUBJECT=$subject"
#puts "SERNUM_DEC=$ser_num"
#puts "SERNUM=$sn"
#puts "notAfter=$notAfter"
#puts "notBefore=$notBefore"
set nick "Nick$sn"
    set daterevoke ""
    certdb eval {begin transaction}
	set err [catch {certdb eval {insert into certDB values( $ckaID, $nick, $sn, $cert, $subject, $notAfter, $notBefore, "", "V")}} result]
#Список новых сертификатов
	certdb eval {insert into certDBNew values ( $ckaID) }
    certdb eval {end transaction} 
    Log::LogMessage "\[insertCert\] error=$err"
    Log::LogMessage "ACTION=insertCert : \[$result\]"
    # check for common error conditions
    set errmsg [openssl::CheckCommonErrors $result]
    if {$errmsg != ""} {
        tk_messageBox -icon error -type ok -title "Выпуск сертификата запрещен!" -message "$errmsg"  -parent .cm
    } elseif {$err == 0} {
	certdb eval {begin transaction}
	if {$incrserial == 1} {
	    incr db(serNumCert)
#puts "NEW_SER=$db(serNumCert)"
	    certdb eval {update mainDB set serNumCert=$db(serNumCert) where dateCreateDB=$db(dateCreateDB)}
	}
	certdb eval {end transaction} 
    } else {
        tk_messageBox -icon error -type ok -title Error -message "Не смог выполнить insertCert"  -parent .cm
    }
    set db(ckaID) $ckaID
}
    

proc insertCertRoot {cert} {
    global db
    global certdb
    certdb eval {begin transaction}
	certdb eval {update mainDB set certCA=$cert where dateCreateDB=$db(dateCreateDB)}
    certdb eval {end transaction} 
    set file [file join $db(dir) rootca.pem]
    set fd [open $file w]
    puts $fd $cert
    close $fd
    set db(certCA) $cert
}

proc insertKeyRoot {key} {
    global db
    global certdb
    certdb eval {begin transaction}
	certdb eval {update mainDB set keyCA=$key where dateCreateDB=$db(dateCreateDB)}
    certdb eval {end transaction} 
    set file [file join $db(dir) rootca.key]
    set fd [open $file w]
    puts $fd $key
    close $fd
#puts "insertKeyRoot=$file"
    set prof(CA.private_key) $file
    set db(keyCA) $key
}

proc insertCRL {crl} {
    global db
    global certdb
    array set b [parse_crl $crl]
#    parray b
    certdb eval {begin transaction}
	certdb eval {insert into crlDB values (NULL, $b(signtype), $b(issue), $b(publishDate), $b(nextDate), $crl)}
    certdb eval {end transaction} 
#################
    CRLManager_Update .cm $db(treeCRL)
}

namespace eval cmd {
    variable _cmd
}


proc cmd::WizardCreateRequestDB {} {
    
    debug::msg "cmd::WizardCreateRequestDB"
    
    set name ".cm.certificatewizard"
    [$name namespace]::initwizard $name csrdb
    $name show
#    puts "cmd::WizardCreateRequestDB END"
}

proc cmd::WizardCreateRequest {} {
    
    debug::msg "cmd::WizardCreateRequest"
    
    set w .cm.certificatewizard
    [$w namespace]::initwizard $w csr
    $w show
    raise $w
    
}

proc cmd::WizardRevokeCertificate {} {
    
    debug::msg "cmd::WizardRevokeCertificate"
    
    set w .cm.revokewizard
    [$w namespace]::initwizard $w revoke "" "" ""
    $w show
    raise $w
}

proc cmd::WizardRevokeCertificateByIndex {certs treeID} {
    
    debug::msg "cmd::WizardRevokeCertificateByIndex"
    
    foreach cert $certs {
        # get certificate filename
        set filename [openssl::Object_GetPEMforCKAID $cert "cert"]
    }
    
    set w .cm.revokewizard
#DB
    [$w namespace]::initwizard $w revokebyindex $filename $certs $treeID
    $w show
    raise $w
}

proc cmd::WizardExamineRequestByIndex {reqs treeID} {
    
    debug::msg "cmd::WizardExamineRequestByIndex"
    
    foreach req $reqs {
        # get certificate filename
        set filename [openssl::Object_GetPEMforCKAID $req "req"]
    }
    
    set w .cm.revokewizard
#DB
    [$w namespace]::initwizard $w examinebyindex $filename $reqs $treeID
    $w show
    raise $w
}

proc cmd::WizardGenerateCRL {} {
    
    debug::msg "cmd::WizardGenerateCRL"
    
    set w .cm.crlwizard
    [$w namespace]::initwizard $w
    $w show
    raise $w
}

proc cmd::WizardSignRequest {} {
    
    debug::msg "cmd::WizardSignRequest"
    
    set w .cm.signwizard
    [$w namespace]::initwizard "signreqfile" "" "" ""
    $w show
#MY    wm stat .cm withdraw
    wm state $w withdraw
    wm state $w normal
    raise $w .
}

proc cmd::WizardSignRequestByIndex {reqs treeID} {
    
    debug::msg "cmd::WizardSignRequestByIndex"
    global dbca

    foreach req $reqs {
	set conf [certdb eval {select reqDB.status from reqDB where reqDB.ckaID=$req}]
	if {$conf != "Утвержден"} {
    	    tk_messageBox -icon error -type ok -title "Выпуск сертификата" -message "Заявка еще не утверждена!!!\n(\"$conf\")"  -parent .cm
	    continue
	}
        # get certificate filename
        set filename [openssl::Object_GetPEMforCKAID $req "req"]
	set w .cm.signwizard
#puts "WizardSignRequestByIndex: $req"
	[$w namespace]::initwizard "signreq" $filename $req $treeID 
	$w show
	raise $w 
#Модальность
	focus $w
	grab $w
	set dbca ""
	vwait  dbca
#	tkwait window $w
	grab release $w
    }

}


proc cmd::WizardExportPKCS12 {file} {
    global dbca
    set dbca ""

    debug::msg "cmd::WizardExportPKCS12"
    
    set w .cm.exportp12wizard
    [$w namespace]::initwizard $w $file
#MY    wm state .cm withdraw
    $w show
}

proc cmd::CreateDB {} {
    debug::msg "cmd::CreateDB"
#MY    wm state .cm withdraw
    set w .cm.setupwizard
    $w show
    return
}

proc cmd::OpenDB {} {
    global db
    global dbca
    if {$db(filedb) != "" } {
	tk_messageBox -title "Открытие БД УЦ" -icon info -type ok -message "У вас уже открыта БД\n$db(filedb)\nНеобходимо закрыть ее"
	return
    }

    set dbca ""
    debug::msg "cmd::OpenDB"
#    set ::pki::oids(1.2.643.2.2.19) "gost2001pubKey"
#    set ::pki::oids(1.2.643.2.2.3)  "gost2001withGOST3411_94"
    set ::pki::oids(1.2.643.100.1)  "OGRN"
    set ::pki::oids(1.2.643.100.5)  "OGRNIP"
    set ::pki::oids(1.2.643.3.131.1.1) "INN"
    set ::pki::oids(1.2.643.100.3) "SNILS"
#Для КПП ЕГАИС
    set ::pki::oids(1.2.840.113549.1.9.2) "UN"
#set ::pki::oids(1.2.840.113549.1.9.2) "unstructuredName"
#Алгоритмы подписи
    set ::pki::oids(1.2.643.2.2.3) "ГОСТ Р 34.10-2001"
    set ::pki::oids(1.2.643.7.1.1.3.2) "ГОСТ Р 34.10-2012-256"
    set ::pki::oids(1.2.643.7.1.1.3.3) "ГОСТ Р 34.10-2012-512"
#emailAddress
#    set ::pki::oids(1.2.840.113549.1.9.1) "emailAddress"

    set w .cm.opendb
    [$w namespace]::initwizard $w
    $w show
#    raise $w
#    grab $w
    vwait dbca
#	tkwait visibility $w
#	tkwait window .cm
    grab release $w
}
array set oid_gost_name { "1.2.643.2.2.19" {"ГОСТ Р 34.10-2001" 256}
			"1.2.643.7.1.1.1.1" {"ГОСТ Р 34.10-2012" 256}
			"1.2.643.7.1.1.1.2" {"ГОСТ Р 34.10-2012" 512}
}

proc cmd::CloseDB {} {
    global db
    global certID
    global crlID
    global certIDRev
    global reqID
    global reqIDAr
    global keyID
    global certdb
    global keydb
    debug::msg "cmd::CloseDB"
    if {$db(filedb) == ""} {
	return
    }
    if {$certID != 0 } {
	for {set j 0 } { $j < $certID} {incr j} {
	    if {[$db(treeCert) exists $j] } {
		$db(treeCert) delete $j
	    }
	}
	set certID 0
    }
    if {$reqID != 0 } {
	for {set j 0 } { $j < $reqID} {incr j} {
	    if {[$db(treeReq) exists $j] } {
		$db(treeReq) delete $j
	    }
	}
	set reqID 0
    }
    if {$certIDRev != 0 } {
	for {set j 0 } { $j < $certIDRev} {incr j} {
	    if {[$db(treeCertRev) exists $j] } {
		$db(treeCertRev) delete $j
	    }
	}
	set certIDRev 0
    }
    if {$reqIDAr != 0 } {
	for {set j 0 } { $j < $reqIDAr} {incr j} {
	    if {[$db(treeReqAr) exists $j] } {
		$db(treeReqAr) delete $j
	    }
	}
	set reqIDAr 0
    }
    if {$crlID != 0 } {
	for {set j 0 } { $j < $crlID} {incr j} {
	    if {[$db(treeCRL) exists $j] } {
		$db(treeCRL) delete $j
	    }
	}
	set crlID 0
    }
#    set w .opendb
#    [$w namespace]::initwizard $w
#    $w show
    set certID 0
    set reqID 0
    set crlID 0
    set certIDRev 0
    set reqIDAr 0
    set keyID 0

    catch {certdb close}
#    catch {keydb close}
    set certdb ""
    set keydb ""
    set db(filedb) ""
    menu_disable
}


proc cmd::WizardCreatePKCS12 {} {
    
    debug::msg "cmd::WizardCreatePKCS12"
    
    set w .cm.certificatewizard
    [$w namespace]::initwizard $w p12
    $w show
    raise $w
#    grab $w
    vwait dbca
    grab release $w
}

proc cmd::WizardCreateSelfSigned {} {
    
    debug::msg "cmd::WizardCreateSelfSigned"
    #tk_messageBox -title "Self Signed Certificates" -icon info -type ok -message "\"Self Signed Certificates\" is not yet implemented"
    set w .selfsignedwizard
    [$w namespace]::initwizard $w
    $w show
    raise $w
}

proc cmd::PublishByIndex {idcerts type} {
    set title "Выберите файл для сертификата"
    set typedb {
	{"Формат PEM"    *.pem}
	{"Формат PEM"    *.crt}
	{"Любой файл"  *}
    }
    set pubtit "Экспорт сертификата"
    set initf ""
    set dir [Config::Get folder.certificates]
    foreach idcert $idcerts {
	switch -- $type {
	    "cert" {
		    set cert [openssl::Object_GetPEMforCKAID $idcert $type]
		}
	    "crl" {
		    set dir [Config::Get folder.crls]
		    set pubtit "Экспорт СОС/CRL"
		    set title "Выберите файл для СОС/CRL"
    		    set initf [file join [::Config::Get folder.crls] "CAFL63-[clock format [clock seconds] -format {%Y-%m-%d}].crl"]
		    set typedb {
		    {"Формат CRL"    *.crl}
		    {"Формат PEM"    *.pem}
		    {"Формат DER"    *.der}
		    {"Любой файл"  *}
		}
		    set cert [openssl::Object_GetPEMforCKAID $idcert $type]
		}
	    default {
        	tk_messageBox -title "Экспорт" -icon error -message "Экспорт неизвестного объекта ($type).\n" -parent .cm
        	    return
	    }
	}
#    puts "PubCERT=$idcert"
	set file [tk_getSaveFile -title $title -filetypes $typedb -initialdir $dir -initialfile $initf -parent .cm]
	if {$file == ""} {
            tk_messageBox -title "$pubtit" -icon error -message "Файл не выбран.\n" -parent .cm
            continue
	}
	set fd [open $file w]
	puts  $fd $cert
	close $fd
	tk_messageBox -title $pubtit -icon info -message "Сертификат сохранен в\n$file" -parent .cm
    }
}

proc cmd::PKCS12ByIndex {idcerts} {
    set dir [Config::Get folder.certificates]
    foreach idcert $idcerts {
	set cert [openssl::Object_GetPEMforCKAID $idcert "cert"]
#	puts "CERT=$cert"
        array    set b [parse_cert_gost $cert]
        set ser_num $b(serial_number) 
	set sn [format %x $ser_num]
	set initf "$sn.pem"
	set filep12 [file join $dir $initf]
	puts "P12_SN=$filep12"
	set fd [open $filep12  w]
	puts  $fd $cert
	close $fd
	cmd::WizardExportPKCS12 $filep12
    }

}


proc cmd::ViewByIndexCertFromReq  {certs} {
    global certdb
    debug::msg "cmd::ViewByIndexCertFromReq $certs"
    
    # if >10 certs : limit to 10 certs
    if {[llength $certs]} {
        set certs [lrange $certs 0 9]
    }
    foreach cert $certs {
	set err [catch {certdb eval {select certDB.ckaID from certDB where certDB.ckaID=$cert}} result]
	if {$result == ""} {
    	    tk_messageBox -icon error -type ok -title "Изданный сертификат" -message "Сертификат еще не выпускался"  -parent .cm
    	    continue 
	}
	cmd::ViewByIndexCert $cert
    }
}



proc cmd::ViewByIndexCert {certs} {
    global certdb
    
    debug::msg "cmd::ViewByIndexCert $certs"
    
    # if >10 certs : limit to 10 certs
    if {[llength $certs]} {
        set certs [lrange $certs 0 9]
    }
    foreach cert $certs {
        
        set crttext [openssl::Certificate_GetInfo -serial $cert -get text]
        set crtdetails [openssl::Certificate_GetInfo -serial $cert -get details]
#puts "cmd::ViewByIndexCert crtdet=$crtdetails"
        set crtextensions [openssl::Certificate_GetInfo -serial $cert -get extensions]
        set publickey [openssl::Certificate_GetInfo -serial $cert -get publickey]
#puts "cmd::ViewByIndexCert pubkey=$publickey"
        set allfields [concat $crtdetails $crtextensions $publickey]
#        puts "ViewByIndexCert allfields=$allfields\n"
        #set allfields [concat $crtdetails $crtextensions]
        set crtstatus [openssl::Certificate_IsValidDB -serial $cert]
        #set attr(exit) [Dialog_ShowCertificateInfo .popup {Certificate} $allfields $crttext]
        set certhex [openssl::Object_GetPEMforCKAID $cert "cert"]
        if {$cert == "ca" } {
    	    Dialog_ShowCertificateInfo .popup$cert {ViewCA} $allfields $crttext $certhex $crtstatus
    	} else {
    	    Dialog_ShowCertificateInfo .popup$cert {Просмотр сертификата} $allfields $crttext $certhex $crtstatus
    	}
    }
}

proc page2com0 {} {
    cmd::ViewCertificateInfo
}
proc page3com0 {} {
    cmd::ViewCertificateInfo
}

proc page4com0 {} {
    cmd::ViewCRLInfo
}

proc page2com1 {} {
#puts "Просмотр корневого сертификата"
    cmd::ViewByIndexCert "ca"
}

proc page2com2 {} {
    exportCerts ca
}

proc page2com3 {} {
    global db
    global certdb 
    global cancelexport
    global countfile

    set cancelexport 0
    set dir [Config::Get web.outfolder]
    set typedb {
	{"Формат SQL-дампа DB"    *.dump}
	{"Любой файл"  *}
    }
    set initf "certAllDB.dump"
    set file [tk_getSaveFile -title "SQL-дамп таблицы всех сертификатов" -filetypes $typedb -initialdir $dir -initialfile $initf -parent .cm]
    if {$file == ""} {
            return
    }
################################
    set tabledb "certDB"
    set tab1 [certdb onecolumn {SELECT sql FROM sqlite_master WHERE name=$tabledb}]
    set tab1 [string trimright $tab1 ")"]
    set i [string first "(" $tab1] 
    incr i
    set tab1 [string range $tab1 $i end]
#puts "TAB1=$tab1"
    set newtab $tab1
    set tab1 [split $tab1 ","]
    set namecol {}
    foreach t1 $tab1 {
	lappend namecol [lindex $t1 0]
    }
#    puts "A=$namecol"
    set i 0
    set countfile 0
    set cancelexport 0
    set progr .cm.progress
    cagui::ProgressWindow_Create .cm.progress "SQL-дамп сертификатов" "Масштаб: все сертификаты"
    cagui::ProgressWindow_SetStatus $progr "Выгружено $i сертификат(ов)" 0
    update
    raise $progr
    set ff [open $file w]
	set csv {}
#puts "TABLEDB=$tabledb"
    set com {select * from $tabledb }
    set com1 [subst $com]
#    puts $com1

    puts $ff "PRAGMA foreign_keys=OFF;"
    puts $ff "BEGIN TRANSACTION;"
    puts $ff "CREATE TABLE $tabledb ($newtab);"
    certdb eval $com1 r {
	set csv {}
	foreach name $namecol {
	    if {$csv != {}} {
		    append csv ","
	    } else {
		    append csv "INSERT INTO \"$tabledb\" VALUES("
	    }
		    append csv \'$r($name)\'
	}
	append csv ");"
	puts $ff $csv
	flush $ff
	incr i
	cagui::ProgressWindow_SetStatus $progr "Выгружено $i сертификат(ов)"  $countfile
	update
	incr countfile
	if {$cancelexport == 1 } {
	    tk_messageBox -title "Дамп таблицы сертификатов" -icon info -message "Экспорт прерван.\n
Было экспортировано $i сертификатов.\n
SQL-дамп сертификатов сохранены в\n$file" -parent  .cm
	    incr countfile
	    break
	}
    }
    puts $ff "COMMIT;"
    close $ff
    cagui::ProgressWindow_SetStatus $progr "Выгружено $i сертификат(ов)" $countfile
    update
    tk_messageBox -title "Дамп таблицы сертификатов" -icon info -message "SQL-дамп сертификатов сохранен в\n$file" -parent .cm
    destroy $progr
    catch "destroy $progr"
}

proc page2com4 {} {
    global cancelexport
    global certdb
    global countfile
#    puts "Выгрузка новых сертификатов в SQL-дамп"
    set dir [Config::Get web.outfolder]
    set typedb {
	{"Формат dump"    *.dump}
	{"Любой файл"  *}
    }
    set initf "certDBNew.dump"
    set file [tk_getSaveFile -title "Выгрузка новых сертификатов в SQL-дамп" -filetypes $typedb -initialdir $dir -initialfile $initf -parent .cm]
    if {$file == ""} {
            return
    }
    set tab1 [certdb onecolumn {SELECT sql FROM sqlite_master WHERE name="certDB"}]
    set tab1 [string trimright $tab1 ")"]
    set i [string first "(" $tab1] 
    incr i
    set tab1 [string range $tab1 $i end]
    set tab1 [split $tab1 ","]
    set namecol {}
    foreach t1 $tab1 {
	lappend namecol [lindex $t1 0]
    }
#    puts "A=$namecol"
    set i 0
    set countfile 0
    set cancelexport 0
    cagui::ProgressWindow_Create .cm.progress "SQL-дамр новых сертификатов" "Масштаб: новые сертификаты"
    cagui::ProgressWindow_SetStatus .cm.progress "Выгружено $i сертификат(ов)" 0
    update
    raise .cm.progress
    set ff [open $file w]
    puts $ff "PRAGMA foreign_keys=OFF;"
    puts $ff "BEGIN TRANSACTION;"
    flush $ff 
    foreach cert [certdb eval {select certDBNew.ckaID from certDBNew}] {
	set csv {}
	certdb eval {select * from certDB where certDB.ckaID = $cert} r {
	    set csv {}
	    foreach name $namecol {
		if {$csv != {}} {
		    append csv ","
		} else {
		    append csv "INSERT INTO \"certDB\" VALUES("
		}
		    append csv \'$r($name)\'
	    }
	    append csv ");"
	    puts $ff $csv
	    flush $ff
	    incr i
	    certdb eval {begin transaction}
		certdb eval {delete from certDBNew where ckaID=$cert}
	    certdb eval {end transaction}
	    cagui::ProgressWindow_SetStatus .cm.progress "Выгружено $i сертификат(ов)"  $countfile
	    update
	    incr countfile
	    if {$cancelexport == 1 } {
		tk_messageBox -title "SQL-дамп новых сертификатов" -icon info -message "Экспорт прерван.\n
Было экспортировано $i сертификатов.\n
SQL-дамп сертификатов сохранены в\n$file" -parent .cm
		incr countfile
		break
	    }
	}
    }
    puts $ff "COMMIT;"
    close $ff
    cagui::ProgressWindow_SetStatus .cm.progress "SQL-дамп для $i сертификатов создан " $countfile
    update
    tk_messageBox -title "SQL-дамп новых сертификатов" -icon info -message "SQL-дамп сертификатов сохранен в\n$file" -parent .cm
    catch "destroy .cm.progress"
}

proc page2com5 {} {
    set w ".cm.mainfr.ff.notbok.p2.left.listbox"
    viewDouble $w "cert"
}

proc page3com2 {} {
    exportCerts revs
}
proc page3com3 {} {
    set w ".cm.mainfr.ff.notbok.p3.left.listbox"
    viewDouble $w "cert"
}

proc exportCerts {type} {
    global db
    global certdb
    global countfile
    global cancelexport
    set cert "XAXA"
    set dir [Config::Get folder.certificates]
    set title ""
    set typedb {
	{"Формат PEM"    *.pem}
	{"Любой файл"  *}
    }
    set initf ""
    set pubtit "Экспорт новых сертификатов"
    switch -- $type {
	news {
	    set com "[certdb eval {select certDBNew.ckaID from certDBNew}]"
	    set title "Выберите каталог для экспорта новых X509"
#	    set initf [file join $dir "NEWCERTS-[clock format [clock seconds] -format {%Y-%m-%d-%H-%M}].pem"]
	    set initf "certnew"
	    }
	revs {
	    set com "[certdb eval {select certDBRev.ckaID from certDBRev}]"
	    set title "Выберите каталог для экспорта отзванных X509"
#	    set initf [file join $dir "NEWCERTS-[clock format [clock seconds] -format {%Y-%m-%d-%H-%M}].pem"]
	    set initf "certrevoke"
	    set pubtit "Экспорт отозванных сертификатов"
	    }
	all {
	    set com "[certdb eval {select certDB.certPEM from certDB}]"
#	    certdb eval {select certDB.certPEM from certDB}
	    set title "Выберите каталог для экспорта всех X509"
#	    set initf [file join $dir "ALLCERTS-[clock format [clock seconds] -format {%Y-%m-%d-%H-%M}].pem"]
	    set initf "cert"
	    set pubtit "Экспорт всех сертификатов"

	}
	ca {
	    set title "Выберите каталог для корневого сертификата"
#	    set initf [file join $dir "CAFL63cert.pem"]
	    set initf "CAFL63cert.pem"
	    set capem [certdb eval {select mainDB.certCA from mainDB}]
	    set capem [string trimright $capem \}]
	    set capem [string trimleft $capem \{ ]
	    
	    set file [tk_chooseDirectory -title $title  -initialdir $dir  -parent .cm]
	    if {$file == ""} {
        	return
	    }
	    set fileca [file join $file $initf]
	    set fd [open $fileca  w]
	    puts  $fd $capem
	    close $fd
	    tk_messageBox -title $pubtit -icon info -message "Корневой сертификат сохранены в\n$fileca" -parent .cm
	    return
	}
	default {
	    return
	}
    }
#    puts "Export New: $dir"
    set file [tk_chooseDirectory -title $title  -initialdir $dir  -parent .cm]
    if {$file == ""} {
            return
    }
    set countfile 0
    set cancelexport 0
    set i 0
    cagui::ProgressWindow_Create .cm.progress "Экспорт сертификатов" "Масштаб: $pubtit"
    cagui::ProgressWindow_SetStatus .cm.progress "Скопировано $i сертификат(ов)" 0
    update
    raise .cm.progress
#################
    set i 0
#    foreach rev [certdb eval {select certDB.certPEM from certDB}] {}
    foreach rev $com {
	if {$type == "news" || $type == "revs"} {
	    set ckaid $rev
	    set rev [certdb eval {select certDB.certPEM from certDB where certDB.ckaID = $rev}]
	    set ss [string trimleft $rev \{]
	    set rev [string trimright $ss \}]
	} 
	set fd [open [file join $file $initf$i.pem] w]
	puts  $fd $rev
	close $fd
	if {$type == "news"} {
#	    certdb eval {begin transaction}
#		certdb eval {delete from certDBNew where ckaID=$ckaid}
#	    certdb eval {end transaction}
	}
	incr i
	if {$cancelexport == 1 } {
	    tk_messageBox -title $pubtit -icon info -message "Экспорт прерван.\n
Было экспортировано $i сертификатов.\n
Сертификаты сохранены в\n$file" -parent .cm
	    break
	}
	cagui::ProgressWindow_SetStatus .cm.progress "Скопировано $i сертификат(ов)"  $countfile
	update
	incr countfile
    }

#########################
    if {$cancelexport == 0 } {
	tk_messageBox -title $pubtit -icon info -message "Сертификаты сохранены в каталоге \n$file." -parent .cm
    }
    catch "destroy .cm.progress"
}

proc cmd::ViewCertificateInfo {} {
    global typesys
    global env
    debug::msg "cmd::ViewCertificateInfo"
    
    set crt_fn [cagui::FileDialog -dialogtype open \
            -defaultextension [Config::Get filetype.cert_default_ext] \
            -filetypes [Config::Get filetype.certificate] \
            -initialdir $env(HOME) \
            -initialfile [::Config::Get folder.certificates] \
            -title "Укажите имя файла с сертификатом" ]

#MS Windows возвращает не пустышку, а after#
    if {$typesys == "win32" } {
      if { "after#" == [string range $crt_fn 0 5] } {
        set crt_fn ""
      }
    }

    if {$crt_fn == ""} {
	return
    }
    set crttextme "Сделать"

    set crtdetails [openssl::Certificate_GetInfo -filename $crt_fn -get details]
    if {$crtdetails  == ""} {
      tk_messageBox -title "Просмотр сертификата" -icon error -message "Файл:\n$crt_fn" -detail "Выбранный файл не содержит сертификата" -parent .cm
      return
    }
    set crttext [openssl::Certificate_GetInfo -filename $crt_fn -get text]
    set crtextensions [openssl::Certificate_GetInfo -filename $crt_fn -get extensions]
    set publickey [openssl::Certificate_GetInfo -filename $crt_fn -get publickey]
    set allfields [concat $crtdetails $crtextensions $publickey]
    #set allfields [concat $crtdetails $crtextensions]
    set crtstatus [openssl::Certificate_IsValid -filename $crt_fn]
#Читаем
    set file $crt_fn
#cert_hex
    set fd [open $file]
    chan configure $fd -translation binary
    set data [read $fd]
    close $fd
    set asndata [cert2der $data]
    if {$asndata == "" } {
      tk_messageBox -title "Просмотр сертификата" -icon error -message "Файл:\n$file" -detail "Выбранный файл не содержит сертификата" -parent .cm
      return
    }
    binary scan $asndata H* certhex
#tk_messageBox -title "Просмотр сертификата" -icon info -message "Файл hex:\n$file" -detail "$certhex" -parent .cm

#    set attr(exit) [Dialog_ShowCertificateInfo .popup {Certificate} $allfields $crttext $crtstatus]
    set attr(exit) [Dialog_ShowCertificateInfo .popup {Certificate} $allfields $crttext $certhex $crtstatus]
}

proc page0com0 {} {
    cmd::ViewRequestInfo
}

proc page0com1 {} {
    cmd::ImportRequest
}
proc page0com3 {} {
    set w ".cm.mainfr.ff.notbok.p0.left.listbox"
    viewDouble $w "req"
}

proc page1com0 {} {
    cmd::ViewRequestInfo
}
proc page1com1 {} {
    set w ".cm.mainfr.ff.notbok.p1.left.listbox"
    viewDouble $w "req"
}

proc cmd::ImportRequest {} {
    global env
    debug::msg "cmd::ImportRequest"
    
    set crt_fn [cagui::FileDialog -dialogtype open \
            -defaultextension [Config::Get filetype.request] \
            -filetypes [Config::Get filetype.request] \
            -initialdir $env(HOME) \
            -initialfile [::Config::Get folder.requests] \
            -title "Выберите файл для импорта запроса" ]

    if {$crt_fn != ""} {
        set crtdetails [openssl::Request_GetInfo -filename $crt_fn -get details]
        if {$crtdetails == ""} {return}
        set crttext [openssl::Request_GetInfo -filename $crt_fn -get text]
        set crtextensions [openssl::Request_GetInfo -filename $crt_fn -get extensions]
        set publickey [openssl::Request_GetInfo -filename $crt_fn -get publickey]
        set allfields [concat $crtdetails $crtextensions $publickey]
        #set allfields [concat $crtdetails $crtextensions]
#        set crtstatus [openssl::Certificate_IsValid -filename $crt_fn]
        set attr(exit) [Dialog_ShowRequestInfo .popup {Импорт запроса на сертификат} $allfields $crttext 1 $crt_fn]
    }
}

proc cmd::ViewRequestInfo {} {
    global env
    debug::msg "cmd::ViewRequestInfo"
    
    set crt_fn [cagui::FileDialog -dialogtype open \
            -defaultextension [Config::Get filetype.request] \
            -filetypes [Config::Get filetype.request] \
            -initialdir $env(HOME) \
            -initialfile [::Config::Get folder.requests] \
            -title "Уважите файл с запросом на сертификат" ]

    if {$crt_fn != ""} {
        set crtdetails [openssl::Request_GetInfo -filename $crt_fn -get details]
        set crttext [openssl::Request_GetInfo -filename $crt_fn -get text]
        set crtextensions [openssl::Request_GetInfo -filename $crt_fn -get extensions]
        set publickey [openssl::Request_GetInfo -filename $crt_fn -get publickey]
        set allfields [concat $crtdetails $crtextensions $publickey]
        #set allfields [concat $crtdetails $crtextensions]
#        set crtstatus [openssl::Certificate_IsValid -filename $crt_fn]
        set attr(exit) [Dialog_ShowRequestInfo .popup {Просмотр запроса} $allfields $crttext 2 ""]
    }
}

proc cmd::ViewByIndexReq {reqs} {
    global env
    debug::msg "cmd::ViewByIndexReq"

    # if >10 certs : limit to 10 certs
    if {[llength $reqs]} {
        set reqs [lrange $reqs 0 9]
    }
    foreach req $reqs {
        set crtdetails [openssl::Request_GetInfo -serial $req -get details]
        set crttext [openssl::Request_GetInfo -serial $req -get text]
        set crtextensions [openssl::Request_GetInfo -serial $req -get extensions]
        set publickey [openssl::Request_GetInfo -serial $req -get publickey]
        set allfields [concat $crtdetails $crtextensions $publickey]
#0 просмотр запроса из БД, не 0 - просмотр импортируемого запроса
        set attr(exit) [Dialog_ShowRequestInfo .popup$req {Просмотр запроса} $allfields $crttext 0 $req]
    }
}

proc cmd::ViewCRLInfo {} {
    global env
    debug::msg "cmd::ViewCRLInfo"
    
    set crl_fn [cagui::FileDialog -dialogtype open \
            -defaultextension [Config::Get filetype.crl] \
            -filetypes [Config::Get filetype.crl] \
            -initialdir $env(HOME) \
            -initialfile [::Config::Get folder.requests] \
            -title "Уважите файл с СОС/CRL " ]

    if {$crl_fn != ""} {
        set crldetails [openssl::CRL_GetInfo -filename $crl_fn -get details]
        set crltext [openssl::CRL_GetInfo -filename $crl_fn -get text]
	set crlissuer [openssl::CRL_GetInfo -filename $crl_fn -get issuer]
        set allfields [concat $crldetails $crlissuer]
#0 просмотр запроса из БД, не 0 - просмотр импортируемого запроса
        set attr(exit) [Dialog_ShowCRLInfo .popup {Просмотр CRL/СОС} $allfields $crltext $crl_fn]
    }
}

proc cmd::ViewByIndexCRL {reqs} {
    global env
    debug::msg "cmd::ViewByIndexReq"

    # if >10 certs : limit to 10 certs
    if {[llength $reqs]} {
        set reqs [lrange $reqs 0 9]
    }
    foreach req $reqs {
        set crldetails [openssl::CRL_GetInfo -serial $req -get details]
        set crltext [openssl::CRL_GetInfo -serial $req -get text]
	set crlissuer [openssl::CRL_GetInfo -serial $req -get issuer]
        set allfields [concat $crldetails $crlissuer]
#0 просмотр запроса из БД, не 0 - просмотр импортируемого запроса
        set attr(exit) [Dialog_ShowCRLInfo .popup$req {Просмотр CRL/СОС} $allfields $crltext $req]
    }
}

proc cmd::SetupProfiles {profilename} {
    debug::msg "cmd::SetupProfiles $profilename"
    ProfileDialog::Create .cm.setupprofiles $profilename
}

proc cmd::Options {} {
    
    debug::msg "cmd::Options"
    OptionsDialog::Create .cm.options
    
}

proc cmd::Help {} {
    tk_messageBox -title "Help" -icon info -type ok -message "Help is not yet implemented" -parent .cm
}

proc cmd::HelpReadme {} {
    eval exec [auto_execok start] [list "readme.html"] &
}

proc cmd::ShowHelp {url} {
    eval exec [auto_execok start] [list "$url"] &
}

proc cmd::ExitDB {} {
    global lirssl_static
    global certdb
    global keydb
    catch {certdb close}
    if {[file exists $lirssl_static]} {
	file delete -force  $lirssl_static
    }
#    catch {keydb close}
    exit 0
}


if {[lindex $argv 0] == "-debug"} {
    set debug::level 1
}

Log::CreateWindow .log
Log::ToWindow .log
#Log::ToFile "ca.log"
Log::ToFile $::calog
interp alias {} log {} ::Log::LogMessage
wm protocol . WM_DELETE_WINDOW "Log::Cleanup; destroy ."

debug::msg "startup : $argv0 $argv"

if {[lindex $argv 0] == "-debug"} {
    set config(debug) 1
    set debug::level 1
}

# for debugging - leave this.
set config(debug) 1
set debug::level 1
#puts "System=$typesys"
# set up main screen
#wm withdraw .

ObjectManager .cm
#waitevent
label .cm.helpview -text "Точка доступа к OCSP и сертификату" -anchor w -justify left -bg #ffe0a6
