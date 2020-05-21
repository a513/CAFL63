# breeze.tcl --
#
# Breeze pixmap theme for the ttk package.
#
#  Copyright (c) 2018 Maximilian Lika

package require Tk 8.6.0

namespace eval ttk::theme::Breeze {
#LISSI
variable I
array set I []

set I(checkbox-unchecked) [image create photo  -data {
R0lGODlhEAAQAPMAAHV3eImLjImMjYuNjoyMjo2Oj42PkLS1tb2/v8LExNbX1+jp
6evs7O3u7vP09AAAACH5BAAAAAAALAAAAAAQABAAAAQysBlAq6WEmbOc/6CDCEAX
ng6Fouoatu4HxylAy/Zd67s+xz9XcAUYIG6JAiNwaQIMiggAOw==
}]

set I(entry-focus) [image create photo  -data {
R0lGODlhFAAUAPMAAD2u6U216k+06k616lC16pDN7JHN7JDM7ZrU8pvU8p3V8uru
8O/w8fn7+/z8/AAAACH5BAAAAAAALAAAAAAUABQAAARPkMlJq11ngM37FsYiGUrj
nGh6NokhDaYqr4EEzLgD2Pm8M7ee6hcUoojGFDJ5WjKdSahRKqT2rLmfIGZsEEYJ
bq6BKEgWBoFnDQCJLHB4BAA7
}]

set I(scrollbar-slider-insens) [image create photo  -data {
R0lGODlhFAAeAPAAAAAAAAAAACH5BAEAAAAALAAAAAAUAB4AAAIXhI+py+0Po5y0
2ouz3rz7D4biSJZmUgAAOw==
}]

set I(notebook-tab-top) [image create photo  -data {
R0lGODlhDAAWAPEBALCys8vMztfZ2wAAACH5BAEAAAMALAAAAAAMABYAAAIfjI8x
mQKcHjxyhjox1IxHa3iISIGXSYboCqZny1pAAQA7
}]

set I(notebook-tab-top-active) [image create photo  -data {
R0lGODlhDAAWAPEAAMvMztfZ2+/w8QAAACH5BAEAAAMALAAAAAAMABYAAAImHI5p
Ie0dzptCUmdvBbrl+1HhND4lxnWnl2rr1sFqC9KiTeKmjhUAOw==
}]

set I(labelframe) [image create photo  -data {
R0lGODlhDwATAPAAAMDCxO/w8SH5BAAAAAAALAAAAAAPABMAAAIihI8Jwe1tnmRx
vmrhypp3H2CcmJGWOaGSem0e68Dfq9RGAQA7
}]

set I(radio-checked) [image create photo  -data {
R0lGODlhEgASAPUAAD2u6T6v6UOv6kCw6UKw6UOw6UOx6UOw6kSw6USw6kSx6kWx
6lW361W461m57Fu57Fm67G7C7m/C7nPE73TE74TK8I7O8Y/P8bXd9bXe9bfe9bjf
9bnf9bzh9tDo+NDo+dbq+fD0+/P2/PX3/Pb3/AAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAACH5BAEAACUALAAAAAASABIAAAagwJJwSCwah4QBADAgHIeC
QKUDAnUqAcFx4fiQSCLR9wNZFAWOECkTYTAiGFIIciAGvJbCclm4kD4BSBUkGgl7
ewocJBUGQgMdJBOHhxQkHQNCACAjD5N7DyMgAJmbnZ4AoKKOkJKnlZdCBIMbhpOJ
i41CdyQXCIcIfh6BUGkkGBINDRJxIQ51RAsQXmBifw5mRgdSVFZYz08GSky5T+VF
QQA7
}]

set I(slider-vert-insens) [image create photo  -data {
R0lGODlhDQAcAPIAAOrq7Ovr7Orr7evr7QAAAAAAAAAAAAAAACH5BAEAAAQALAAA
AAANABwAAAMySLrc/msIEaCcAjyMNxceF3bOB5bfOKlnY7IwKsqkm9Ir3jKvHtuz
RoCjeQwzkKRykQAAOw==
}]

set I(arrow-left-prelight) [image create photo  -data {
R0lGODlhDAAMAPAAAD2u6QAAACH5BAEAAAEALAAAAAAMAAwAAAIRjI+JoNvHXoiP
VgmxsVdzXQAAOw==
}]

set I(button-active) [image create photo  -data {
R0lGODlhEgASAPIAAIS3z5bD2JDK5JTQ6wAAAAAAAAAAAAAAACH5BAEAAAQALAAA
AAASABIAAAMtSAHc7kGJQau1Yt19Gf+DB27iaJUmhaar2Y4vGH8zV5NAeua6Gky6
jOJBbEQSADs=
}]

set I(arrow-left) [image create photo  -data {
R0lGODlhDAAMAPAAADE2OwAAACH5BAEAAAEALAAAAAAMAAwAAAIRjI+JoNvHXoiP
VgmxsVdzXQAAOw==
}]

set I(radio-unchecked-active) [image create photo  -data {
R0lGODlhEgASAPQAAJnR65nS65vT65nS7JrS7KTW66TW7aXW7abW7bPb7bTb7LPc
7bTc7dXn79bn79/r7+Hq8O/w8QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAACH5BAEAABIALAAAAAASABIAAAVboCSOZGmOwGAYA3CiyRPN
0ZO4JuDQfNTgo8Cux3MQSAwikTEiQJQ9yEAkgBIFooO1h8hueV1J9TvDSpxkSGCU
/DKbQ6ixBGhAfyeAQkZ7LIAnAQMFBQNrL4gmIQA7
}]

set I(empty) [image create photo  -data {
R0lGODlhCwALAPAAAAAAAAAAACH5BAEAAAAALAAAAAALAAsAAAIKhI+py+0Po5yg
AAA7
}]

set I(scale-trough-horizontal) [image create photo  -data {
R0lGODlhFAAUAPIAAL/BxcDCw8DBxMDCxMHDxAAAAAAAAAAAACH5BAEAAAUALAAA
AAAUABQAAAMkWLrc/jDKSau9uIXBu/8DUABg+ZFmqq4Cun7E+HpiZt94ru8JADs=
}]

set I(button-empty) [image create photo  -data {
R0lGODlhEgASAPAAAO/w8QAAACH5BAAAAAAALAAAAAASABIAAAIPhI+py+0Po5y0
2ouz3pwXADs=
}]

set I(arrow-down-small-insens) [image create photo  -data {
R0lGODlhCAAIAPAAAAAAAAAAACH5BAEAAAAALAAAAAAIAAgAAAIHhI+py+1dAAA7
}]

set I(arrow-right) [image create photo  -data {
R0lGODlhDAAMAPAAADE2OwAAACH5BAEAAAEALAAAAAAMAAwAAAISjI8ZoMqNHjRy
1nZTjnP13RkFADs=
}]

set I(arrow-right-insens) [image create photo  -data {
R0lGODlhDAAMAPAAAAAAAAAAACH5BAEAAAAALAAAAAAMAAwAAAIKhI+py+0Po5yU
FQA7
}]

set I(scale-slider) [image create photo  -data {
R0lGODlhEgASAPQAAIWGiIWIiYaIiIeJiY+RkpCRkpCSkpGSk5GTk5+gorKytLKz
tLS1t7W2t8LExMfIydrb29rc3Nvc3ezt7u3u7+/w8QAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAACH5BAEAABYALAAAAAASABIAAAVZoCWOZGmKQrE4zlIMp3hE
VW1Hx5lMdl9NiRKC4vNREKOApFiUAGRMpkHEiBYboofV98hue11L9VvDWg7k2tSi
JDtHw+2xtIsCTwdIEZKLCQgKLAoEMDGGJSEAOw==
}]

set I(radio-unchecked-pressed) [image create photo  -data {
R0lGODlhEgASAPQAAJfR65jR65jS65nS65jR7JnR7JjS7JnS7JnT7JrS7KPW7KTV
7KTW7Lrd7rre7rve7rre78fi78fj793q8N7r8OPs8OTs8Ovv8ezu8e/w8fDw8fHx
8fPy8ffz8QAAAAAAACH5BAEAAB4ALAAAAAASABIAAAV2oCeOZGme6BkMxhCkYsBI
UzVJioEmDcZtmg0H00iYCI+OJsNkajoOQmlxWTabmsuCVIhwrmBOBDESUKxgJ0Un
MljQaY2F7THDwZr1qPtNM8VkI1R3TlolBA5KeFBSJTw+QEIYEEYnAAo0NjgAMHUH
BgcCnaMeIQA7
}]

set I(treeview) [image create photo  -data {
R0lGODlhHgAeAPABAN3j6f///yH5BAAAAAAALAAAAAAeAB4AAAJChI+pe+EPo5xm
2gsr3lLzH3jgJo5XaVJASq7s6b6qbKF0GN+PTfOy/wKyhCmiyThCgpQfJsfZ0kWg
GCpMmmFot4cCADs=
}]

set I(arrow-up-prelight) [image create photo  -data {
R0lGODlhDAAMAPAAAD2u6QAAACH5BAEAAAEALAAAAAAMAAwAAAISjI+pywnQYJAO
UXPxybv5Dy4FADs=
}]

set I(checkbox-unchecked-active) [image create photo  -data {
R0lGODlhEAAQAPMAAJPO6aLQ5qPS6aTU6aXU6aXU6qXV6r/V4NbZ28jg6cng6c/k
7+jp6ezv8e3y8vP09CH5BAAAAAAALAAAAAAQABAAAAQx0BlAq6WilcOe/+CTBEAX
ng+Fouoatu4HxylAy/Zd67s+xz9XcAUQKG6LQYN0aRIQEQA7
}]

set I(scale-slider-pressed) [image create photo  -data {
R0lGODlhEgASAPQAAFe36le46Va462e+6mi+62m+62m+7Gq+7H7G63/H65rP7ZnQ
7Z3R7J/T7bLa77bb7rbb79Pl79Tl8NTm8O3v8e/w8QAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAACH5BAEAABYALAAAAAASABIAAAVXoCWOZGmKwqA4jjIIp1hI
VW1LxJlQdl9RiFKB5+tRCiPApFicBEQHJtMgakiLDNHj6oNouT2vxQquZS3RcoVq
UZadoyH3WNpJgadZMZKLpRYsCy8xhCYhADs=
}]

set I(scale-slider-active) [image create photo  -data {
R0lGODlhEgASAPQAAKHU7KHV7aLU7KrX7anY7arY7avY7bXc7Lbc7cLh7sXg7cTg
7sbi7tDl79Lm79Lm8OHq8OHr8O7v8e/w8QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAACH5BAEAABQALAAAAAASABIAAAVVICWOZGmKAbE0zUIEp2hE
U21Hw4lIdj9Jh1KB5+tJDCMAreiLCEQDJjNHYUiLCpHj6ntouT1vFWzLUqLkCVVJ
do6G3GNpJwWeZkUI9ZRKsBIvMYImIQA7
}]

set I(scale-trough-vertical) [image create photo  -data {
R0lGODlhFAAUAPIAAL/BxcDCw8DBxMDCxMHDxAAAAAAAAAAAACH5BAEAAAUALAAA
AAAUABQAAAMzWLoaM4DJCd6LM1ub9R7d9IEhM5bmhy7nWrQrjMolHdod7m3uq7o6
0UbQq1gIvYIRM0kAADs=
}]

set I(treeheading-prelight) [image create photo  -data {
R0lGODlhHgAeAPAAAJTQ68vMziH5BAAAAAAALAAAAAAeAB4AAAJBDI6py2EMI3Ky
tmczoDrzXn1gJI6XKZVooq5H68KrjNKmPeKg3vGa78G4WMLhq2gEWpQh5JCZcsak
M4f1is1qrQUAOw==
}]

set I(arrow-up-insens) [image create photo  -data {
R0lGODlhDAAMAPAAAAAAAAAAACH5BAEAAAAALAAAAAAMAAwAAAIKhI+py+0Po5yU
FQA7
}]

set I(radio-checked-insensitive) [image create photo  -data {
R0lGODlhEgASAPQAALvLvrzMv7zNv73Nv73MwL3NwMDPw8DOxMHPxMHPxcPQxsbT
ysfTysnUzMnVzMrVzc/Z0tDZ09je29rf3Nrg3d3h4N7i4OXn6Obn6efo6gAAAAAA
AAAAAAAAAAAAAAAAACH5BAEAABoALAAAAAASABIAAAWKoCaOZGmOAqACwjmqj2RZ
0qOeQVJlGYbxFUSgBEhcMpKFAbGQZC4IAAmwgxBWAEIkU5GKBI8MZYBVFSaZx1AD
cDbKKwfSC7BkFHCVImOh2/F5e30ibRlveXISXmBiBXBnaWtsVVcrWlxehAhHEgwH
BwxOUJkiAQg7PT9cQicwMjQ2pCYBWJIutyQhADs=
}]

set I(arrow-down-prelight) [image create photo  -data {
R0lGODlhDAAMAPAAAD2u6QAAACH5BAEAAAEALAAAAAAMAAwAAAISjI+py43AoJEv
0XCPzI+7DxoFADs=
}]

set I(scale-slider-insensitive) [image create photo  -data {
R0lGODlhEgASAPQAAMHOxsHQxcPQxMbRyMXSycbSyMbSycfSycbSyszVz9Ha09Hb
1dLa1dPb19jf29ne3Nnf3OHj4+Dk4+bn6efo6gAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAACH5BAEAABUALAAAAAASABIAAAVZYCWOZGmKQrE4zlIIp2hI
VG1LxJlMdk9NiRKB5+tNECNApFiMBEQHJrMgakiLDNHj6oNouT1vxQquZSvRMoVa
UZadoyH3WNpJgadZERerCAYKLAoDMH2GIyEAOw==
}]

set I(arrow-up-small-prelight) [image create photo  -data {
R0lGODlhCAAIAPAAAD2u6QAAACH5BAEAAAEALAAAAAAIAAgAAAILjI+pCpAeYERy
rQIAOw==
}]

set I(radio-unchecked-insensitive) [image create photo  -data {
R0lGODlhEgASAPQAAL3Nwb7MwL7NwL7Nwb3Owb7Owb3Owr7Owr/OwsTRx8TSyMXS
ycbTyc3Xz83Yz83Y0OHl4uHl4+bq6Ofq6e/w8QAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAACH5BAEAABUALAAAAAASABIAAAVeYCWOZGmOgqEohnCOgCNR
NCU5wClEdU9BLtKA5+tFDqRHsfgYFSZL34QgQkSLCNHi6mNouT1vxQqmZSvP8iQw
UoKbowMxeiwJIFHgCdCY1SQPOS8VAQYJCQZsg4skIQA7
}]

set I(radio-checked-pressed) [image create photo  -data {
R0lGODlhEgASAPUAAI/P6pDO6pDP6pLP65PQ65TQ65fR65fR7ZjS65jS7JnS7JnT
7JjS7ZnS7ZrS7JrT7ZrU7Z3U7aDU7aTX7qXX7rfe8Lfe8brf8rvg8rzg8r3g88vn
9eLv+OLv+ePw+enx+ury+uvy+uvy++zz+vH1+/L1+/T2+/T2/PX2/P36/QAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAACH5BAEAACoALAAAAAASABIAAAafQJVwSCwaj8ijApFAKJLC
A2XjEXk2lAPyoSmZQp+QqZSBGA+aFKcSMUQqnFRGS5yUOhPAgDAQUDwlE0QKGygX
AgWJiQEXKBsPQwoeIxIDiokDEiMeC0MNISAOBJcFBA4gIQyRk5WkmZudQoSGiJeM
jpBDdnh6fH4eJIJEBxlqbG4WcRh0RBAZXmAhJyQYZkdSVFYbE8xIDgsJCw5Q5ENB
ADs=
}]

set I(entry-active) [image create photo  -data {
R0lGODlhFAAUAPIAAJTP67Da7MLf7eru8O/w8fn7+/z8/AAAACH5BAAAAAAALAAA
AAAUABQAAANDSLrcPgHISWkYKohiuv9dIQQKwIFoCJRpa6wE4KawPIP1jbO6l/ed
H1DYI+qMN+RM6aqddAWY5ukSkQiQinZycXi/CQA7
}]

set I(checkbox-unchecked-pressed) [image create photo  -data {
R0lGODlhEAAQAPQAAJ/P5pTO6ZTP6ZXP6ZTP6pXP6p/Q56DR6aLT6aDS6qLT6qPU
6qLV69Xa3MfY4NHk69Lk69fn8PDt7Orv8uvy8/P09PT19ff29Pj29fn29fn39QAA
AAAAAAAAAAAAAAAAACH5BAEAABsALAAAAAAQABAAAAVS4CaOZClSSDCsLBsc06Y4
Enbd+K09xkZIlopwSNQQNgUMcSm8FJAX5tIJlRKphai1+cxuudUvVrsdfytm8ZOg
OWeOCYgmR89EGJsJQNDqBxYNIQA7
}]

set I(checkbox-checked-pressed) [image create photo  -data {
R0lGODlhEAAQAPQAAIXJ54zL6J/P5pPO6ZTO6ZTP6ZXP6ZTP6pXP6p/Q56DR6aLT
6aDS6qLT6qPU6qLV69Xa3MfY4NHk69Lk69fn8PDt7Ofv8+rv8uvy8/Hz9PP19ff2
9Pj29fn29fn39QAAACH5BAEAAB8ALAAAAAAQABAAAAVs4CeOZCliC2GsLEso19dE
Fbfd+O1JyXdUGotwOMx4Dh8ExwIIOJ8BgGWDSG4sgYF2OwhMq4hrlqv1Uq1YcvmL
HpPNYLG6yw6n1fD2PG9vQp1SZwceGUSGGR1IDBMeOY4dFA8fFwIFLZcEDhAhADs=
}]

set I(arrow-down-insens) [image create photo  -data {
R0lGODlhDAAMAPAAAAAAAAAAACH5BAEAAAAALAAAAAAMAAwAAAIKhI+py+0Po5yU
FQA7
}]

set I(scrollbar-trough-horiz-active) [image create photo  -data {
R0lGODlhOAAUAPAAAAAAAAAAACH5BAEAAAAALAAAAAA4ABQAAAIghI+py+0Po5y0
2ouz3rz7D4biSJbmiabqyrbuC8fyWgAAOw==
}]

set I(checkbox-checked) [image create photo  -data {
R0lGODlhEAAQAPMAAD2u6V235l256V656WG66WG76mG86p7J4KjT6a3a79TZ2+jp
6enu8enw8vP09AAAACH5BAAAAAAALAAAAAAQABAAAAQ6sBlAq6WClbOc/6CDBEAX
ng7lXdcKuKyavnNMyzZ+5y4c97XfzMcC5nbE1hB1AgwQTFCCwCAdAQRFBAA7
}]

set I(notebook-tab-top-hover) [image create photo  -data {
R0lGODlhDAAWAPEAAJTP65TQ68Df7gAAACH5BAEAAAMALAAAAAAMABYAAAIfRI45
linBWory0HplbntW/1mhOHaISYYoNLJlu8ZtAQA7
}]

set I(checkbox-checked-active) [image create photo  -data {
R0lGODlhEAAQAPMAAJPO6aLQ5qPS6aTU6aXU6aXU6qXV6r/V4NbZ28jg6cng6c/k
7+jp6ezv8e3y8vP09CH5BAAAAAAALAAAAAAQABAAAAQ60BlAq6WilcOe/+CTBEAX
ng/lXdcKuKyavnNMyzZ+5y4c97XfzMcC5nbE1hB1AggUTNBi0CAdAQREBAA7
}]

set I(arrow-left-insens) [image create photo  -data {
R0lGODlhDAAMAPAAAAAAAAAAACH5BAEAAAAALAAAAAAMAAwAAAIKhI+py+0Po5yU
FQA7
}]

set I(button-focus) [image create photo  -data {
R0lGODlhEgASAPIAADaYyjue0j2u6VGm1QAAAAAAAAAAAAAAACH5BAEAAAQALAAA
AAASABIAAAMuSBPc7kMBQau1YN19Gf+CB27iaJUmhaar2Y4vGH8zV5NBeua6Okw6
QEDxKDYiCQA7
}]

set I(button-hover) [image create photo  -data {
R0lGODlhEgASAPMAAJPO6ZvR6ZrR6pzR6qrQ4ajQ4qvV5rDa7L3d677d68Lf7cDf
7u/w8QAAAAAAAAAAACH5BAEAAA0ALAAAAAASABIAAAQ5sJ0Aqr11HKmY/yC4GEFo
hgJwrkzFnu4bxvJH162Ke3fdy79XkDVcFWGDnSdwSOwQhAYJQwUECo0IADs=
}]

set I(scrollbar-trough-vert-active) [image create photo  -data {
R0lGODlhFAA4APAAAAAAAAAAACH5BAEAAAAALAAAAAAUADgAAAIghI+py+0Po5y0
2ouz3rz7D4biSJbmiabqyrbuC8fyWgAAOw==
}]

set I(button-toggled) [image create photo  -data {
R0lGODlhEgASAPIAAL/BxcDCw8DBxMDCxMHDxAAAAAAAAAAAACH5BAEAAAUALAAA
AAASABIAAAMaWDHc7qCAR9+sOOvNu/9gKI5kaYrC5RGSFyUAOw==
}]

set I(arrow-right-prelight) [image create photo  -data {
R0lGODlhDAAMAPAAAD2u6QAAACH5BAEAAAEALAAAAAAMAAwAAAISjI8ZoMqNHjRy
1nZTjnP13RkFADs=
}]

set I(transparent) [image create photo  -data {
R0lGODlhFAAeAPAAAAAAAAAAACH5BAEAAAAALAAAAAAUAB4AAAIXhI+py+0Po5y0
2ouz3rz7D4biSJZmUgAAOw==
}]

set I(scrollbar-slider-horiz) [image create photo  -data {
R0lGODlhHgAUAPIAAD2t6Tyu6D2u6T6u6QAAAAAAAAAAAAAAACH5BAEAAAQALAAA
AAAeABQAAAMsSLrc/jDKSau9OOvNCRBgKI7kOBBDqa5iyr5wDA+uDAeo/Z5d7//A
oHBoSQAAOw==
}]

set I(arrow-up) [image create photo  -data {
R0lGODlhDAAMAPAAADE2OwAAACH5BAEAAAEALAAAAAAMAAwAAAISjI+pywnQYJAO
UXPxybv5Dy4FADs=
}]

set I(arrow-down) [image create photo  -data {
R0lGODlhDAAMAPAAADE2OwAAACH5BAEAAAEALAAAAAAMAAwAAAISjI+py43AoJEv
0XCPzI+7DxoFADs=
}]

set I(radio-unchecked) [image create photo  -data {
R0lGODlhEgASAPQAAHt9fnx9fnx+f31+f3t+gHx+gHx/gH+BgYqLjIuNjo2PkI6P
kJ+hoZ+hop6iop+ioqCio8zNzs3Oz9rb29zc3e7v8O/w8QAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAACH5BAEAABcALAAAAAASABIAAAVf4CWOZGmOgZEkRnCizVRZ
VjU1rhlIdN9HORTPR5QMSBCi0vIYFShLIoUgOkSJlYNIcSUutl3f92IN17SXp5kC
GCXDzdFgGDWWApEo8CRgyGg2DgIvIgIGCAgGg4SMJCEAOw==
}]

set I(entry) [image create photo  -data {
R0lGODlhFAAUAPMAAMDCxMTGycXGycTHydbX2dbY2d3e397f4O7v8O/w8fv7+/z8
/AAAAAAAAAAAAAAAACH5BAAAAAAALAAAAAAUABQAAARNMMlJq0VkgM37DgQiEYey
nGh6KgYhDaYqr4MEzPgC2Pm8J7ee6hcUoojGFDJ5WjKdSahRKqT2rLlfIGZUCEYG
bo5VkGACnjQAJLK43REAOw==
}]

set I(checkbox-unchecked-insensitive) [image create photo  -data {
R0lGODlhEAAQAPMAALu8vr/AwsDBxMHCxMLCxcPDxcPExsPFxsfIys7P0dHR0tXY
2d3d3+Pk5eXm5+fo6iH5BAAAAAAALAAAAAAQABAAAAQx0BlAq6WiHcSe/+CjBEAX
ng+Fouoatu4HxylAy/Zd67s+xz9XcAUYKG6LQoN0aRISEQA7
}]

set I(scrollbar-slider-horiz-active) [image create photo  -data {
R0lGODlhHgAUAPIAAJPO6JLO6ZPO6ZPP6QAAAAAAAAAAAAAAACH5BAEAAAQALAAA
AAAeABQAAAMrSLrc/jDKSau9OOvNyRBgKI7kGBBBqa5iyr5wHLsyDKD1e3Z87//A
oNCSAAA7
}]

set I(entry-insensitive) [image create photo  -data {
R0lGODlhFAAUAPMAANnZ29ra2tra3Nrb3Nvc3Nvc3ePk5ePk5uTl5u7v8O/w8QAA
AAAAAAAAAAAAAAAAACH5BAEAAAsALAAAAAAUABQAAARIUMlJq02mgM37LkgiIUtp
nmiASAXqooMEvPQCyPV7K3OO7j2fCSg8EYulI1JZZAqdPmhOWtu1kAvCKIAUHCQJ
hMZDBoksaHQEADs=
}]

set I(notebook-client) [image create photo  -data {
R0lGODlhHgAeAPAAAMvMzu/w8SH5BAAAAAAALAAAAAAeAB4AAAJChI+pe+EPo5xm
2gsr3lLzH3jgJo5XaVJASq7s6b6qbKF0GN+PTfOy/wKyhCmiyThCgpQfJsfZ0kWg
GCpMmmFot4cCADs=
}]

set I(arrow-down-small-prelight) [image create photo  -data {
R0lGODlhCAAIAPAAAD2u6QAAACH5BAEAAAEALAAAAAAIAAgAAAIKjI9pgLzfnJoU
FQA7
}]

set I(radio-checked-active) [image create photo  -data {
R0lGODlhEgASAPQAAJbP7JXQ6pTQ65bR65fS65fR7JfS7JjS65jS7JnS7KDV7aHV
7aHV7qXW7q/b8LPb8bbe8cHi88Lj89Xp9dXp9tTq9tfr99jr99/u+ODu+OLv+fH1
+/L1+/X2/Pb3/AAAACH5BAEAAB8ALAAAAAASABIAAAWU4CeOZGmORSAIQXGOgABV
mlZBAnAaTOZ5nc4vozCUAAyOZ+JYLBwTz0ahGwl8EcJqdZB4MgIUxGNJbLeIiwfi
+gQqnsf5/PBUBiKBxtOYbxseGmEfenx+K4CCIm9xhwJ1dyIFYxYIfmlrbYRYWltd
HhiDIgAKG0tNTxRSVCUGCj5AQqBFJzEzNTc5L5IDKwOau8EiIQA7
}]

set I(button) [image create photo  -data {
R0lGODlhEgASAPMAAMDCxMTGyMXGyMTGycXIysjJysnMzs/R0s7R09XX2Nja3Nze
3+/w8QAAAAAAAAAAACH5BAEAAA0ALAAAAAASABIAAAQ6sJ0Aqr01oIYW+2AYKkYg
nuIAoCxTtegLi/IM1ra75h9u+zMgTNgisowxE48hQCR4iUKjhKkCAoRGBAA7
}]

set I(arrow-down-small) [image create photo  -data {
R0lGODlhCAAIAPAAADE2OwAAACH5BAEAAAEALAAAAAAIAAgAAAIKjI9pgLzfnJoU
FQA7
}]

set I(button-insensitive) [image create photo  -data {
R0lGODlhFAAUAPQAAM7O0NjY2t3d3t3d393e39/f4eDg4eHi5OLi5OTl5uXm5+Xm
6Ozt7+3t7+3u7+7u7+7u8O7v8O/v8O7u8e/v8e/v8u7w8O/w8e/w8vDw8fDw8vDx
8gAAAAAAAAAAAAAAACH5BAEAABwALAAAAAAUABQAAAV+ICeOZGlyR6Gu7GogI7JY
W23fNaYEYlFpwKBQOBn0hshhoZdpOp/QzJJTuFiv2OxlWtV6rVyKeEwuU8LmtJgr
abvfcAk7Tm9zI/i8fh+58/94XBCDhIWGEIKHioNTBg0PkJGSkg0EIggJDA6bnJ2b
DAkAIwECLaYFAqInqyYhADs=
}]

set I(arrow-up-small-insens) [image create photo  -data {
R0lGODlhCAAIAPAAAAAAAAAAACH5BAEAAAAALAAAAAAIAAgAAAIHhI+py+1dAAA7
}]

set I(scrollbar-slider-vert) [image create photo  -data {
R0lGODlhFAAeAPIAAD2t6Tyu6D2u6T6u6QAAAAAAAAAAAAAAACH5BAEAAAQALAAA
AAAUAB4AAANESLoKIoPJOd6LM1ub9Rbd9IEhM5bmhy7nSrQrjMolHdod7m3uq7o6
0S82nBVrx1syt9xxgE0hDzolWjCriiXQI2ixkgQAOw==
}]

set I(scrollbar-slider-vert-active) [image create photo  -data {
R0lGODlhFAAeAPIAAJPO6JLO6ZPO6ZPP6QAAAAAAAAAAAAAAACH5BAEAAAQALAAA
AAAUAB4AAANDSLo6IoHJGd6LM1ub9Rbd9IEhM5bmhy7nSrQrjMolHdod7m3uq7o6
0S82nBVrx1syt9xxgE0hDzolVlEVC6BHyGImCQA7
}]

set I(arrow-up-small) [image create photo  -data {
R0lGODlhCAAIAPAAADE2OwAAACH5BAEAAAEALAAAAAAIAAgAAAILjI+pCpAeYERy
rQIAOw==
}]

set I(checkbox-checked-insensitive) [image create photo  -data {
R0lGODlhEAAQAPMAALu8vr/AwsDBxMHCxMLCxcPDxcPExsPFxsfIys7P0dHR0tXY
2d3d3+Pk5eXm5+fo6iH5BAAAAAAALAAAAAAQABAAAAQ60BlAq6WiHcSe/+CjBEAX
ng/lXdcKuKyavnNMyzZ+5y4c97XfzMcC5nbE1hB1AgwUTNCi0CAdAYREBAA7
}]

    variable version 0.8
    package provide ttk::theme::Breeze $version

    variable colors
    array set colors {
        -fg             "#31363b"
        -bg             "#eff0f1"
        
        #-disabledbg     "#e3e5e6"
        #-disabledfg     "#a8a9aa"
        -disabledfg     "#bbcbbe"
        -disabledbg     "#e7e8ea"
        
        -selectbg       "#3daee9"
        -selectfg       "white"
        
        -window         "#eff0f1"
        -focuscolor     "#3daee9"
        -checklight     "#94d0eb"
    }
if {0} {
    proc LoadImages {imgdir} {
        variable I
        foreach file [glob -directory $imgdir *.png] {
            set img [file tail [file rootname $file]]
            set I($img) [image create photo -file $file -format png]
        }
    }

    LoadImages [file join [file dirname [info script]] Breeze]
}
    ttk::style theme create Breeze -parent default -settings {
        ttk::style configure . \
            -background $colors(-bg) \
            -foreground $colors(-fg) \
            -troughcolor $colors(-bg) \
            -selectbackground $colors(-selectbg) \
            -selectforeground $colors(-selectfg) \
            -fieldbackground $colors(-window) \
            -font "Helvetica 10" \
            -borderwidth 1 \
            -focuscolor $colors(-focuscolor) \
            -highlightcolor $colors(-checklight)

        ttk::style map . -foreground [list disabled $colors(-disabledfg)]

        #
        # Layouts:
        #

        ttk::style layout TButton {
            Button.button -children {
                
                    Button.padding -children {
                        Button.label -side left -expand true
                    }
                
            }
        }

        ttk::style layout Toolbutton {
            Toolbutton.button -children {
                    Toolbutton.padding -children {
                        Toolbutton.label -side left -expand true
                    }
            }
        }

        ttk::style layout Vertical.TScrollbar {
            Vertical.Scrollbar.trough -sticky ns -children {
                Vertical.Scrollbar.thumb -expand true
            }
        }

        ttk::style layout Horizontal.TScrollbar {
            Horizontal.Scrollbar.trough -sticky ew -children {
                Horizontal.Scrollbar.thumb -expand true
            }
        }

        ttk::style layout TMenubutton {
            Menubutton.button -children {
                Menubutton.focus -children {
                    Menubutton.padding -children {
                        Menubutton.indicator -side right
                        Menubutton.label -side right -expand true
                    }
                }
            }
        }
#MY place image to Treeview
if {0} {
        ttk::style layout Item {
            Treeitem.padding -sticky nswe -children {
                Treeitem.indicator -side left -sticky {} Treeitem.image -side left -sticky {} -children {
                    Treeitem.text -side left -sticky {}
                    }
                }
        }
}
        #
        # Elements:
        #

        ttk::style element create Button.button image [list $I(button) \
                pressed     $I(button-focus) \
                {active focus}       $I(button-active) \
                active      $I(button-hover) \
                focus       $I(button-hover) \
                disabled    $I(button-insensitive) \
            ] -border 3 -sticky ewns

        ttk::style element create Toolbutton.button image [list $I(button-empty) \
                {active selected !disabled}  $I(button-active) \
                selected            $I(button-toggled) \
                pressed             $I(button-active) \
                {active !disabled}  $I(button-hover) \
            ] -border 3 -sticky news

        ttk::style element create Checkbutton.indicator image [list $I(checkbox-unchecked) \
                disabled            $I(checkbox-unchecked-insensitive) \
                {pressed selected}  $I(checkbox-checked-pressed) \
                {active selected}   $I(checkbox-checked-active) \
                {pressed !selected} $I(checkbox-unchecked-pressed) \
                active              $I(checkbox-unchecked-active) \
                selected            $I(checkbox-checked) \
                {disabled selected} $I(checkbox-checked-insensitive) \
            ] -width 22 -sticky w

        ttk::style element create Radiobutton.indicator image [list $I(radio-unchecked) \
                disabled            $I(radio-unchecked-insensitive) \
                {pressed selected}  $I(radio-checked-pressed) \
                {active selected}   $I(radio-checked-active) \
                {pressed !selected} $I(radio-unchecked-pressed) \
                active              $I(radio-unchecked-active) \
                selected            $I(radio-checked) \
                {disabled selected} $I(radio-checked-insensitive) \
            ] -width 22 -sticky w

            
        ttk::style element create Horizontal.Scrollbar.trough image $I(scrollbar-trough-horiz-active) \
        -border {6 0 6 0} -sticky ew
        ttk::style element create Horizontal.Scrollbar.thumb \
             image [list $I(scrollbar-slider-horiz) \
                        {active !disabled}  $I(scrollbar-slider-horiz-active) \
                        disabled            $I(scrollbar-slider-insens) \
            ] -border {6 0 6 0} -sticky ew

        ttk::style element create Vertical.Scrollbar.trough image $I(scrollbar-trough-vert-active) \
            -border {0 6 0 6} -sticky ns
        ttk::style element create Vertical.Scrollbar.thumb \
            image [list $I(scrollbar-slider-vert) \
                        {active !disabled}  $I(scrollbar-slider-vert-active) \
                        disabled            $I(scrollbar-slider-insens) \
            ] -border {0 6 0 6} -sticky ns

        
        ttk::style element create Horizontal.Scale.trough \
            image [list $I(scrollbar-slider-horiz) disabled $I(scale-trough-horizontal)] \
            -border {8 5 8 5} -padding 0
        ttk::style element create Horizontal.Scale.slider \
            image [list $I(scale-slider) \
                disabled $I(scale-slider-insensitive) \
                pressed $I(scale-slider-pressed)\
                active $I(scale-slider-active) \
                ] \
            -sticky {}
            
            
        ttk::style element create Vertical.Scale.trough \
            image [list $I(scrollbar-slider-vert) disabled $I(scale-trough-vertical)] \
            -border {8 5 8 5} -padding 0
        ttk::style element create Vertical.Scale.slider \
            image [list $I(scale-slider) \
                disabled $I(scale-slider-insensitive) \
                pressed $I(scale-slider-pressed)\
                active $I(scale-slider-active) \
                ] \
            -sticky {}

        ttk::style element create Entry.field \
            image [list $I(entry) \
                        {focus !disabled} $I(entry-focus) \
                        {hover !disabled} $I(entry-active) \
                        disabled $I(entry-insensitive)] \
            -border 3 -padding {6 8} -sticky news

        ttk::style element create Labelframe.border image $I(labelframe) \
            -border 4 -padding 4 -sticky news

        ttk::style element create Menubutton.button \
            image [list $I(button) \
                        pressed  $I(button-active) \
                        active   $I(button-hover) \
                        disabled $I(button-insensitive) \
            ] -sticky news -border 3 -padding {3 2}
        ttk::style element create Menubutton.indicator \
            image [list $I(arrow-down) \
                        active   $I(arrow-down-prelight) \
                        pressed  $I(arrow-down-prelight) \
                        disabled $I(arrow-down-insens) \
            ] -sticky e -width 20

        ttk::style element create Combobox.field \
            image [list $I(entry) \
                {readonly disabled}  $I(button-insensitive) \
                {readonly pressed}   $I(button-hover) \
                {readonly focus hover}     $I(button-active) \
                {readonly focus}     $I(button-focus) \
                {readonly hover}     $I(button-hover) \
                readonly             $I(button) \
                {disabled} $I(entry-insensitive) \
                {focus}    $I(entry-focus) \
                {focus hover}    $I(entry-focus) \
                {hover}    $I(entry-active) \
            ] -border 4 -padding {6 8}
        ttk::style element create Combobox.downarrow \
            image [list $I(arrow-down) \
                        active    $I(arrow-down-prelight) \
                        pressed   $I(arrow-down-prelight) \
                        disabled  $I(arrow-down-insens) \
          ]  -border 4 -sticky {}

        ttk::style element create Spinbox.field \
            image [list $I(entry) focus $I(entry-focus) disabled $I(entry-insensitive) hover $I(entry-active)] \
            -border 4 -padding {6 8} -sticky news
        ttk::style element create Spinbox.uparrow \
            image [list $I(arrow-up-small) \
                        active    $I(arrow-up-small-prelight) \
                        pressed   $I(arrow-up-small-prelight) \
                        disabled  $I(arrow-up-small-insens) \
            ] -border 4 -sticky {}
        ttk::style element create Spinbox.downarrow \
            image [list $I(arrow-down-small) \
                        active    $I(arrow-down-small-prelight) \
                        pressed   $I(arrow-down-small-prelight) \
                        disabled  $I(arrow-down-small-insens) \
          ] -border 4 -sticky {}

       ttk::style element create Notebook.client \
            image $I(notebook-client) -border 1
        ttk::style element create Notebook.tab \
            image [list $I(notebook-tab-top) \
                        selected    $I(notebook-tab-top-active) \
                        active      $I(notebook-tab-top-hover) \
            ] -padding {12 4 12 4} -border 2

            
        # TODO Enhance
        ttk::style element create Horizontal.Progressbar.trough \
            image $I(scrollbar-trough-horiz-active) -border {6 0 6 0} -sticky ew
        ttk::style element create Horizontal.Progressbar.pbar \
            image $I(scrollbar-slider-horiz) -border {6 0 6 0} -sticky ew

        ttk::style element create Vertical.Progressbar.trough \
            image $I(scrollbar-trough-vert-active) -border {0 6 0 6} -sticky ns
        ttk::style element create Vertical.Progressbar.pbar \
            image $I(scrollbar-slider-vert) -border {0 6 0 6} -sticky ns

        # TODO: Ab hier noch teilweise Arc style
        ttk::style element create Treeview.field \
            image $I(treeview) -border 1
        ttk::style element create Treeheading.cell \
            image [list $I(notebook-client) \
                active $I(treeheading-prelight)] \
            -border 1 -padding 4 -sticky ewns
        
        # TODO: arrow-* ist at the moment a little bit too big 
        # the small version is too small :-)
        # And at the moment there are no lines as in the Breeze theme
        # And hover, pressed doesn't work
        ttk::style element create Treeitem.indicator \
            image [list $I(arrow-right) \
                user2 $I(empty) \
                user1 $I(arrow-down) \
                ] \
            -width 15 -sticky w
            
        # I don't know why Only with this I get a thin enough sash
        ttk::style element create vsash image $I(transparent) -sticky e -padding 1 -width 1
	    ttk::style element create hsash image $I(transparent) -sticky n -padding 1 -width 1

        #ttk::style element create Separator.separator image $I()

        #
        # Settings:
        #

        ttk::style configure TButton -padding {8 4 8 4} -width -10 -anchor center
        ttk::style configure TMenubutton -padding {8 4 4 4}
        ttk::style configure Toolbutton -padding {6 2} -anchor center
        ttk::style configure TCheckbutton -padding 4
        ttk::style configure TRadiobutton -padding 4
        ttk::style configure TSeparator -background $colors(-bg)

        #ttk::style configure TPanedwindow -width 1 -padding 0
        ttk::style map TPanedwindow -background [list hover $colors(-checklight)]
        ttk::style map TCombobox -selectbackground [list \
            !focus         $colors(-window) \
            {readonly hover} $colors(-checklight) \
            {readonly focus} $colors(-focuscolor) \
            ]
            
        ttk::style map TCombobox -selectforeground [list \
            !focus $colors(-fg) \
            {readonly hover} $colors(-fg) \
            {readonly focus} $colors(-selectfg) \
            ]
        
        # Treeview
        ttk::style configure Treeview -background white
        ttk::style configure Treeview.Item -padding {2 0 0 0}
        ttk::style map Treeview \
            -background [list selected $colors(-selectbg)] \
            -foreground [list selected $colors(-selectfg)]
        
        # Some defaults for non ttk-widgets so that they fit
        # to the Breeze theme, too
        tk_setPalette background [ttk::style lookup . -background] \
        	foreground [ttk::style lookup . -foreground] \
        	highlightColor [ttk::style lookup . -focuscolor] \
        	selectBackground [ttk::style lookup . -selectbackground] \
        	selectForeground [ttk::style lookup . -selectforeground] \
        	activeBackground [ttk::style lookup . -selectbackground] \
        	activeForeground [ttk::style lookup . -selectforeground]
        option add *font [ttk::style lookup . -font]
    }
}
