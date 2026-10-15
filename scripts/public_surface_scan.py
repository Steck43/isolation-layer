"""Public-surface scan (standard library only).

Fails when a tracked file, its path, or anything a reader could decode from
it carries a private term, a personal home path, a private network address,
a personal email, a user@host identifier, or the box host name.

Private terms are never stored in this repository. CI passes them in the
LEAK_DENYLIST secret; a local run reads --denylist (default
.git/info/leak-denylist). One entry per line: plain text matches as a
case-insensitive substring after normalisation, and an entry starting with
"re:" is a regular expression. The list must hold exactly EXPECTED_ENTRIES
(or --expect-entries, for tests) entries plus the canary, and the canary must be found in every planted form
before the real scan runs, so an empty, truncated, or never-matching list
fails.

Output never contains a private term: a hit names the rule and the entry
index, and a path that itself carries a term is printed as its index in the
tracked file list.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import hashlib
import html
import itertools
import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote

CANARY = "zqxwvk"
# How many private entries the list must hold. CI runs the base branch copy
# of this file, so the count is set by the base, not by the change under review.
EXPECTED_ENTRIES = 36
MIN_PLAIN = 3
MIN_COMPACT = 6
MAX_DEPTH = 2

# sha256 of the casefolded box host name token. The name itself is not
# written here.
BUILTIN_HOST_TOKENS = frozenset(
    {"1fbdb4006b386690234710ff0f85c9c665835b2f42a2eb4e68ba9a04713a3606"}
)
# Letter count of each host token, so the name is also found glued inside a
# longer identifier (camel case, a digit suffix, a lower-case prefix).
BUILTIN_HOST_LENGTHS = frozenset({8})
MAX_COMPOUND = 128

# sha256 of casefolded identifiers that are public interfaces defined by
# sibling projects (an environment variable name read by the atoms engine).
# Only that exact whole identifier is set aside before the separator-free
# match; every other form of a private entry still hits.
ALLOWED_IDENTIFIERS = frozenset(
    {"cfaf606a8669f70fe0f15b9b40fe8f351822867d3c6ac8a7285b7cd2adc81040"}
)
_IDENT = re.compile(r"[A-Za-z0-9_]+")

# Look-alike letters, folded before matching. _UTS39_PACK is derived from
# Unicode's confusables.txt (UTS #39) 18.0.0, dated 2026-08-06, (c) Unicode,
# Inc., under the Unicode License v3 (https://www.unicode.org/license.txt):
# every non-ASCII code point whose skeleton is one ASCII letter or digit, as
# HEX:LETTER pairs. Rebuild it with scripts/gen_confusables.py. The scanner and
# the voice lint each carry this same block (a test keeps the copies equal),
# because CI copies each of them out of the base branch as a single file.
_UTS39_PACK = (
    "A1:i D7:x FE:p 131:i 17F:f 184:b 18D:g 192:f 196:l 1A6:R 1A7:2 1B7:3 1BC:5 "
    "1BD:s 1BF:p 1C0:l 21C:3 222:8 223:8 237:j 24C:R 251:a 261:g 263:y 269:i "
    "26A:i 26F:w 284:f 28B:u 28F:y 37F:J 391:A 392:B 395:E 396:Z 397:H 399:l "
    "39A:K 39C:M 39D:N 39F:O 3A1:P 3A4:T 3A5:Y 3A7:X 3B1:a 3B3:y 3B9:i 3BD:v "
    "3BF:o 3C1:p 3C3:o 3C5:u 3D2:Y 3DC:F 3E8:2 3EC:6 3ED:o 3F1:p 3F2:c 3F3:j "
    "3F8:p 3F9:C 3FA:M 405:S 406:l 408:J 410:A 412:B 415:E 417:3 41A:K 41C:M "
    "41D:H 41E:O 420:P 421:C 422:T 423:Y 425:X 42C:b 430:a 431:6 433:r 435:e "
    "43E:o 440:p 441:c 443:y 445:x 448:w 455:s 456:i 458:j 461:w 474:V 475:v "
    "4AE:Y 4AF:y 4BA:h 4BB:h 4BD:e 4C0:l 4CF:l 4E0:3 501:d 50C:G 51A:Q 51B:q "
    "51C:W 51D:w 545:3 54D:U 54F:S 555:O 561:w 563:q 566:q 570:h 575:j 578:n "
    "57C:n 57D:u 581:g 582:i 584:f 585:o 5C0:l 5D5:l 5D8:v 5DF:l 5E1:o 627:l "
    "647:o 661:l 665:o 667:V 6BE:o 6C1:o 6D5:o 6F1:l 6F5:o 6F7:V 7C0:O 7CA:l "
    "7CB:o 7CC:Y 7D3:F 7D5:b 7E0:T 840:o 964:l 966:o 969:3 9E6:o 9EA:8 9ED:9 "
    "A66:o A67:9 A6A:8 AE6:o AE9:3 B03:8 B20:O B66:o B68:9 BE6:o C02:o C66:o "
    "C82:o CE6:O D02:o D1F:s D20:o D66:o D6D:9 D82:o E50:o ED0:o 1004:c 101D:o "
    "1040:o 104A:l 105A:c 10B9:h 10BD:S 10C7:2 10CD:Z 10E7:y 10FD:S 10FF:o 110B:o "
    "11BC:o 1200:U 12D0:O 13A0:D 13A1:R 13A2:T 13A5:i 13A9:Y 13AA:A 13AB:J 13AC:E "
    "13B3:W 13B7:M 13BB:H 13BD:Y 13C0:G 13C2:h 13C3:Z 13CE:4 13CF:b 13D2:R 13D4:W "
    "13D5:S 13D9:V 13DA:S 13DE:L 13DF:C 13E2:P 13E6:K 13E7:d 13EE:6 13F3:G 13F4:B "
    "142F:V 144C:U 146D:P 146F:d 1472:b 148D:J 14AA:L 14BF:2 1541:x 157C:H 157D:x "
    "1587:R 15AF:b 15B4:F 15C5:A 15DE:D 15EA:D 15F0:M 15F7:B 1616:2 166D:X 166E:x "
    "16B7:X 16C1:l 16D0:l 16D5:K 16D6:M 1702:3 172A:7 1763:x 17E0:o 1A45:o 1A80:o "
    "1A90:o 1BEA:o 1BEC:x 1C82:o 1C83:c 1C84:7 1C95:3 1CB7:2 1CBD:S 1CBF:O 1CF5:X "
    "1D04:c 1D0F:o 1D11:o 1D1C:u 1D20:v 1D21:w 1D22:z 1D26:r 1D83:g 1D8C:y 1E9D:f "
    "1EFF:y 2102:C 210A:g 210B:H 210C:H 210D:H 210E:h 2110:l 2111:l 2112:L 2113:l "
    "2115:N 2119:P 211A:Q 211B:R 211C:R 211D:R 2124:Z 2128:Z 212C:B 212D:C 212E:e "
    "212F:e 2130:E 2131:F 2133:M 2134:o 2139:i 213D:y 2145:D 2146:d 2147:e 2148:i "
    "2149:j 2160:l 2164:V 2169:X 216C:L 216D:C 216E:D 216F:M 2170:i 2174:v 2179:x "
    "217C:l 217D:c 217E:d 21BF:l 2223:l 2228:v 222A:U 22A4:T 22C1:v 22C3:U 22FF:E "
    "2373:i 2374:p 237A:a 23FD:l 2502:l 2503:l 2573:X 27D9:T 292B:x 292C:x 29E2:w "
    "2A2F:x 2C6B:Z 2C6C:z 2C82:B 2C85:r 2C8C:Z 2C8D:z 2C8E:H 2C92:l 2C93:i 2C94:K "
    "2C98:M 2C9A:N 2C9C:3 2C9E:O 2C9F:o 2CA2:P 2CA3:p 2CA4:C 2CA5:c 2CA6:T 2CA8:Y "
    "2CA9:y 2CAC:X 2CBD:w 2CC4:3 2CCA:9 2CCB:9 2CCC:3 2CCE:P 2CCF:p 2CD0:L 2CD2:6 "
    "2CD3:6 2CDC:6 2D2D:z 2D38:V 2D39:E 2D4A:l 2D4F:l 2D54:O 2D55:Q 2D5D:X 3007:O "
    "3112:T 311A:Y 3147:o 4E05:T 4E2B:Y A4D0:B A4D1:P A4D2:d A4D3:D A4D4:T A4D6:G "
    "A4D7:K A4D9:J A4DA:C A4DC:Z A4DD:F A4DF:M A4E0:N A4E1:L A4E2:S A4E3:R A4E6:V "
    "A4E7:H A4EA:W A4EB:X A4EC:Y A4EE:A A4F0:E A4F2:l A4F3:O A4F4:U A50B:T A543:6 "
    "A557:B A56F:l A576:S A589:8 A5CB:E A644:2 A647:i A6C9:Z A6DF:V A6EF:2 A731:s "
    "A75A:2 A76A:3 A76E:9 A76F:9 A781:l A798:F A799:f A79F:u A7AB:3 A7AE:l A7B2:J "
    "A7B3:X A7B4:B A7FA:w A7FE:l A830:l A8CE:l AA5D:l AB32:e AB35:f AB3D:o AB47:r "
    "AB48:r AB4E:u AB52:u AB5A:y AB64:a AB75:i AB81:r AB83:w AB93:z AB9E:4 ABA4:w "
    "ABA9:v ABAA:s ABAF:c ABBE:6 FBA6:o FBA7:o FBA8:o FBA9:o FBAA:o FBAB:o FBAC:o "
    "FBAD:o FE31:l FE8D:l FE8E:l FEE9:o FEEA:o FEEB:o FEEC:o FF10:O FF11:l FF12:2 "
    "FF13:3 FF14:4 FF15:5 FF16:6 FF17:7 FF18:8 FF19:9 FF21:A FF22:B FF23:C FF24:D "
    "FF25:E FF26:F FF27:G FF28:H FF29:l FF2A:J FF2B:K FF2C:L FF2D:M FF2E:N FF2F:O "
    "FF30:P FF31:Q FF32:R FF33:S FF34:T FF35:U FF36:V FF37:W FF38:X FF39:Y FF3A:Z "
    "FF41:a FF42:b FF43:c FF44:d FF45:e FF46:f FF47:g FF48:h FF49:i FF4A:j FF4B:k "
    "FF4C:l FF4E:n FF4F:o FF50:p FF51:q FF52:r FF53:s FF54:t FF55:u FF56:v FF57:w "
    "FF58:x FF59:y FF5A:z FF5C:l FFB7:o FFE8:l 1017E:f 1018B:d 10282:B 10286:E "
    "10287:F 1028A:l 10290:X 10292:O 10295:P 10296:S 10297:T 102A0:A 102A1:B "
    "102A2:C 102A5:F 102AB:O 102B0:M 102B1:T 102B2:Y 102B4:X 102CF:H 102F5:Z "
    "10301:B 10302:C 10309:l 1030F:O 10311:M 10315:T 10317:X 1031A:8 1031C:b "
    "10320:l 10322:X 10404:O 10415:C 1041B:L 10420:S 1042C:o 1043D:c 10448:s "
    "104B4:R 104C2:O 104CE:U 104D2:7 104EA:o 104F6:u 10507:Z 1050E:l 10513:N "
    "10516:O 10518:K 1051B:C 1051D:V 10525:F 10526:L 10527:X 10926:l 1092C:o "
    "10C13:X 10C17:O 10C1F:V 10C20:Y 10C21:M 10C3E:l 10C82:X 10CA5:l 10CC2:x "
    "10CFA:l 10CFC:X 10D07:o 11047:l 110C0:l 11124:o 11141:l 111C5:l 11302:o "
    "113D4:l 11445:8 1144B:l 114D0:o 115C5:l 11641:l 11706:v 1170A:w 1170E:w "
    "1170F:w 118A0:V 118A2:F 118A3:L 118A4:Y 118A6:E 118A9:Z 118AC:9 118AE:E "
    "118AF:4 118B2:L 118B5:O 118B8:U 118BB:5 118BC:T 118C0:v 118C1:s 118C2:F "
    "118C3:i 118C4:y 118C6:7 118C8:o 118CA:3 118CC:9 118D5:6 118D6:9 118D7:o "
    "118D8:u 118DC:y 118E0:O 118E5:Z 118E6:W 118E9:C 118EC:X 118EF:W 118F2:C "
    "11ABC:Z 11ABE:N 11C41:l 11DDA:l 11DE0:O 11DE1:l 169C1:9 169FE:8 16A19:r "
    "16AD6:S 16AE9:O 16D63:l 16E82:4 16E8A:7 16EAA:l 16EB6:b 16F08:V 16F0A:T "
    "16F16:L 16F28:l 16F35:R 16F3A:S 16F3B:3 16F40:A 16F42:U 16F43:Y 1CCD6:A "
    "1CCD7:B 1CCD8:C 1CCD9:D 1CCDA:E 1CCDB:F 1CCDC:G 1CCDD:H 1CCDE:l 1CCDF:J "
    "1CCE0:K 1CCE1:L 1CCE2:M 1CCE3:N 1CCE4:O 1CCE5:P 1CCE6:Q 1CCE7:R 1CCE8:S "
    "1CCE9:T 1CCEA:U 1CCEB:V 1CCEC:W 1CCED:X 1CCEE:Y 1CCEF:Z 1CCF0:O 1CCF1:l "
    "1CCF2:2 1CCF3:3 1CCF4:4 1CCF5:5 1CCF6:6 1CCF7:7 1CCF8:8 1CCF9:9 1CEFC:V "
    "1D100:l 1D134:c 1D1FE:7 1D206:3 1D207:b 1D20C:W 1D20D:V 1D212:7 1D213:F "
    "1D216:R 1D22A:L 1D373:T 1D377:l 1D400:A 1D401:B 1D402:C 1D403:D 1D404:E "
    "1D405:F 1D406:G 1D407:H 1D408:l 1D409:J 1D40A:K 1D40B:L 1D40C:M 1D40D:N "
    "1D40E:O 1D40F:P 1D410:Q 1D411:R 1D412:S 1D413:T 1D414:U 1D415:V 1D416:W "
    "1D417:X 1D418:Y 1D419:Z 1D41A:a 1D41B:b 1D41C:c 1D41D:d 1D41E:e 1D41F:f "
    "1D420:g 1D421:h 1D422:i 1D423:j 1D424:k 1D425:l 1D427:n 1D428:o 1D429:p "
    "1D42A:q 1D42B:r 1D42C:s 1D42D:t 1D42E:u 1D42F:v 1D430:w 1D431:x 1D432:y "
    "1D433:z 1D434:A 1D435:B 1D436:C 1D437:D 1D438:E 1D439:F 1D43A:G 1D43B:H "
    "1D43C:l 1D43D:J 1D43E:K 1D43F:L 1D440:M 1D441:N 1D442:O 1D443:P 1D444:Q "
    "1D445:R 1D446:S 1D447:T 1D448:U 1D449:V 1D44A:W 1D44B:X 1D44C:Y 1D44D:Z "
    "1D44E:a 1D44F:b 1D450:c 1D451:d 1D452:e 1D453:f 1D454:g 1D456:i 1D457:j "
    "1D458:k 1D459:l 1D45B:n 1D45C:o 1D45D:p 1D45E:q 1D45F:r 1D460:s 1D461:t "
    "1D462:u 1D463:v 1D464:w 1D465:x 1D466:y 1D467:z 1D468:A 1D469:B 1D46A:C "
    "1D46B:D 1D46C:E 1D46D:F 1D46E:G 1D46F:H 1D470:l 1D471:J 1D472:K 1D473:L "
    "1D474:M 1D475:N 1D476:O 1D477:P 1D478:Q 1D479:R 1D47A:S 1D47B:T 1D47C:U "
    "1D47D:V 1D47E:W 1D47F:X 1D480:Y 1D481:Z 1D482:a 1D483:b 1D484:c 1D485:d "
    "1D486:e 1D487:f 1D488:g 1D489:h 1D48A:i 1D48B:j 1D48C:k 1D48D:l 1D48F:n "
    "1D490:o 1D491:p 1D492:q 1D493:r 1D494:s 1D495:t 1D496:u 1D497:v 1D498:w "
    "1D499:x 1D49A:y 1D49B:z 1D49C:A 1D49E:C 1D49F:D 1D4A2:G 1D4A5:J 1D4A6:K "
    "1D4A9:N 1D4AA:O 1D4AB:P 1D4AC:Q 1D4AE:S 1D4AF:T 1D4B0:U 1D4B1:V 1D4B2:W "
    "1D4B3:X 1D4B4:Y 1D4B5:Z 1D4B6:a 1D4B7:b 1D4B8:c 1D4B9:d 1D4BB:f 1D4BD:h "
    "1D4BE:i 1D4BF:j 1D4C0:k 1D4C1:l 1D4C3:n 1D4C5:p 1D4C6:q 1D4C7:r 1D4C8:s "
    "1D4C9:t 1D4CA:u 1D4CB:v 1D4CC:w 1D4CD:x 1D4CE:y 1D4CF:z 1D4D0:A 1D4D1:B "
    "1D4D2:C 1D4D3:D 1D4D4:E 1D4D5:F 1D4D6:G 1D4D7:H 1D4D8:l 1D4D9:J 1D4DA:K "
    "1D4DB:L 1D4DC:M 1D4DD:N 1D4DE:O 1D4DF:P 1D4E0:Q 1D4E1:R 1D4E2:S 1D4E3:T "
    "1D4E4:U 1D4E5:V 1D4E6:W 1D4E7:X 1D4E8:Y 1D4E9:Z 1D4EA:a 1D4EB:b 1D4EC:c "
    "1D4ED:d 1D4EE:e 1D4EF:f 1D4F0:g 1D4F1:h 1D4F2:i 1D4F3:j 1D4F4:k 1D4F5:l "
    "1D4F7:n 1D4F8:o 1D4F9:p 1D4FA:q 1D4FB:r 1D4FC:s 1D4FD:t 1D4FE:u 1D4FF:v "
    "1D500:w 1D501:x 1D502:y 1D503:z 1D504:A 1D505:B 1D507:D 1D508:E 1D509:F "
    "1D50A:G 1D50D:J 1D50E:K 1D50F:L 1D510:M 1D511:N 1D512:O 1D513:P 1D514:Q "
    "1D516:S 1D517:T 1D518:U 1D519:V 1D51A:W 1D51B:X 1D51C:Y 1D51E:a 1D51F:b "
    "1D520:c 1D521:d 1D522:e 1D523:f 1D524:g 1D525:h 1D526:i 1D527:j 1D528:k "
    "1D529:l 1D52B:n 1D52C:o 1D52D:p 1D52E:q 1D52F:r 1D530:s 1D531:t 1D532:u "
    "1D533:v 1D534:w 1D535:x 1D536:y 1D537:z 1D538:A 1D539:B 1D53B:D 1D53C:E "
    "1D53D:F 1D53E:G 1D540:l 1D541:J 1D542:K 1D543:L 1D544:M 1D546:O 1D54A:S "
    "1D54B:T 1D54C:U 1D54D:V 1D54E:W 1D54F:X 1D550:Y 1D552:a 1D553:b 1D554:c "
    "1D555:d 1D556:e 1D557:f 1D558:g 1D559:h 1D55A:i 1D55B:j 1D55C:k 1D55D:l "
    "1D55F:n 1D560:o 1D561:p 1D562:q 1D563:r 1D564:s 1D565:t 1D566:u 1D567:v "
    "1D568:w 1D569:x 1D56A:y 1D56B:z 1D56C:A 1D56D:B 1D56E:C 1D56F:D 1D570:E "
    "1D571:F 1D572:G 1D573:H 1D574:l 1D575:J 1D576:K 1D577:L 1D578:M 1D579:N "
    "1D57A:O 1D57B:P 1D57C:Q 1D57D:R 1D57E:S 1D57F:T 1D580:U 1D581:V 1D582:W "
    "1D583:X 1D584:Y 1D585:Z 1D586:a 1D587:b 1D588:c 1D589:d 1D58A:e 1D58B:f "
    "1D58C:g 1D58D:h 1D58E:i 1D58F:j 1D590:k 1D591:l 1D593:n 1D594:o 1D595:p "
    "1D596:q 1D597:r 1D598:s 1D599:t 1D59A:u 1D59B:v 1D59C:w 1D59D:x 1D59E:y "
    "1D59F:z 1D5A0:A 1D5A1:B 1D5A2:C 1D5A3:D 1D5A4:E 1D5A5:F 1D5A6:G 1D5A7:H "
    "1D5A8:l 1D5A9:J 1D5AA:K 1D5AB:L 1D5AC:M 1D5AD:N 1D5AE:O 1D5AF:P 1D5B0:Q "
    "1D5B1:R 1D5B2:S 1D5B3:T 1D5B4:U 1D5B5:V 1D5B6:W 1D5B7:X 1D5B8:Y 1D5B9:Z "
    "1D5BA:a 1D5BB:b 1D5BC:c 1D5BD:d 1D5BE:e 1D5BF:f 1D5C0:g 1D5C1:h 1D5C2:i "
    "1D5C3:j 1D5C4:k 1D5C5:l 1D5C7:n 1D5C8:o 1D5C9:p 1D5CA:q 1D5CB:r 1D5CC:s "
    "1D5CD:t 1D5CE:u 1D5CF:v 1D5D0:w 1D5D1:x 1D5D2:y 1D5D3:z 1D5D4:A 1D5D5:B "
    "1D5D6:C 1D5D7:D 1D5D8:E 1D5D9:F 1D5DA:G 1D5DB:H 1D5DC:l 1D5DD:J 1D5DE:K "
    "1D5DF:L 1D5E0:M 1D5E1:N 1D5E2:O 1D5E3:P 1D5E4:Q 1D5E5:R 1D5E6:S 1D5E7:T "
    "1D5E8:U 1D5E9:V 1D5EA:W 1D5EB:X 1D5EC:Y 1D5ED:Z 1D5EE:a 1D5EF:b 1D5F0:c "
    "1D5F1:d 1D5F2:e 1D5F3:f 1D5F4:g 1D5F5:h 1D5F6:i 1D5F7:j 1D5F8:k 1D5F9:l "
    "1D5FB:n 1D5FC:o 1D5FD:p 1D5FE:q 1D5FF:r 1D600:s 1D601:t 1D602:u 1D603:v "
    "1D604:w 1D605:x 1D606:y 1D607:z 1D608:A 1D609:B 1D60A:C 1D60B:D 1D60C:E "
    "1D60D:F 1D60E:G 1D60F:H 1D610:l 1D611:J 1D612:K 1D613:L 1D614:M 1D615:N "
    "1D616:O 1D617:P 1D618:Q 1D619:R 1D61A:S 1D61B:T 1D61C:U 1D61D:V 1D61E:W "
    "1D61F:X 1D620:Y 1D621:Z 1D622:a 1D623:b 1D624:c 1D625:d 1D626:e 1D627:f "
    "1D628:g 1D629:h 1D62A:i 1D62B:j 1D62C:k 1D62D:l 1D62F:n 1D630:o 1D631:p "
    "1D632:q 1D633:r 1D634:s 1D635:t 1D636:u 1D637:v 1D638:w 1D639:x 1D63A:y "
    "1D63B:z 1D63C:A 1D63D:B 1D63E:C 1D63F:D 1D640:E 1D641:F 1D642:G 1D643:H "
    "1D644:l 1D645:J 1D646:K 1D647:L 1D648:M 1D649:N 1D64A:O 1D64B:P 1D64C:Q "
    "1D64D:R 1D64E:S 1D64F:T 1D650:U 1D651:V 1D652:W 1D653:X 1D654:Y 1D655:Z "
    "1D656:a 1D657:b 1D658:c 1D659:d 1D65A:e 1D65B:f 1D65C:g 1D65D:h 1D65E:i "
    "1D65F:j 1D660:k 1D661:l 1D663:n 1D664:o 1D665:p 1D666:q 1D667:r 1D668:s "
    "1D669:t 1D66A:u 1D66B:v 1D66C:w 1D66D:x 1D66E:y 1D66F:z 1D670:A 1D671:B "
    "1D672:C 1D673:D 1D674:E 1D675:F 1D676:G 1D677:H 1D678:l 1D679:J 1D67A:K "
    "1D67B:L 1D67C:M 1D67D:N 1D67E:O 1D67F:P 1D680:Q 1D681:R 1D682:S 1D683:T "
    "1D684:U 1D685:V 1D686:W 1D687:X 1D688:Y 1D689:Z 1D68A:a 1D68B:b 1D68C:c "
    "1D68D:d 1D68E:e 1D68F:f 1D690:g 1D691:h 1D692:i 1D693:j 1D694:k 1D695:l "
    "1D697:n 1D698:o 1D699:p 1D69A:q 1D69B:r 1D69C:s 1D69D:t 1D69E:u 1D69F:v "
    "1D6A0:w 1D6A1:x 1D6A2:y 1D6A3:z 1D6A4:i 1D6A5:j 1D6A8:A 1D6A9:B 1D6AC:E "
    "1D6AD:Z 1D6AE:H 1D6B0:l 1D6B1:K 1D6B3:M 1D6B4:N 1D6B6:O 1D6B8:P 1D6BB:T "
    "1D6BC:Y 1D6BE:X 1D6C2:a 1D6C4:y 1D6CA:i 1D6CE:v 1D6D0:o 1D6D2:p 1D6D4:o "
    "1D6D6:u 1D6E0:p 1D6E2:A 1D6E3:B 1D6E6:E 1D6E7:Z 1D6E8:H 1D6EA:l 1D6EB:K "
    "1D6ED:M 1D6EE:N 1D6F0:O 1D6F2:P 1D6F5:T 1D6F6:Y 1D6F8:X 1D6FC:a 1D6FE:y "
    "1D704:i 1D708:v 1D70A:o 1D70C:p 1D70E:o 1D710:u 1D71A:p 1D71C:A 1D71D:B "
    "1D720:E 1D721:Z 1D722:H 1D724:l 1D725:K 1D727:M 1D728:N 1D72A:O 1D72C:P "
    "1D72F:T 1D730:Y 1D732:X 1D736:a 1D738:y 1D73E:i 1D742:v 1D744:o 1D746:p "
    "1D748:o 1D74A:u 1D754:p 1D756:A 1D757:B 1D75A:E 1D75B:Z 1D75C:H 1D75E:l "
    "1D75F:K 1D761:M 1D762:N 1D764:O 1D766:P 1D769:T 1D76A:Y 1D76C:X 1D770:a "
    "1D772:y 1D778:i 1D77C:v 1D77E:o 1D780:p 1D782:o 1D784:u 1D78E:p 1D790:A "
    "1D791:B 1D794:E 1D795:Z 1D796:H 1D798:l 1D799:K 1D79B:M 1D79C:N 1D79E:O "
    "1D7A0:P 1D7A3:T 1D7A4:Y 1D7A6:X 1D7AA:a 1D7AC:y 1D7B2:i 1D7B6:v 1D7B8:o "
    "1D7BA:p 1D7BC:o 1D7BE:u 1D7C8:p 1D7CA:F 1D7CE:O 1D7CF:l 1D7D0:2 1D7D1:3 "
    "1D7D2:4 1D7D3:5 1D7D4:6 1D7D5:7 1D7D6:8 1D7D7:9 1D7D8:O 1D7D9:l 1D7DA:2 "
    "1D7DB:3 1D7DC:4 1D7DD:5 1D7DE:6 1D7DF:7 1D7E0:8 1D7E1:9 1D7E2:O 1D7E3:l "
    "1D7E4:2 1D7E5:3 1D7E6:4 1D7E7:5 1D7E8:6 1D7E9:7 1D7EA:8 1D7EB:9 1D7EC:O "
    "1D7ED:l 1D7EE:2 1D7EF:3 1D7F0:4 1D7F1:5 1D7F2:6 1D7F3:7 1D7F4:8 1D7F5:9 "
    "1D7F6:O 1D7F7:l 1D7F8:2 1D7F9:3 1D7FA:4 1D7FB:5 1D7FC:6 1D7FD:7 1D7FE:8 "
    "1D7FF:9 1DF5A:a 1DF6A:A 1DF7D:w 1DF81:E 1E140:O 1E141:l 1E145:V 1E2F0:O "
    "1E2F2:9 1E8C7:l 1E8CB:8 1ED01:l 1EE00:l 1EE24:o 1EE80:l 1EE84:o 1F74C:C "
    "1F768:T 1FBF0:O 1FBF1:l 1FBF2:2 1FBF3:3 1FBF4:4 1FBF5:5 1FBF6:6 1FBF7:7 "
    "1FBF8:8 1FBF9:9"
)
# Look-alikes the Unicode table leaves out, because their skeleton is not a
# single ASCII letter: Latin small capitals and a few Cyrillic and Greek
# letters.
_LOOKALIKE_EXTRA = (
    "24F:y 262:g 274:n 280:r 299:b 29C:h 29F:l 3B5:e 3BA:k 432:b 43A:k 43C:m "
    "43D:h 442:t 1D00:a 1D05:d 1D07:e 1D0A:j 1D0B:k 1D0D:m 1D18:p 1D1B:t A730:f"
)
_CONFUSABLES = str.maketrans(
    {
        chr(int(code, 16)): letter
        for code, letter in (
            pair.split(":") for pair in (_UTS39_PACK + " " + _LOOKALIKE_EXTRA).split()
        )
    }
)

_LITERAL = re.compile(r"""[rRbBuUfF]{0,2}("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')""")
_JOINERS = ("", " ", "-", "_", ".", "/")
_B64 = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){4,}")
_ESC = re.compile(
    r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\U([0-9a-fA-F]{8})|\\([ntr])"
)
_SIMPLE_ESC = {"n": "\n", "t": "\t", "r": "\r"}
_CONTINUATION = re.compile(r"[\"']\s*\\?\r?\n\s*[\"']|\\\r?\n\s*")
_SVG_GEOMETRY = re.compile(r'\b(?:d|points|viewBox|transform)="[^"]*"')
_BASE_ONLY = {
    "email",
    "user-at-host",
    "private-ipv4",
    "private-ipv6",
    "host-dns-name",
    "trust-domain",
}
_TOKEN = re.compile(r"[A-Za-z0-9]+")
_COMPOUND = re.compile(r"[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*")

_SEP = r"(?:\\+|/+)"
RULES: dict[str, re.Pattern[str]] = {
    "windows-home-path": re.compile(
        r"[A-Za-z]:" + _SEP + r"Users" + _SEP + r"[A-Za-z0-9]", re.IGNORECASE
    ),
    "posix-home-path": re.compile(r"/home/[a-z0-9_]"),
    "mac-home-path": re.compile(r"/Users/[A-Za-z0-9]"),
    "tilde-user-path": re.compile(r"~[A-Za-z][A-Za-z0-9_-]*/"),
    "wsl-network-path": re.compile(r"(?:\\\\|//)wsl(?:\$|\.localhost)", re.IGNORECASE),
    "private-ipv4": re.compile(
        r"(?<![\d.])(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168|"
        r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])|169\.254)\.\d{1,3}\.\d{1,3}(?![\d.]*\d)"
    ),
    "private-ipv6": re.compile(
        r"(?<![0-9A-Fa-f:])(?:f[cd][0-9a-f]{2}|fe[89ab][0-9a-f]):[0-9a-f:]*:[0-9a-f]",
        re.IGNORECASE,
    ),
    "email": re.compile(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
    ),
    "user-at-host": re.compile(
        r"(?<![\w.@/+\\-])[A-Za-z_][A-Za-z0-9_-]*@[A-Za-z][A-Za-z0-9-]*(?![\w.@-])"
    ),
    # A name under a suffix that only resolves on one host or one private
    # network (Hyper-V, mDNS, home routers, tailnets).
    "host-dns-name": re.compile(
        r"(?<![\w.-])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\."
        r"(?:mshome\.net|local|lan|home\.arpa|internal|localdomain|intranet|ts\.net)"
        r"(?![\w-])",
        re.IGNORECASE,
    ),
    # A SPIFFE trust domain other than a reserved placeholder or a template.
    "trust-domain": re.compile(
        r"(?:spiffe://|trust_domain\s*[=:]\s*[\"'])"
        r"(?!\{|(?:[\w-]+\.)*(?:invalid|test|example)(?![\w.-])|example\.(?:org|com|net)(?![\w.-]))"
        r"[A-Za-z0-9][A-Za-z0-9.-]*",
        re.IGNORECASE,
    ),
}
_EMAIL_OK = re.compile(
    r"@(?:users\.noreply\.github\.com|noreply\.github\.com|example\.(?:com|org|net)|\d+\.(?:service|slice|scope))$",
    re.IGNORECASE,
)
_PLACEHOLDER_LOCAL = {"user", "you", "name", "me", "operator", "root"}
# The stock Firecracker guest image prompt is generic, not a host identity.
_PLACEHOLDER_HOST = {
    "host",
    "example",
    "localhost",
    "server",
    "box",
    "remote",
    "guest",
    "ubuntu-fc-uvm",
}


class ListError(ValueError):
    """The private list cannot be trusted; the message never names an entry."""


class Entry:
    """One private term. Its repr never shows the term."""

    __slots__ = ("index", "canary", "_rx", "_compact", "_folded")

    def __init__(self, index: int, raw: str) -> None:
        self.index = index
        self.canary = raw.casefold() == CANARY
        if raw.startswith("re:"):
            try:
                rx = re.compile(raw[3:], re.IGNORECASE)
            except re.error:
                raise ListError(f"entry {index}: not a valid pattern") from None
            if rx.search("") is not None:
                raise ListError(f"entry {index}: matches empty text")
            if not rx.search(_literal_core(raw[3:])):
                raise ListError(f"entry {index}: cannot be shown to match anything")
            self._rx = rx
            self._compact = None
            # A pattern that turns case sensitivity back on keeps it: the
            # casefolded view would let it match a case it was written to skip.
            self._folded = not _turns_case_off(raw[3:])
        else:
            norm = normalise(raw).casefold()
            core = _compact(norm)
            if len(core) < MIN_PLAIN:
                raise ListError(
                    f"entry {index}: fewer than {MIN_PLAIN} letters or digits"
                )
            self._rx = re.compile(re.escape(norm), re.IGNORECASE)
            self._folded = True
            self._compact = core if len(core) >= MIN_COMPACT else None

    def __repr__(self) -> str:
        return f"<entry {self.index}>"

    def hits(self, views: Views) -> bool:
        if self._rx.search(views.text):
            return True
        # Case folding goes further than IGNORECASE (a sharp s folds to ss).
        if self._folded and self._rx.search(views.folded):
            return True
        return bool(self._compact and self._compact in views.compact)


class Views:
    """Every decoded form of one input. Its repr never shows the text."""

    __slots__ = ("text", "folded", "plain", "base", "compact", "tokens")

    def __init__(
        self, base: list[str], joined: list[str], obfuscated: list[str]
    ) -> None:
        # Address and identity rules read the decoded forms; path and network
        # rules also read joined literals; private entries read everything,
        # including reversed and rot13 forms.
        self.base = _SVG_GEOMETRY.sub("", "\n".join(base))
        self.plain = self.base + "\n" + _SVG_GEOMETRY.sub("", "\n".join(joined))
        self.text = "\n".join(base + joined + obfuscated)
        self.folded = self.text.casefold()
        self.compact = "\n".join(
            _compact(_drop_allowed(f).casefold()) for f in base + joined + obfuscated
        )
        self.tokens = _token_hashes(self.plain)

    def __repr__(self) -> str:
        return "<views>"


def _sre():
    try:
        import re._parser as sre  # Python 3.11 and later
    except ImportError:  # pragma: no cover - older interpreters
        import sre_parse as sre
    return sre


def _regex_key(pattern: str) -> str:
    """A key two spellings of the same regex share, read from the parsed
    pattern: groups that only group (or set a flag that is already set) are
    dropped, a repeat of exactly once is its body, a one-letter class is the
    letter, and letters compare without case except inside a group that turns
    case off. Anything else is kept as parsed, so patterns that match different
    text keep different keys."""
    sre = _sre()
    repeats = {sre.MAX_REPEAT, sre.MIN_REPEAT}
    repeats.add(getattr(sre, "POSSESSIVE_REPEAT", sre.MAX_REPEAT))

    def letter(code: int, nocase: bool) -> tuple:
        lower = chr(code).lower()
        return ("lit", ord(lower) if nocase and len(lower) == 1 else code)

    def canon(items, nocase: bool) -> list:
        out: list = []
        for op, av in items:
            if op is sre.SUBPATTERN:
                group, add, removed, sub = av
                inner = (nocase or bool(add & re.IGNORECASE)) and not (
                    removed & re.IGNORECASE
                )
                body = canon(sub, inner)
                other_flags = (add | removed) & ~re.IGNORECASE
                if group is None and inner == nocase and not other_flags:
                    out.extend(body)
                else:
                    out.append(("group", group is not None, add, removed, tuple(body)))
            elif op in repeats and av[0] == av[1] == 1:
                out.extend(canon(av[2], nocase))
            elif op in repeats:
                out.append((str(op), av[0], av[1], tuple(canon(av[2], nocase))))
            elif op is sre.LITERAL:
                out.append(letter(av, nocase))
            elif op is sre.IN and len(av) == 1 and av[0][0] is sre.LITERAL:
                out.append(letter(av[0][1], nocase))
            elif op is sre.BRANCH:
                out.append(("branch", tuple(tuple(canon(b, nocase)) for b in av[1])))
            elif op in (sre.ASSERT, sre.ASSERT_NOT):
                out.append((str(op), av[0], tuple(canon(av[1], nocase))))
            else:
                out.append((str(op), repr(av)))
        return out

    tree = sre.parse(pattern, re.IGNORECASE)
    flags = tree.state.flags & ~(re.IGNORECASE | re.UNICODE)
    return repr((flags, tuple(canon(tree, True))))


def _turns_case_off(pattern: str) -> bool:
    """True when any group in the parsed pattern removes IGNORECASE, however
    the flag group is spelled; the same characters inside a literal or a
    character class do not count."""
    sre = _sre()

    def walk(node: object) -> bool:
        if isinstance(node, tuple) and len(node) == 2 and node[0] is sre.SUBPATTERN:
            _group, _add, removed, _sub = node[1]
            if removed & re.IGNORECASE:
                return True
        if isinstance(node, (list, tuple, sre.SubPattern)):
            return any(walk(child) for child in node)
        return False

    return walk(sre.parse(pattern, re.IGNORECASE))


def _literal_core(pattern: str) -> str:
    core = re.sub(r"\(\?[a-zA-Z-]*:?|\\[bBAZ]|[\^$()]", "", pattern)
    return core.replace("\\", "")


def _drop_allowed(text: str) -> str:
    def one(match: re.Match[str]) -> str:
        word = match.group(0)
        digest = hashlib.sha256(word.casefold().encode()).hexdigest()
        return " " if digest in ALLOWED_IDENTIFIERS else word

    return _IDENT.sub(one, text)


def _compact(text: str) -> str:
    return re.sub(r"[\W_]+", "", text)


# Unicode Default_Ignorable_Code_Point (DerivedCoreProperties.txt), as ranges.
# These render as nothing, so a private name with one inside reads as the name;
# the standard library has no lookup for the property, hence the table.
_DEFAULT_IGNORABLE = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)


def _ignorable(ch: str) -> bool:
    cp = ord(ch)
    return unicodedata.category(ch) == "Cf" or any(
        lo <= cp <= hi for lo, hi in _DEFAULT_IGNORABLE
    )


def normalise(text: str) -> str:
    """NFKC, then drop every default-ignorable code point and format character,
    then every combining mark, spacing ones included (a letter plus a mark
    composes into a different letter, so a mark inside a name hid it), then
    fold Latin look-alikes."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if not _ignorable(ch))
    text = unicodedata.normalize("NFD", text)
    text = "".join(
        ch for ch in text if unicodedata.category(ch) not in ("Mn", "Mc", "Me")
    )
    text = unicodedata.normalize("NFC", text)
    return text.translate(_CONFUSABLES)


def _token_hashes(text: str) -> frozenset[str]:
    words = [w.casefold() for w in _TOKEN.findall(text)]
    tokens = set(words)
    tokens.update(a + b for a, b in zip(words, words[1:]))
    tokens.update(a + b + c for a, b, c in zip(words, words[1:], words[2:]))
    for match in _COMPOUND.finditer(text):
        run = _compact(match.group(0)).casefold()
        if len(run) > MAX_COMPOUND:
            continue
        for size in BUILTIN_HOST_LENGTHS:
            tokens.update(run[i : i + size] for i in range(len(run) - size + 1))
    return frozenset(hashlib.sha256(t.encode()).hexdigest() for t in tokens)


def _regex_literal(pattern: str) -> str | None:
    """The text a pattern matches if it is only a literal (escaped
    punctuation allowed); None when it uses any regex syntax."""
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            nxt = pattern[i + 1 : i + 2]
            if not nxt or nxt.isalnum() or nxt == "_":
                return None  # \b, \d, \1 and the like are regex syntax
            out.append(nxt)
            i += 2
            continue
        if ch in ".^$*+?{}[]|()":
            return None
        out.append(ch)
        i += 1
    return "".join(out)


def load_entries(raw: str, expect: int) -> list[Entry]:
    lines = [line.strip() for line in raw.splitlines()]
    lines = [line for line in lines if line and not line.startswith("#")]
    if not lines:
        raise ListError("private list is empty")
    entries = [Entry(i, line) for i, line in enumerate(lines)]
    # Repeats cannot meet the exact count: an entry that repeats an earlier one
    # after normalise().casefold() and whitespace folding, a regex that is only
    # a literal name (keyed as that name), a regex that differs only by case,
    # or another spelling of the canary, plain or regex, is refused by index.
    # Distinct entries that name nothing private still count; see CHANGELOG.
    seen: dict[str, int] = {}
    for index, line in enumerate(lines):
        if entries[index].canary:
            continue  # counted below: the canary must appear exactly once
        literal = _regex_literal(line[3:]) if line.startswith("re:") else line
        if literal is None:
            key = "re:" + _regex_key(line[3:])
        else:
            key = " ".join(normalise(literal).casefold().split())
            if key == CANARY:
                raise ListError(f"entry {index}: is another spelling of the canary")
        if key in seen:
            raise ListError(f"entry {index}: duplicates entry {seen[key]}")
        seen[key] = index
    canaries = [e for e in entries if e.canary]
    if len(canaries) != 1:
        raise ListError(
            f"private list must hold the canary exactly once, found {len(canaries)}"
        )
    real = len(entries) - 1
    if real != expect:
        raise ListError(f"private list holds {real} entries, expected {expect}")
    return entries


def decodings(data: bytes) -> list[str]:
    """Every text a reader could get from these bytes. Nothing is skipped."""
    out = [data.decode("utf-8", "replace")]
    # Wide decodes run on every file: look-alike letters in UTF-16 or UTF-32
    # carry no NUL byte, so NUL is not a reliable sign of a wide encoding.
    for enc, width in (
        ("utf-16-le", 2),
        ("utf-16-be", 2),
        ("utf-32-le", 4),
        ("utf-32-be", 4),
    ):
        for shift in range(width):
            chunk = data[shift:]
            chunk = chunk[: len(chunk) - len(chunk) % width]
            out.append(chunk.decode(enc, "replace"))
    if b"\x00" in data:
        out.append(data.replace(b"\x00", b"").decode("latin-1"))
    out.append(data.decode("latin-1"))
    return out


def _printable(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text and sum(ch.isprintable() for ch in text) >= 0.9 * len(text):
        return text
    return None


def _decoded_tokens(text: str) -> list[str]:
    out: list[str] = []
    for token in _B64.findall(text):
        body = token.rstrip("=")
        for decode in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = _printable(decode(body + "=" * (-len(body) % 4)))
            except (binascii.Error, ValueError):
                continue
            if decoded:
                out.append(decoded)
    for token in _HEX.findall(text):
        decoded = _printable(bytes.fromhex(token))
        if decoded:
            out.append(decoded)
    return out


def _unescape(text: str) -> str:
    def one(match: re.Match[str]) -> str:
        if match.group(4):
            return _SIMPLE_ESC[match.group(4)]
        return chr(int(match.group(1) or match.group(2) or match.group(3), 16))

    return _ESC.sub(one, text)


_DECODERS = (unquote, _unescape, html.unescape)
MAX_ROUNDS = 4


def _decoded_closure(seed: str) -> list[str]:
    """``seed`` and every text the decoders reach from it, in any order."""
    seen = {seed}
    out = [seed]
    frontier = [seed]
    for _ in range(MAX_ROUNDS):
        later = []
        for form in frontier:
            for decode in _DECODERS:
                found = normalise(decode(form))
                if found not in seen:
                    seen.add(found)
                    out.append(found)
                    later.append(found)
        frontier = later
    return out


def text_forms(text: str, depth: int = 0) -> tuple[list[str], list[str], list[str]]:
    """(decoded forms, joined forms, obfuscated forms) of one text."""
    base = normalise(text)
    # A line continuation is a join the language itself performs, so every
    # rule reads the continued text, not only the path and private rules.
    forms = [text, *_decoded_closure(base)]
    continued = _CONTINUATION.sub("", base)
    if continued != base:
        forms += _decoded_closure(continued)
    joined: list[str] = []
    literals = [_drop_allowed(m.group(1)[1:-1]) for m in _LITERAL.finditer(base)]
    for size in range(2, 5):
        for i in range(len(literals) - size + 1):
            window = literals[i : i + size]
            joined.extend(joiner.join(window) for joiner in _JOINERS)
    obfuscated = [base[::-1], codecs.encode(base, "rot13")]
    if depth < MAX_DEPTH:
        tokens = itertools.chain.from_iterable(
            _decoded_tokens(form) for form in dict.fromkeys(forms[1:])
        )
        for decoded in dict.fromkeys(tokens):
            more, more_joined, more_obfuscated = text_forms(decoded, depth + 1)
            forms += more
            joined += more_joined
            obfuscated += more_obfuscated
    return forms, [normalise(f) for f in joined], obfuscated


def views_for(data: bytes) -> Views:
    forms: list[str] = []
    joined: list[str] = []
    obfuscated: list[str] = []
    for text in decodings(data):
        more, more_joined, more_obfuscated = text_forms(text)
        forms += more
        joined += more_joined
        obfuscated += more_obfuscated
    return Views(forms, joined, obfuscated)


def _builtin_hits(views: Views) -> list[str]:
    hits: list[str] = []
    for name, rx in RULES.items():
        for match in rx.finditer(views.base if name in _BASE_ONLY else views.plain):
            found = match.group(0)
            if name == "email" and _EMAIL_OK.search(found):
                continue
            if name == "user-at-host":
                local, host = found.lower().split("@", 1)
                if local in _PLACEHOLDER_LOCAL and host in _PLACEHOLDER_HOST:
                    continue
            hits.append(name)
            break
    if views.tokens & BUILTIN_HOST_TOKENS:
        hits.append("box-host-name")
    return hits


def scan_bytes(data: bytes, entries: list[Entry]) -> list[str]:
    """Rule names and entry indexes found in ``data``; never the matched text."""
    views = views_for(data)
    hits = _builtin_hits(views)
    hits += [
        f"private entry {e.index}" for e in entries if not e.canary and e.hits(views)
    ]
    return hits


def canary_hits(data: bytes, entries: list[Entry]) -> bool:
    views = views_for(data)
    return any(e.canary and e.hits(views) for e in entries)


def tracked_files(root: Path) -> list[str]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    return [rel.decode("utf-8", "surrogateescape") for rel in raw.split(b"\0") if rel]


def scan_tree(root: Path, entries: list[Entry]) -> tuple[int, list[str]]:
    rels = tracked_files(root)
    hits: list[str] = []
    for number, rel in enumerate(rels):
        try:
            path_hits = scan_bytes(rel.encode("utf-8", "surrogateescape"), entries)
            shown = f"<tracked file #{number}>" if path_hits else rel
            for hit in path_hits:
                hits.append(f"{shown}: path: {hit}")
            full = root / rel
            if full.is_symlink():
                data = os.fsencode(os.readlink(full))
            elif full.is_file():
                data = full.read_bytes()
            else:
                # Missing from the worktree, or a directory or device: never
                # scan it as empty bytes.
                hits.append(
                    f"<tracked file #{number}>: not a regular file in the worktree"
                )
                continue
            for hit in scan_bytes(data, entries):
                hits.append(f"{shown}: {hit}")
        except Exception as exc:  # fail closed without echoing content
            hits.append(f"<tracked file #{number}>: scan error ({type(exc).__name__})")
    return len(rels), hits


def _urlsafe(term: str) -> str:
    """Unpadded URL-safe base64 of the term plus a suffix that forces - or _."""
    suffixes = (
        "".join(combo)
        for n in (1, 2, 3)
        for combo in itertools.product("?>~", repeat=n)
    )
    for suffix in suffixes:
        encoded = (
            base64.urlsafe_b64encode((term + suffix).encode()).decode().rstrip("=")
        )
        if "-" in encoded or "_" in encoded:
            return encoded
    raise ValueError("no URL-safe form")


def planted_forms(term: str) -> dict[str, bytes]:
    """The term in every form the scan must see through."""
    half = len(term) // 2
    a, b = term[:half], term[half:]
    forms = {
        "plain": term,
        "split-literals": f'X = ("{a}", "{b}")',
        "concatenated": f'X = "{a}" + "{b}"',
        "split-lines": f'X = "{a}" \\\n    "{b}"',
        "base64": base64.b64encode(term.encode()).decode(),
        "base64-urlsafe-unpadded": _urlsafe(term),
        "hex": term.encode().hex(),
        "percent": "".join(f"%{ord(c):02X}" for c in term),
        "double-percent": "".join(f"%25{ord(c):02X}" for c in term),
        "unicode-escape": "".join(f"\\u{ord(c):04x}" for c in term),
        "html-entity": "".join(f"&#x{ord(c):x};" for c in term),
        "fullwidth": "".join(chr(ord(c) + 0xFEE0) for c in term),
        "zero-width": "​".join(term),
        "percent-separator": a + "%20" + b,
        "fullwidth-separator": a + "－" + b,
        "homoglyph": term.replace("x", "х"),
        "reversed": term[::-1],
        "rot13": codecs.encode(term, "rot13"),
    }
    out = {k: v.encode("utf-8") for k, v in forms.items()}
    out["utf-16-bom"] = codecs.BOM_UTF16_LE + term.encode("utf-16-le")
    out["utf-16-le-no-bom"] = term.encode("utf-16-le")
    out["utf-16-be-no-bom"] = term.encode("utf-16-be")
    out["utf-32-le-no-bom"] = term.encode("utf-32-le")
    out["utf-32-be-bom"] = codecs.BOM_UTF32_BE + term.encode("utf-32-be")
    out["binary"] = b"\x89PNG\r\n\x1a\n\x00\x00" + term.encode() + b"\x00\xff"
    return out


def self_check(entries: list[Entry]) -> int:
    missed = [
        name
        for name, data in planted_forms(CANARY).items()
        if not canary_hits(data, entries)
    ]
    if missed:
        raise ListError(
            f"canary not found in {len(missed)} planted form(s): {', '.join(missed)}"
        )
    return len(planted_forms(CANARY))


def _read_list(path: Path | None) -> str:
    raw = os.environ.get("LEAK_DENYLIST", "")
    if raw.strip():
        return raw
    if path is not None and path.is_file():
        return path.read_text(encoding="utf-8")
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--expect-entries", type=int, default=EXPECTED_ENTRIES)
    parser.add_argument("--denylist", type=Path, default=None)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.denylist is None:
        common = subprocess.check_output(
            ["git", "rev-parse", "--git-common-dir"], cwd=root, text=True
        ).strip()
        denylist = (root / common).resolve() / "info" / "leak-denylist"
    else:
        denylist = args.denylist
    try:
        entries = load_entries(_read_list(denylist), args.expect_entries)
        forms = self_check(entries)
        files, hits = scan_tree(root, entries)
    except ListError as exc:
        print(f"public surface scan: FAIL: {exc}")
        return 1
    except Exception as exc:  # never echo content
        print(f"public surface scan: FAIL: {type(exc).__name__}")
        return 1
    print(
        f"public surface scan: {files} tracked files, {len(entries) - 1} private entries, "
        f"canary found in {forms}/{forms} planted forms, {len(hits)} hits"
    )
    for hit in hits:
        print(hit)
    return 0 if files > 0 and not hits else 1


if __name__ == "__main__":
    sys.exit(main())
