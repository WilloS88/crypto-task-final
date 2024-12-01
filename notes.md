# DSA

odesila zpravu a hashuje 2x
najit si hash knihovnu 

poslu hash a zasifruju soukromym klicem (RSA)

zabalime do ZIP
a overovatel

pokud jsou oba otisky totozne, tak je potvrzena identita odesilatele a potvrzena integrita prijate zpravy
(tzn. zprava nebyla )

v Cr maji digitalni podpisy stejnou vahu jako osobni podpis


exponenty jsou prehozeny pro zasifrovani a desifrovnai


- Nacist soubor s podpisem
- zobrazeni informaci o podepisovani souboru (nazev, datum vytvoreni, typ souboru)

- Podpis souboru pomoci SHA-3 a RSA
- Overovani podpisu souboru (porovnavani dvou hashu, pokud jsou stejne, tak je to spravne)
- Generovani klicoveho paru s exportem do souboru (.priv a .pub)

- UI kompletne interaktivni (volba souboru v dialogovem okne)
- tlacitka
- Informaovani uzivatele prostrednictvim GUi, ze podpis neni v poradku

## Soubory

soubor.pri bude obsahovat soukromy klic, obsah souboru: RSA SOUKROMY_KLIC_V_BASE64
soubor .pub verejny klic RSA VEREJNY_KLIC_V_BASE64

soubor .msg bude obsahovat otevreny text zpravy
soubor .zip bude obsahovat soubory *.msg a *.sign

soubor *.sign bude obsahovat SHA3 souboru *.msg, ktery bude zasifrovan pomoci RSAprivate key


