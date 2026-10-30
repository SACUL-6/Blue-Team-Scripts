EXT=jdmninjjbnicomamhgcnomgimkbbmkch
curl -L -o ext.crx "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=130.0&acceptformat=crx2,crx3&x=id%3D${EXT}%26uc"
unzip ext.crx -d ext_src3
cat ./ext_src/*