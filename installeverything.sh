#!/bin/bash

echo 'WELCOME '
echo 'LETS BEGIN'
#checks to make sure git is installed
apt install git 
echo 'MAKING TOOLKIT FOLDER'
mkdir toolkit
echo '[=] pushd toolkit'
pushd toolkit/

function methodologies () {
	mkdir methodologies
	echo '	[#] installing PayloadsAllTheThings'
	git clone https://github.com/swisskyrepo/PayloadsAllTheThings methodologies/PayloadsAllTheThings
	echo '	[#] smashed it, bring on the next one'
	echo '	[#] installing GTFOBins'
	git clone https://github.com/GTFOBins/GTFOBins.github.io methodologies/GTFOBins
	echo '	[#] YES! DONE. NEXT! '
	echo '	[#] installing LOLBAS'
	git clone https://github.com/LOLBAS-Project/LOLBAS.git methodologies/lolbas
	echo '	[#] done! '
	echo '	[#] installing MITM Cheatsheet '
	git clone https://github.com/Sab0tag3d/MITM-cheatsheet methodologies/mitm-cheatsheet
	echo '	[#]  installing  paradisperdu notes' 
	git clone  https://github.com/paradisperdu/Web-Application-Testing.wiki.git methodologies/paradisperdu/web
	git clone  https://github.com/paradisperdu/Android-Testing.wiki.git methodologies/paradisperdu/mobile/android 
	git clone  https://github.com/paradisperdu/ios-testing.wiki.git methodologies/paradisperdu/mobile/ios
	git clone  https://github.com/paradisperdu/Infrastructure.wiki.git methodologies/paradisperdu/inf
	echo '	[#] great success!'
	echo 'downloading cyberchef'
	mkdir -p cyberchef
	wget -P cyberchef/ https://gchq.github.io/CyberChef/CyberChef_v9.20.3.zip

}

function wordlists () {
	mkdir wordlists
	echo '	[#]  installing wordlists'
	echo '	[#] params.txt' 
	git clone https://gist.github.com/nullenc0de/9cb36260207924f8e1787279a05eb773 wordlists/params
	echo '	[#] installing content discovery from nullenc0de' 
	git clone https://gist.github.com/nullenc0de/96fb9e934fc16415fbda2f83f08b28e7 wordlists/content_discover/nullennc0de
	echo ' [#] installing content discovery from jhaddix'  
	git clone https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10 wordlists/content_discover/jhaddix
	echo '	[#] installing all.txt from jhaddix'
	git clone  https://gist.github.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a wordlists/all
	echo '	[#] installing seclists... this will take some time' 
	git clone  https://github.com/danielmiessler/SecLists wordlists/seclists
	echo '	[#] installing cloud metadata from jhaddix' 
	git clone https://gist.github.com/jhaddix/78cece26c91c6263653f31ba453e273b wordlists/cloud

}

function bruteforce () {

	echo '	[+] Installing bruteforce related stuff '
	mkdir bruteforce
	echo ' 	[+] Installing HYDRA dependencies'
	apt-get -y install  libssl-dev libssh-dev libidn11-dev libpcre3-dev \
                 libgtk2.0-dev libmysqlclient-dev libpq-dev libsvn-dev \
                 firebird-dev libmemcached-dev libgpg-error-dev \
                 libgcrypt11-dev libgcrypt20-dev
	git clone https://github.com/vanhauser-thc/thc-hydra.git bruteforce/hydra
	pushd bruteforce/hydra
	./configure
	make
	make install
	popd
	echo '	[+] Hydra Installed '
}

function cracking () {
	mkdir cracking
	echo ' [#] installing HoboRules'
	git clone https://github.com/praetorian-code/Hob0Rules.git wordlists/hoborules 
	echo ' [#] installing John the Ripper '
	mkdir -p cracking/john/src
	echo '	[#] installing dependencies'
	apt-get -y install git build-essential libssl-dev zlib1g-dev yasm pkg-config libgmp-dev libpcap-dev libbz2-dev nvidia-opencl-dev ocl-icd-opencl-dev opencl-headers fglrx-dev 
	pushd cracking/john/src
	echo '	[#] cloning JTR'
	git clone https://github.com/magnumripper/JohnTheRipper -b bleeding-jumbo john
	popd
	pushd cracking/john/src/john/src
	echo '	[#] making JTR'
	./configure && make -s clean && make -sj4
	echo '	[+] testing the build '
	popd
	pushd cracking/john/src/john/run
	./john --test=0
	echo '	[+] running john benchmark '
	./john --test
	popd
	echo ' [#] installing hashcat'
	pushd cracking/
	git clone https://github.com/hashcat/hashcat.git
	popd
	pushd cracking/hashcat/
	echo '[#] making hashcat'
	make
	make install
	echo '[+] finished haschat'
	popd
	echo '[+] downloading crackerjack'
	echo '[+] For now this requires manual install and configure'
	echo '[+] making sure packages are installed'
	apt install git screen python3-venv python-pip sqlite3
	pushd cracking/
	git clone https://github.com/ctxis/crackerjack.git
	popd
	pushd cracking/crackerjack/
	echo '[+] creating venv for crackerjack'
	python3 -m venv venv
	. venv/bin/activate
	echo '[+] installing requirements'
	pip install -r requirements.txt
	flask db init
	flask db migrate
	flask db upgrade
	deactivate
	echo '[+] Installed. At this point it can be run locally'
	popd
}
	
function reverse_engineering () {
	mkdir reverse_engineering
	echo '[+] retrieving ghidra source, you need to build this manually'
	pushd reverse_engineering/
	git clone https://github.com/NationalSecurityAgency/ghidra.git
	echo '[+] downloading latest release build from ghdra-sre.org'
	wget -P ghidra/ https://www.ghidra-sre.org/ghidra_9.1.2_PUBLIC_20200212.zip
	echo '[+] downloading hopper deb package'
	mkdir hopperapp
	wget -P hopperapp/ https://d2ap6ypl1xbe4k.cloudfront.net/Hopper-v4-4.5.23-Linux.deb
	echo '[+] installing hopper and dependencies'	
	apt install libqt5core5a libdouble-conversion1 qttranslations5-l10n libdouble-conversion1 libqt5core5a libqt5dbus5 libqt5gui5 libqt5network5 libqt5printsupport5 libqt5svg5 libqt5widgets5 libqt5xml5 libxcb-xinerama0 qt5-gtk-platformtheme  qttranslations5-l10n libdouble-conversion1 libqt5core5a libqt5dbus5 libqt5gui5 libqt5network5 libqt5printsupport5 libqt5svg5 libqt5widgets5 libqt5xml5 libxcb-xinerama0 qt5-gtk-platformtheme qttranslations5-l10n
	dpkg -i hopperapp/Hopper-v4-4.5.23-Linux.deb
	echo '[+] hopper installed'
	echo  '[+] installing radare2'
	git clone https://github.com/radareorg/radare2.git
	pushd radare2/sys
	./install.sh
	popd
	echo '[+] radare2 installed'
	echo '[+] installing dnspy'
	git clone https://github.com/0xd4d/dnSpy.git
	echo '[+] done'
	echo '[+] installing r2frida'
	echo 'installing dependencies' 
	apt install make gcc libzip-dev nodejs npm curl pkg-config git	
	echo 'downloading'
	git clone --recursive https://github.com/nowsecure/r2frida.git
#	echo 'installing'
#	pushd r2frida
#	make
#	make install
#	popd
}	 
	
function cloud () {
	echo 'installing awscli'
	apt install awscli
	mkdir cloud
	pushd cloud
	echo 'installing cs-suite'
	git clone --recursive https://github.com/SecurityFTW/cs-suite.git
	pushd cs-suite
	echo 'setting up venv and installing requirements'
	pip install virtualenv
	virtualenv -p python2.7 venv
	source venv/bin/activate
	pip install -r requirements.txt
	python cs.py --help	
	deactivate
	popd
	echo 'installing teh s3 bucketeers'
	git clone --recursive https://github.com/tomdev/teh_s3_bucketeers.git
	echo 'done'
	echo 'installing scout suite'
	git clone --recursive https://github.com/nccgroup/ScoutSuite
	pushd ScoutSuite
	virtualenv -p python3 venv
	source venv/bin/activate
	pip install -r requirements.txt
	python scout.py --help
	deactivate
	echo 'scout suite is installed'
	popd
}

function social_engineering () {
	mkdir social_engineering
	echo 'installing SET'
	pushd social_engineering
	git clone https://github.com/trustedsec/social-engineer-toolkit/
	pushd social-engineer-toolkit
	python3 -m venv venv
	. venv/bin/activate
	echo 'installing requirements'
	pip3 install -r requirements.txt
	echo 'installing...'
	python setup.py
	deactivate
	popd
}

function ssl () {
	mkdir ssl
	pushd ssl
	echo 'installing ssl-cipher-enum' 
	git clone https://github.com/portcullislabs/ssl-cipher-suite-enum.git
	echo 'installing testssl.sh'
	git clone --depth 1 https://github.com/drwetter/testssl.sh.git
	echo 'installing sslyze'
	git clone https://github.com/nabla-c0d3/sslyze.git
	pusdh sslyze
	python
}
#methodologies
#wordlists
#bruteforce
#cracking
#reverse_engineering
#cloud
social_engineering
ssl

popd
	
