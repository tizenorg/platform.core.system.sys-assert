cd `dirname $0`
if [ ! -d "./build" ]
then 
	mkdir build
fi
cd `dirname $0`/build
cmake ../ -DCMAKE_INSTALL_PREFIX=/usr
make
make install
