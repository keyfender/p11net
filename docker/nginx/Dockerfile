FROM nginx:alpine

RUN set -ex ;\
  echo "@testing http://nl.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories ;\
  apk add --no-cache --purge -U \
    boost \
    boost-filesystem \
    boost-thread \
    protobuf \
    leveldb@testing \
    mailcap \
    openssl \
    make \
    git \
    cmake \
    g++ \
    curl \
    protobuf-dev \
    boost-dev \
    openssl-dev \
    leveldb-dev@testing \
    ;\
  ln -s /usr/include/locale.h /usr/include/xlocale.h ;\
  echo "#include <sys/time.h>" >> /usr/include/time.h ;\
  mkdir /src ;\
  cd /src ;\
  curl -L https://github.com/Microsoft/cpprestsdk/archive/v2.9.1.tar.gz \
    | tar zxpf - ;\
  mkdir cpprestsdk-2.9.1/Release/build ;\
  cd cpprestsdk-2.9.1/Release/build ;\
  cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=1 -DBUILD_TESTS=0 \
    -DBUILD_SAMPLES=0 -DCPPREST_EXCLUDE_WEBSOCKETS=0 \
    -DCMAKE_CXX_FLAGS="-Wno-cpp" ;\
  make VERBOSE=1 -j4 ;\
  make install ;\
  cd /src ;\
  curl -L https://github.com/OpenSC/libp11/releases/download/libp11-0.4.7/libp11-0.4.7.tar.gz \
    | tar zxpf - ;\
  cd libp11-0.4.7 ;\
  ./configure ;\
  make -j4 ;\
  make install ;\
  cd /src ;\
  git clone --depth=1 https://github.com/keyfender/p11net ;\
  mkdir p11net/build ;\
  cd p11net/build ;\
  cmake .. ;\
  make VERBOSE=1 -j4 ;\
  mv libp11net.so / ;\
  cd / ;\
  rm -rf /src ;\
  apk del \
    make \
    git \
    cmake \
    g++ \
    protobuf-dev \
    boost-dev \
    openssl-dev \
    leveldb-dev \
    ;\  
  rm -rf /var/cache/apk/*

ADD openssl.cnf /etc/ssl/
ADD nginx.conf /etc/nginx
