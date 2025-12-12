FROM gentoo/stage3:latest AS build

ENV FEATURES="-sandbox -usersandbox"
ENV CFLAGS="-O3 -pipe -march=native"
ENV USE="-threads minimal aio openssl"

RUN emerge-webrsync
RUN emerge --oneshot sys-libs/zlib

WORKDIR /usr/src
RUN wget https://nginx.org/download/nginx-1.29.4.tar.gz \
    && tar xf nginx-1.29.4.tar.gz \
    && mv nginx-1.29.4 nginx

RUN wget https://www.openssl.org/source/openssl-3.5.4.tar.gz \
    && tar xf openssl-3.5.4.tar.gz \
    && mv openssl-3.5.4 /usr/src/nginx/openssl

WORKDIR /usr/src/nginx

RUN ./configure \
    --prefix=/opt/nginx \
    --with-cc-opt="$CFLAGS" \
    --with-ld-opt="-static" \
    --with-http_ssl_module \
    --with-openssl=/usr/src/nginx/openssl \
    --without-http_rewrite_module \
    --without-http_gzip_module

RUN make -j"$(nproc)" && make install
RUN strip /opt/nginx/sbin/nginx # Strip the binary to reduce size


# Final minimal image
FROM scratch
COPY --from=build /opt/nginx /opt/nginx
COPY nginx.conf /opt/nginx/nginx.conf

COPY passwd /etc/passwd
COPY group /etc/group

EXPOSE 80
ENTRYPOINT ["/opt/nginx/sbin/nginx", "-c", "/opt/nginx/nginx.conf", "-g", "daemon off;"]

