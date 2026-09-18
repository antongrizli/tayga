FROM alpine:3.20

RUN apk add --no-cache build-base linux-headers

WORKDIR /src
COPY . .

RUN make clean \
 && make CC=gcc CFLAGS='-O2' LDFLAGS='' \
 && make test
