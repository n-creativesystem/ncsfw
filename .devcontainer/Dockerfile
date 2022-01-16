FROM scratch as client

ENV DOCKER_CLIENT_VERSION=19.03.8
ENV DOCKER_API_VERSION=1.40
ADD https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLIENT_VERSION}.tgz .

FROM golang:1.16-buster
ENV TZ=Asia/Tokyo
ARG ARG_DOCKER_CLIENT_VERSION=19.03.8

ENV DOCKER_CLIENT_VERSION=${ARG_DOCKER_CLIENT_VERSION}
ENV DOCKER_API_VERSION=1.40
COPY --from=client docker-${DOCKER_CLIENT_VERSION}.tgz .

RUN curl -fsSL https://deb.nodesource.com/setup_16.x | bash \
    && apt-get install -y nodejs \
    && curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add \
    && echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list \
    && apt-get update \
    && apt-get install -y yarn \
    && yarn global add @vue/cli

RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata protobuf-compiler \
    && cp /usr/share/zoneinfo/Asia/Tokyo /etc/localtime \
    && echo "Asia/Tokyo" >  /etc/timezone \
    && tar xzvf docker-${DOCKER_CLIENT_VERSION}.tgz \
    && mv docker/* /usr/bin/ \
    && rm -rf docker-${DOCKER_CLIENT_VERSION}.tgz \
    && rm -rf /var/lib/apt/lists/* \
    && go install github.com/uudashr/gopkgs/v2/cmd/gopkgs@latest \
    && go install github.com/ramya-rao-a/go-outline@latest \
    && go install github.com/cweill/gotests/gotests@latest \
    && go install github.com/fatih/gomodifytags@latest \
    && go install github.com/josharian/impl@latest \
    && go install github.com/haya14busa/goplay/cmd/goplay@latest \
    && go install github.com/go-delve/delve/cmd/dlv@latest \
    && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest \
    && go install golang.org/x/tools/gopls@latest \
    && go install google.golang.org/protobuf/cmd/protoc-gen-go@latest \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest \
    && go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest

WORKDIR /src/

CMD [ "sh" ]