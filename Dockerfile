FROM alpine AS build
RUN apk add build-base
WORKDIR /src
COPY . .
RUN make modbus-server

FROM alpine
COPY --from=build /src/bin/modbus-server /bin/
ENTRYPOINT [ "/bin/modbus-server" ]
EXPOSE 502