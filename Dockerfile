FROM alpine AS build
RUN apk add build-base
WORKDIR /src
COPY . .
RUN make modbus-server && make modbus-client

FROM alpine AS final
COPY --from=build /src/bin/modbus-server /src/bin/modbus-client /bin/
ENTRYPOINT [ "/bin/modbus-server" ]
EXPOSE 502