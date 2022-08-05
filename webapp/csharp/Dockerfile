# https://hub.docker.com/_/microsoft-dotnet
FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /source

# copy csproj and restore as distinct layers
COPY ./*.csproj ./
RUN dotnet restore

# copy everything else and build app    
COPY ./. ./
RUN dotnet publish -c release -o /app --no-restore

# final stage/image
FROM mcr.microsoft.com/dotnet/aspnet:7.0
WORKDIR /tmp
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
  apt-get -y upgrade && \
  apt-get install -y wget gcc g++ make sqlite3 && \
  wget -q https://dev.mysql.com/get/mysql-apt-config_0.8.22-1_all.deb && \
  apt-get -y install ./mysql-apt-config_*_all.deb && \
  apt-get -y update && \
  apt-get -y install mysql-client

RUN useradd --uid=1001 --create-home isucon
USER isucon

RUN mkdir -p /home/isucon/webapp/go
WORKDIR /home/isucon/webapp/csharp
COPY --from=build /app ./
ENTRYPOINT ["dotnet", "csharp.dll"]