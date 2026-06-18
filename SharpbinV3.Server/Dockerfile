FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /app
COPY . .
WORKDIR /app/SharpbinV3.Server
RUN dotnet restore SharpbinV3.Server.csproj
RUN dotnet publish SharpbinV3.Server.csproj -c Release -o /app/out

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app/out .
RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 10001 appuser && mkdir -p /app/data && chown -R appuser:appuser /app
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
USER appuser
ENTRYPOINT ["dotnet", "SharpbinV3.Server.dll"]
