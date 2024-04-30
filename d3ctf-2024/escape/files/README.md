# Description
This is a easy qemu escape challenge for check in, hope you will have fun in D^3 CTF 2024

# Docker

## Build

`docker build . -t d3escp`

## Run

`docker run -d -p "127.0.0.1:5555:5555" -h "d3escp" --name="d3escp" d3escp`

## Connect

`nc 127.0.0.1 5555`