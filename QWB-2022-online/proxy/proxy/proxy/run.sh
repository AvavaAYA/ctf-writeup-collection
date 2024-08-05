docker build -t "proxy" .
docker run -d -p "0.0.0.0:1080:1080" -h "proxy" --name="proxy" proxy
