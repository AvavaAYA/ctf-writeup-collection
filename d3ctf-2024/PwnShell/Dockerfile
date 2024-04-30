FROM php:8.3-apache
RUN apt-get update
RUN apt-get upgrade -y
RUN DEBIAN_FRONTEND=noninteractive
RUN apt install vim gdbserver -y

COPY ./stuff/php.ini /usr/local/etc/php
COPY ./stuff/vuln.so /usr/local/lib/php/extensions/no-debug-non-zts-20230831
COPY ./stuff/readflag /
COPY ./flag.txt /flag.txt
COPY ./stuff/index.php /var/www/html
RUN chmod 400 /flag.txt
RUN chmod u+sx /readflag
RUN chmod -R 777 /var/www/html
