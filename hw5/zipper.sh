#!/bin/sh


mkdir module
cp hw5secws.c module
cp Makefile module

mkdir user
cp main.py user

mkdir c_detection
cp classifier.py http_traffic_scraper.py http.py *.har c_code.txt smtp.py c_detection

mkdir ftp
cp ftp.py ftp

mkdir ips
cp superset_ips.py ips

zip -r 214166027.zip module user mitm.py c_detection ftp ips *.pptx documentation.txt


rm -r module user ips ftp c_detection
