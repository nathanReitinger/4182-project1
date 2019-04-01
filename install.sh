#!/bin/sh


sudo apt-get update
sudo apt-get upgrade

sudo apt-get install python3 -y
sudo apt-get install python3-pip -y

sudo pip3 install -r requirements.txt