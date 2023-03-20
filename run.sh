#!/bin/sh
sudo sh -c '(dmesg -W &); insmod prl_exp.ko'
