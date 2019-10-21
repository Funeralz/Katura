clear
zmap -p8088 -wyarn.lst -olist
ulimit -n 999999
python xx.py list
sh roots.sh