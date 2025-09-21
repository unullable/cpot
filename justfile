honeypot:
 crystal build ./src/main.cr -o cpot --progress

honeypot-report:
 crystal build ./src/main.cr -o cpot -Dreport_abuse --progress
