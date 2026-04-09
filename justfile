honeypot-complete:
  crystal build ./src/main.cr -o cpot -Dreport_telegram -Dreport_abuse --progress

honeypot-abuse:
  crystal build ./src/main.cr -o cpot -Dreport_abuse --progress

honeypot-telegram:
  crystal build ./src/main.cr -o cpot -Dreport_telegram --progress
