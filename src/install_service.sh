#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

FILENAME="/etc/systemd/system/mro_watcher.service"

cat >$FILENAME <<EOF
[Unit]
Description=MRO watcher
After=multi-user.target
ConditionPathExists=/home/panthyr/.local/bin/mro_watcher
[Service]
WorkingDirectory=/home/panthyr
Type=simple
User=panthyr
ExecStart=/bin/bash -c '/home/panthyr/.local/bin/mro_watcher'
# append only works starting at systemd 240
StandardOutput=append:/home/panthyr/data/logs/service_mro_watcher_stdout.log
StandardError=append:/home/panthyr/data/logs/service_mro_watcher_stderr.log
Restart=always
RestartSec=300s
[Install
WantedBy=multi-user.target
Alias=p_worker
EOF

chmod 644 $FILENAME

echo "Created service file $FILENAME"

systemctl daemon-reload && systemctl enable mro_watcher.service && systemctl start mro_watcher.service

echo "Status: "
systemctl status mro_watcher.service