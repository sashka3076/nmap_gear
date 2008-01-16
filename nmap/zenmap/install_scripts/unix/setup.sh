#!/bin/sh -e

echo "Updating/Creating dumped operating system list..."
python install_scripts/utils/create_os_list.py

echo "Updating/Creating dumped services list..."
python install_scripts/utils/create_services_dump.py
