**How to use auto-update-os**

**Use at your own risk - automatically triggering an unattended OS update might be considered stupid**

Copy the two systemd files into /etc/systemd/system

Enable the service with:  sudo systemd enable auto-update-os.service
Start the service (this can be sone at anytime to trigger an update) with:  sudo systemd start auto-update-os.service

**Remember: You won't see any information from the update process, so you cannot check the build files or easily cancel the update - hence, Stupid!!**
