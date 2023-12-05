base:
  '*':
    - commands.ipconfig
    - commands.ipco
    - windows_update.download
    - windows_update.install
    - service.start
    - service.stop
    - master_script.run
