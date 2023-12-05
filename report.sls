all_grains: 
  cmd.script:
    - source: salt://report/all_grains.ps1
    - shell: powershell
    - cwd: C:\Windows\System32
    - args: '-ExecutionPolicy Bypass'

base_machine_grain_value:
  cmd.script:
    - source: salt://report/base_machine.ps1
    - shell: powershell
    - cwd: C:\Windows\System32
    - args: '-ExecutionPolicy Bypass'

windows_update_grain_value:
  cmd.script:
    - source: salt://report/installed_updates.ps1
    - shell: powershell
    - cwd: C:\Windows\System32
    - args: '-ExecutionPolicy Bypass'

software_grain_value:
  cmd.script:
    - source: salt://report/all_softwares.ps1
    - shell: powershell
    - cwd: C:\Windows\System32
    - args: '-ExecutionPolicy Bypass'

C:\{{grains.id}}.json:
  file.copy:
    - source: C:\1.json

delete_file1:
  file.absent:
    - name: C:\1.json

azure_upload:
  cmd.script:
    - source: salt://report/azure.ps1
    - shell: powershell
    - cwd: C:\Windows\System32
    - args: '-ExecutionPolicy Bypass'

delete_file2:
  file.absent:
    - name: C:\{{grains.id}}.json

