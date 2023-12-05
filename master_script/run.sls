{% set script_name = salt['pillar.get']('script_name', '') %}

run_powershell_script:
  cmd.script:
    - source: salt://master_script/script_files/{{script_name}}.ps1
    - shell: powershell
    - cwd: C:\Windows\System32
    - args: '-ExecutionPolicy Bypass'

