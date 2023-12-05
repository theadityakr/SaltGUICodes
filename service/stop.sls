{% set service_name = salt['pillar.get']('service_name', '') %}

stop:
  cmd.run:
    - name: net stop {{ service_name}}
    - shell: powershell
    - cwd: C:\Windows\System32

