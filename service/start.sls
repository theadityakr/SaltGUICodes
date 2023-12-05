{% set service_name = salt['pillar.get']('service_name', '') %}

start:
  cmd.run:
    - name: net start {{ service_name}}
    - shell: powershell
    - cwd: C:\Windows\System32
