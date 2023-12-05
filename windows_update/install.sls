install_windows_update_module:
  cmd.run:
    - name: Install-Module -Name PSWindowsUpdate -Confirm:$false
    - shell: powershell
    - cwd: C:\Windows\System32

check_windows_update_module:
  cmd.run:
    - name: Get-Package -Name PSWindowsUpdate
    - shell: powershell
    - cwd: C:\Windows\System32

install_windows_update:
  cmd.run:
    - name: Get-WindowsUpdate -Install -Confirm:$false -IgnoreReboot
    - shell: powershell
    - cwd: C:\Windows\System32

