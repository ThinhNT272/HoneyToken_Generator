param (
    [string]$DecoyConfigPath = "\\DC01\Public\decoys.json"
)

$ErrorActionPreference = 'SilentlyContinue'

# Name prefix for all honey-token scheduled tasks
$TASK_PREFIX = "HoneyToken_"

# C# definition to access LsaAddAccountRights Win32 API
$CSharp = @"
using System;using System.Runtime.InteropServices;
public class Ls {
[DllImport("advapi32.dll")]public static extern uint LsaOpenPolicy(IntPtr s,IntPtr o,uint a,out IntPtr h);
[DllImport("advapi32.dll")]public static extern uint LsaAddAccountRights(IntPtr h,IntPtr sid,L_S[] r,uint c);
[DllImport("advapi32.dll")]public static extern uint LsaClose(IntPtr h);
[StructLayout(LayoutKind.Sequential)]public struct L_S {public ushort l;public ushort m;public IntPtr b;}
}
"@

if (-not ("Ls" -as [type])) { Add-Type -TypeDefinition $CSharp }

function Grant-BatchLogonRight {
    param([string]$AccountName)
    try {
        $Account = New-Object System.Security.Principal.NTAccount($AccountName)
        $SID = $Account.Translate([System.Security.Principal.SecurityIdentifier])
        
        $sidBytes = New-Object byte[] $SID.BinaryLength
        $SID.GetBinaryForm($sidBytes, 0)
        
        $SidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SID.BinaryLength)
        [System.Runtime.InteropServices.Marshal]::Copy($sidBytes, 0, $SidPtr, $SID.BinaryLength)

        $PolicyHandle = [IntPtr]::Zero
        $access = 0x000F0811
        $res = [Ls]::LsaOpenPolicy([IntPtr]::Zero, [IntPtr]::Zero, $access, [ref]$PolicyHandle)
        if ($res -ne 0) { throw "LsaOpenPolicy failed: $res" }

        $Right = "SeBatchLogonRight"
        $r = New-Object Ls+L_S
        $r.b = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($Right)
        $r.l = [ushort]($Right.Length * 2)
        $r.m = [ushort](($Right.Length + 1) * 2)

        $res = [Ls]::LsaAddAccountRights($PolicyHandle, $SidPtr, [Ls+L_S[]]@($r), 1)
        [void][Ls]::LsaClose($PolicyHandle)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($SidPtr)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($r.b)
        
        if ($res -ne 0) { throw "LsaAddAccountRights failed: $res" }
    } catch {
        Write-Warning "Failed to grant SeBatchLogonRight: $_"
    }
}

# 1. Read configuration from share
$DecoysToInject = @()
if (Test-Path $DecoyConfigPath) {
    try {
        $Config = Get-Content $DecoyConfigPath -Raw | ConvertFrom-Json
        # Read all decoys from config
        if ($Config.decoys) {
            $DecoysToInject = $Config.decoys
        }
    } catch {
        # Treat as empty on parse failure
    }
}

# 2. Get currently registered HoneyToken tasks on this workstation
$CurrentTasks = Get-ScheduledTask -TaskPath "\" -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "$TASK_PREFIX*" }

# 3. Clean up unassigned tasks (tasks that are not in the current decoys list)
foreach ($task in $CurrentTasks) {
    $decoyName = $task.TaskName.Substring($TASK_PREFIX.Length)
    $stillAssigned = $DecoysToInject | Where-Object { $_.username -eq $decoyName }
    
    if (-not $stillAssigned) {
        Stop-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Output "Removed stale decoy task: $($task.TaskName)"
    }
}

# 4. Inject assigned decoys
if ($DecoysToInject) {
    # Resolve local domain
    $DomainName = $env:USERDNSDOMAIN
    if (-not $DomainName) {
        $DomainName = (Get-WmiObject Win32_ComputerSystem).Domain
    }

    foreach ($decoy in $DecoysToInject) {
        $taskName = "$TASK_PREFIX$($decoy.username)"
        $runAsUser = "$DomainName\$($decoy.username)"
        $password = $decoy.password
        
        # Check if the task already exists and is running
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask -and $existingTask.State -eq 'Running') {
            continue # Already running, skip
        }

        # Grant logon privilege
        Grant-BatchLogonRight -AccountName $runAsUser

        # Register Scheduled Task
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -NoProfile -Command "while(1){Start-Sleep 3600}"'
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $taskName -Action $action -Settings $settings -User $runAsUser -Password $password -RunLevel Limited -ErrorAction SilentlyContinue | Out-Null
        Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        
        Write-Output "Successfully injected decoy: $runAsUser (Task: $taskName)"
    }
}
