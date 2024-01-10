defmodule PowerShelldle.Commands do
  @type command() :: %{
          name: String.t(),
          description: String.t(),
          params: String.t()
        }

  @commands [
    %{
      description: "Gets the security descriptor for a resource, such as a file or registry key.",
      name: "Get-Acl",
      params:
        "[-AllCentralAccessPolicies] [-Audit] [-Exclude <String[]>] [-Filter <String>] [-Include <String[]>]-InputObject* <PSObject> [-UseTransaction] [<CommonParameters>]"
    },
    %{
      description: "Sorts objects by property values.",
      name: "Sort-Object",
      params:
        "Sort-Object [[-Property] <Object[]>] [-CaseSensitive] [-Culture <String>] [-Descending] [-InputObject <PSObject>][-Unique] [<CommonParameters>]"
    },
    %{
      description:
        "Specifies how Windows PowerShell handles information stream data for a\n\n        command.",
      name: "Write-Information",
      params: "[-MessageData*] <Object> [[-Tags] <String[]>] [<CommonParameters>]"
    },
    %{
      description: "Retrieves the SMB shares on the computer.",
      name: "Get-SmbShare",
      params:
        "[[-Name] <String[]>] [[-ScopeName] <String[]>] [-AvailabilityType <AvailabilityType[]>] [-CachingMode<CachingMode[]>] [-CaTimeout <UInt32[]>] [-CimSession <CimSession[]>] [-ConcurrentUserLimit <UInt32[]>][-ContinuouslyAvailable <Boolean[]>] [-EncryptData <Boolean[]>] [-FolderEnumerationMode <FolderEnumerationMode[]>][-IncludeHidden] [-Scoped <Boolean[]>] [-ShareState <ShareState[]>] [-SmbInstance {Default | CSV}] [-Special<Boolean[]>] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Imports the layout of the Start into a mounted Windows image.",
      name: "Import-StartLayout",
      params:
        "[-LayoutPath*] <String> [-MountPath*] <String> [-InformationAction {SilentlyContinue | Stop |Continue | Inquire | Ignore | Suspend}] [-InformationVariable <System.String>] [-Confirm] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Compares two sets of objects.",
      name: "Compare-Object",
      params:
        "[-ReferenceObject*] <PSObject[]> [-DifferenceObject*] <PSObject[]> [-CaseSensitive] [-Culture<String>] [-ExcludeDifferent] [-IncludeEqual] [-PassThru] [-Property <Object[]>] [-SyncWindow <Int32>][<CommonParameters>]"
    },
    %{
      description: "Suspends Bitlocker encryption for the specified volume.",
      name: "Suspend-BitLocker",
      params:
        "[-MountPoint*] <String[]> [[-RebootCount] <Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Stops (shuts down) local and remote computers.",
      name: "Stop-Computer",
      params:
        "[[-ComputerName] <String[]>] [[-Credential] <PSCredential>] [-AsJob] [-Confirm] [-DcomAuthentication{Default | None | Connect | Call | Packet | PacketIntegrity | PacketPrivacy | Unchanged}] [-Force] [-Impersonation{Default | Anonymous | Identify | Impersonate | Delegate}] [-Protocol {DCOM | WSMan}] [-ThrottleLimit <Int32>][-WhatIf] [-WsmanAuthentication {Default | Basic | Negotiate | CredSSP | Digest | Kerberos}] [<CommonParameters>]"
    },
    %{
      description: "Gets an object that contains information about a TPM.",
      name: "Get-Tpm",
      params: "[<CommonParameters>]"
    },
    %{
      description:
        "Takes a Disk object or unique disk identifiers and a set of attributes, and\n\n        updates the physical disk on thesystem.",
      name: "Set-Disk",
      params:
        "[-Number*] <UInt32> [-CimSession <CimSession[]>] [-Guid <String>] [-IsReadOnly <Boolean>] [-Signature<UInt32>] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Gets the hotfixes that have been applied to the local and remote computers.",
      name: "Get-HotFix",
      params:
        "[-ComputerName <String[]>] [-Credential <PSCredential>] [-Description <String[]>] [<CommonParameters>]"
    },
    %{
      description: "Adds a signed app package to a user account.",
      name: "Add-AppxPackage",
      params:
        "[-DependencyPackages <String[]>] [-ForceApplicationShutdown] [-ForceTargetApplicationShutdown][-InstallAllResources] -MainPackage* <String> [-Register*] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Runs commands or expressions on the local computer.",
      name: "Invoke-Expression",
      params: "[-Command*] <String> [<CommonParameters>]"
    },
    %{
      description: "Creates a job trigger for a scheduled job.",
      name: "New-JobTrigger",
      params:
        "[-Once*] -At* <DateTime> [-RandomDelay <TimeSpan>] [-RepeatIndefinitely] [-RepetitionDuration<TimeSpan>] [-RepetitionInterval <TimeSpan>] [<CommonParameters>]"
    },
    %{
      description: "Unblocks files that were downloaded from the Internet.",
      name: "Unblock-File",
      params: "[-Confirm] -LiteralPath* <String[]> [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Turns script debugging features on and off, sets the trace level, and toggles\n\n        strict mode.",
      name: "Set-PSDebug",
      params: "[-Step] [-Strict] [-Trace <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Returns information about PnP devices.",
      name: "Get-PnpDevice",
      params:
        "[[-InstanceId] <String[]>] [-CimSession <CimSession[]>] [-Class <String[]>] [-InformationAction{SilentlyContinue | Stop | Continue | Inquire | Ignore | Suspend}] [-InformationVariable <System.String]>][-PresentOnly] [-Status {OK | ERROR | DEGRADED | UNKNOWN}] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Starts a Windows PowerShell background job.",
      name: "Start-Job",
      params:
        "[-ScriptBlock*] <ScriptBlock> [[-InitializationScript] <ScriptBlock>] [-ArgumentList <Object[]>][-Authentication {Default | Basic | Negotiate | NegotiateWithImplicitCredential | Credssp | Digest | Kerberos}][-Credential <PSCredential>] [-InputObject <PSObject>] [-Name <String>] [-PSVersion <Version>] [-RunAs32][<CommonParameters>]"
    },
    %{
      description: "Starts, stops, and suspends a service, and changes its properties.",
      name: "Set-Service",
      params:
        "[-ComputerName <String[]>] [-Confirm] [-Description <String>] [-DisplayName <String>] [-InputObject<ServiceController>] [-PassThru] [-StartupType {Boot | System | Automatic | Manual | Disabled}] [-Status {Running| Stopped | Paused}] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Replaces the contents of a file with contents that you specify.",
      name: "Set-Content",
      params:
        "[-Value*] <Object[]> [-Confirm] [-Credential <PSCredential>] [-Encoding {Unknown | String | Unicode |Byte | BigEndianUnicode | UTF8 | UTF7 | UTF32 | Ascii | Default | Oem | BigEndianUTF32}] [-Exclude <String[]>][-Filter <String>] [-Force] [-Include <String[]>] -LiteralPath* <String[]> [-NoNewline] [-PassThru] [-Stream<String>] [-UseTransaction] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Finds text in an XML string or document.",
      name: "Select-Xml",
      params:
        "[-XPath*] <String> -Content* <String[]> [-Namespace <Hashtable>] [<CommonParameters>]"
    },
    %{
      description: "Gets the services on a local or remote computer.",
      name: "Get-Service",
      params:
        "[-ComputerName <String[]>] [-DependentServices] -DisplayName* <String[]> [-Exclude <String[]>][-Include <String[]>] [-RequiredServices] [<CommonParameters>]"
    },
    %{
      description: "Retrieves the specified VPN connection profile information.",
      name: "Get-VpnConnection",
      params:
        "[[-Name] <String[]>] [-AllUserConnection] [-CimSession <CimSession[]>] [-ThrottleLimit <Int32>][<CommonParameters>]"
    },
    %{
      description: "Gets the properties and methods of objects.",
      name: "Get-Member",
      params:
        "[[-Name] <String[]>] [-Force] [-InputObject <PSObject>] [-MemberType {AliasProperty | CodeProperty |Property | NoteProperty | ScriptProperty | Properties | PropertySet | Method | CodeMethod | ScriptMethod | Methods| ParameterizedProperty | MemberSet | Event | Dynamic | All}] [-Static] [-View {Extended | Adapted | Base | All}][<CommonParameters>]"
    },
    %{
      description: "Deletes the contents of an item, but does not delete the item.",
      name: "Clear-Content",
      params:
        "[-Confirm] [-Credential <PSCredential>] [-Exclude <String[]>] [-Filter <String>] [-Force] [-Include<String[]>] -LiteralPath* <String[]> [-Stream <String>] [-UseTransaction] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Sends output to the command line.",
      name: "Out-Host",
      params: "[-InputObject <PSObject>] [-Paging] [<CommonParameters>]"
    },
    %{
      description: "Gets information about .pfx certificate files on the computer.",
      name: "Get-PfxCertificate",
      params: "[-FilePath*] <String[]> [<CommonParameters>]"
    },
    %{
      description:
        "Converts Microsoft .NET Framework objects into HTML that can be displayed in a\n\n        Web browser.",
      name: "ConvertTo-Html",
      params:
        "[[-Property] <Object[]>] [[-Head] <String[]>] [[-Title] <String>] [[-Body] <String[]>] [-As {Table| List}] [-CssUri <Uri>] [-InputObject <PSObject>] [-PostContent <String[]>] [-PreContent <String[]>][<CommonParameters>]"
    },
    %{
      description:
        "Converts objects into a series of comma-separated (CSV) strings and saves the\n\n        strings in a CSV file.",
      name: "Export-Csv",
      params:
        "[[-Path] <String>] [[-Delimiter] <Char>] [-Append] [-Confirm] [-Encoding {Unicode | UTF7 | UTF8 | ASCII| UTF32 | BigEndianUnicode | Default | OEM}] [-Force] -InputObject* <PSObject> [-LiteralPath <String>] [-NoClobber][-NoTypeInformation] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Creates or updates an instance of an existing Windows Management\n\n        Instrumentation (WMI) class.",
      name: "Set-WmiInstance",
      params:
        "[-Class*] <String> [-Arguments <Hashtable>] [-AsJob] [-Authentication {Default | None | Connect |Call | Packet | PacketIntegrity | PacketPrivacy | Unchanged}] [-Authority <String>] [-ComputerName <String[]>][-Confirm] [-Credential <PSCredential>] [-EnableAllPrivileges] [-Impersonation {Default | Anonymous | Identify |Impersonate | Delegate}] [-Locale <String>] [-Namespace <String>] [-PutType {None | UpdateOnly | CreateOnly |UpdateOrCreate}] [-ThrottleLimit <Int32>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Converts a secure string to an encrypted standard string.",
      name: "ConvertFrom-SecureString",
      params: "[-SecureString*] <SecureString> [-Key <Byte[]>] [<CommonParameters>]"
    },
    %{
      description:
        "Converts object properties in comma-separated value (CSV) format into CSV\n\n        versions of the original objects.",
      name: "ConvertFrom-Csv",
      params:
        "[-InputObject*] <PSObject[]> [[-Delimiter] <Char>] [-Header <String[]>] [<CommonParameters>]"
    },
    %{
      description: "Gets a random number, or selects objects randomly from a collection.",
      name: "Get-Random",
      params:
        "[-InputObject*] <Object[]> [-Count <Int32>] [-SetSeed <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Applies configuration to nodes.",
      name: "Start-DscConfiguration",
      params:
        "[[-Path] <String>] -CimSession* <CimSession[]> [-Confirm] [-Force] [-JobName <String>][-ThrottleLimit <Int32>] [-Wait] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Modifies an IP interface.",
      name: "Set-NetIPInterface",
      params:
        "[[-InterfaceAlias] <String[]>] [-AddressFamily <AddressFamily[]>] [-AdvertiseDefaultRoute{Disabled | Enabled}] [-AdvertisedRouterLifetime <TimeSpan>] [-Advertising {Disabled | Enabled}] [-AutomaticMetric{Disabled | Enabled}] [-BaseReachableTimeMs <UInt32>] [-CimSession <CimSession[]>] [-ClampMss {Disabled |Enabled}] [-CompartmentId <UInt32[]>] [-CurrentHopLimit <UInt32>] [-DadRetransmitTimeMs <UInt32>] [-DadTransmits<UInt32>] [-Dhcp {Disabled | Enabled}] [-DirectedMacWolPattern {Disabled | Enabled}] [-EcnMarking {Disabled |UseEct1 | UseEct0 | AppDecide}] [-ForceArpNdWolPattern {Disabled | Enabled}] [-Forwarding {Disabled | Enabled}][-IgnoreDefaultRoutes {Disabled | Enabled}] [-IncludeAllCompartments] [-InterfaceIndex <UInt32[]>][-InterfaceMetric <UInt32>] [-ManagedAddressConfiguration {Disabled | Enabled}] [-NeighborDiscoverySupported<NeighborDiscoverySupported[]>] [-NeighborUnreachabilityDetection {Disabled | Enabled}] [-NlMtuBytes <UInt32>][-OtherStatefulConfiguration {Disabled | Enabled}] [-PassThru] [-PolicyStore <String>] [-ReachableTime <UInt32[]>][-RetransmitTimeMs <UInt32>] [-RouterDiscovery {Disabled | Enabled | ControlledByDHCP}] [-ThrottleLimit <Int32>][-WeakHostReceive {Disabled | Enabled}] [-WeakHostSend {Disabled | Enabled}] [-Confirm] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Sends an HTTP or HTTPS request to a RESTful web service.",
      name: "Invoke-RestMethod",
      params:
        "[-Uri*] <Uri> [-Body <Object>] [-Certificate <X509Certificate>] [-CertificateThumbprint <String>][-ContentType <String>] [-Credential <PSCredential>] [-DisableKeepAlive] [-Headers <IDictionary>] [-InFile<String>] [-MaximumRedirection <Int32>] [-Method {Default | Get | Head | Post | Put | Delete | Trace | Options |Merge | Patch}] [-OutFile <String>] [-PassThru] [-Proxy <Uri>] [-ProxyCredential <PSCredential>][-ProxyUseDefaultCredentials] [-SessionVariable <String>] [-TimeoutSec <Int32>] [-TransferEncoding {chunked |compress | deflate | gzip | identity}] [-UseBasicParsing] [-UseDefaultCredentials] [-UserAgent <String>][-WebSession <WebRequestSession>] [<CommonParameters>]"
    },
    %{
      description: "Gets a credential object based on a user name and password.",
      name: "Get-Credential",
      params: "[-Credential*] <PSCredential> [<CommonParameters>]"
    },
    %{
      description: "Gets files and folders.",
      name: "Get-Item",
      params:
        "[-Credential <PSCredential>] [-Exclude <String[]>] [-Filter <String>] [-Force] [-Include <String[]>]-LiteralPath* <String[]> [-Stream <String[]>] [-UseTransaction] [<CommonParameters>]"
    },
    %{
      description: "Gets a list of the app packages that are installed in a user profile.",
      name: "Get-AppxPackage",
      params:
        "[[-Name] <String>] [[-Publisher] <String>] [-AllUsers] [-PackageTypeFilter {None | Main |Framework | Resource | Bundle | Xap}] [-User <String>] [-Volume <AppxVolume>] [<CommonParameters>]"
    },
    %{
      description: "Gets drives in the current session.",
      name: "Get-PSDrive",
      params:
        "[-LiteralName*] <String[]> [-PSProvider <String[]>] [-Scope <String>] [-UseTransaction][<CommonParameters>]"
    },
    %{
      description: "Sets the basic network adapter properties.",
      name: "Set-NetAdapter",
      params:
        "[-Name*] <String[]> [-AsJob] [-CimSession <CimSession[]>] [-IncludeHidden] [-MacAddress <String>][-NoRestart] [-PassThru] [-ThrottleLimit <Int32>] [-VlanID <UInt16>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Clears the display in the host program.",
      name: "Clear-Host",
      params: "[<CommonParameters>]"
    },
    %{
      description: "Finds modules from an online gallery that match specified criteria.",
      name: "Find-Module",
      params:
        "[[-Name] <String[]>] [-AllVersions] [-Command <String[]>] [-Credential <PSCredential>] [-DscResource<String[]>] [-Filter <String>] [-IncludeDependencies] [-Includes {DscResource | Cmdlet | Function |RoleCapability}] [-MaximumVersion <Version>] [-MinimumVersion <Version>] [-Proxy <Uri>] [-ProxyCredential<PSCredential>] [-Repository <String[]>] [-RequiredVersion <Version>] [-RoleCapability <String[]>] [-Tag<String[]>] [<CommonParameters>]"
    },
    %{
      description: "Disables a feature in a Windows image.",
      name: "Disable-WindowsOptionalFeature",
      params:
        "[-LogLevel {Errors | Warnings | WarningsInfo}] [-LogPath <String>] [-NoRestart][-PackageName <String>] [-Remove] [-ScratchDirectory <String>] [-SystemDrive <String>] [-WindowsDirectory<String>] -FeatureName* <String[]> -Online* [<CommonParameters>]"
    },
    %{
      description:
        "Exports a certificate or a PFXData object to a Personal Information Exchange\n\n        (PFX) file.",
      name: "Export-PfxCertificate",
      params:
        "[-Cert*] <Certificate> [-FilePath*] <String> [-ChainOption {BuildChain | EndEntityCertOnly |PfxDataOnly}] [-Force] [-NoClobber] [-NoProperties] [-Password <SecureString>] [-ProtectTo <String[]>] [-Confirm][-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Creates a route in the IP routing table.",
      name: "New-NetRoute",
      params:
        "[-DestinationPrefix*] <String> [-AddressFamily {IPv4 | IPv6}] [-CimSession <CimSession[]>] [-NextHop<String>] [-PolicyStore <String>] [-PreferredLifetime <TimeSpan>] [-Protocol {Other | Local | NetMgmt | Icmp | Egp| Ggp | Hello | Rip | IsIs | EsIs | Igrp | Bbn | Ospf | Bgp | Idpr | Eigrp | Dvmrp | Rpl | Dhcp}] [-Publish {No |Age | Yes}] [-RouteMetric <UInt16>] [-ThrottleLimit <Int32>] [-ValidLifetime <TimeSpan>] -InterfaceAlias* <String>[-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Returns a list of all software packages that have been installed by using\n\n        Package Management.",
      name: "Get-Package",
      params:
        "[[-Name] <String[]>] [-AdditionalArguments <String[]>] [-AllVersions] [-Force] [-ForceBootstrap][-MaximumVersion <String>] [-MinimumVersion <String>] [-ProviderName {msi | NuGet | msu | Programs | PowerShellGet| psl | chocolatey}] [-RequiredVersion <String>] [<CommonParameters>]"
    },
    %{
      description:
        "Saves command output in a file or variable and also sends it down the\n\n        pipeline.",
      name: "Tee-Object",
      params: "[-FilePath*] <String> [-Append] [-InputObject <PSObject>] [<CommonParameters>]"
    },
    %{
      description: "Adds a single .cab or .msu file to a Windows image.",
      name: "Add-WindowsPackage",
      params:
        "[-IgnoreCheck] [-LogLevel {Errors | Warnings | WarningsInfo}] [-LogPath <String>] [-NoRestart][-PreventPending] [-ScratchDirectory <String>] [-SystemDrive <String>] [-WindowsDirectory <String>] -Online*-PackagePath* <String> [<CommonParameters>]"
    },
    %{
      description: "Converts an object to a JSON-formatted string.",
      name: "ConvertTo-Json",
      params: "[-InputObject*] <Object> [-Compress] [-Depth <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Gets local user accounts.",
      name: "Get-LocalUser",
      params: "[[-Name] <String[]>] [<CommonParameters>]"
    },
    %{
      description: "Resolves the wildcard characters in a path, and displays the path contents.",
      name: "Resolve-Path",
      params:
        "[-Credential <PSCredential>] -LiteralPath* <String[]> [-Relative] [-UseTransaction][<CommonParameters>]"
    },
    %{
      description: "Gets Windows capabilities for an image or a running operating system.",
      name: "Get-WindowsCapability",
      params:
        "[-LogLevel {Errors | Warnings | WarningsInfo}] [-LogPath <String>] [-Name <String>][-ScratchDirectory <String>] [-SystemDrive <String>] [-WindowsDirectory <String>] -Path* <String>[<CommonParameters>]"
    },
    %{
      description:
        "Sends the specified objects to the next command in the pipeline. If the\n\n        command is the last command in thepipeline, the objects are displayed in the console.",
      name: "Write-Output",
      params: "[-InputObject*] <PSObject[]> [-NoEnumerate] [<CommonParameters>]"
    },
    %{
      description:
        "Cleans a disk by removing all partition information and un-initializing it,\n\n        erasing all data on the disk.",
      name: "Clear-Disk",
      params:
        "[-Number*] <UInt32[]> [-CimSession <CimSession[]>] [-PassThru] [-RemoveData] [-RemoveOEM][-ThrottleLimit <Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Formats the output as a list of properties in which each property appears on a\n\n        new line.",
      name: "Format-List",
      params:
        "[[-Property] <Object[]>] [-DisplayError] [-Expand {CoreOnly | EnumOnly | Both}] [-Force] [-GroupBy<Object>] [-InputObject <PSObject>] [-ShowError] [-View <String>] [<CommonParameters>]"
    },
    %{
      description: "Groups objects that contain the same value for specified properties.",
      name: "Group-Object",
      params:
        "[[-Property] <Object[]>] [-AsHashTable] [-AsString] [-CaseSensitive] [-Culture <String>][-InputObject <PSObject>] [-NoElement] [<CommonParameters>]"
    },
    %{
      description: "Retrieves the SMB server configuration.",
      name: "Get-SmbServerConfiguration",
      params:
        "[-CimSession <CimSession[]>] [-ThrottleLimit <Int32>] [-Confirm] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Gets the list of cipher suites for TLS for a computer.",
      name: "Get-TlsCipherSuite",
      params: "[[-Name] <String>] [<CommonParameters>]"
    },
    %{
      description:
        "Subscribes to the events that are generated by a Microsoft .NET Framework\n\n        object.",
      name: "Register-ObjectEvent",
      params:
        "[-InputObject*] <PSObject> [-EventName*] <String> [[-SourceIdentifier] <String>] [[-Action]<ScriptBlock>] [-Forward] [-MaxTriggerCount <Int32>] [-MessageData <PSObject>] [-SupportEvent] [<CommonParameters>]"
    },
    %{
      description: "Starts one or more instances of a scheduled task.",
      name: "Start-ScheduledTask",
      params:
        "[-TaskName*] <String> [[-TaskPath] <String>] [-CimSession <CimSession[]>] [-ThrottleLimit<Int32>] [<CommonParameters>]"
    },
    %{
      description:
        "Converts objects into a series of comma-separated value (CSV) variable-length\n\n        strings.",
      name: "ConvertTo-Csv",
      params:
        "ConvertTo-Csv [-InputObject*] <PSObject> [[-Delimiter] <Char>] [-NoTypeInformation] [<CommonParameters>]"
    },
    %{
      description: "Waits for the processes to be stopped before accepting more input.",
      name: "Wait-Process",
      params: "[-Id*] <Int32[]> [[-Timeout] <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Configures the computer to receive remote commands.",
      name: "Enable-PSRemoting",
      params: "[-Confirm] [-Force] [-SkipNetworkProfileCheck] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Changes the value of an item to the value specified in the command.",
      name: "Set-Item",
      params:
        "[[-Value] <Object>] [-Confirm] [-Credential <PSCredential>] [-Exclude <String[]>] [-Filter <String>][-Force] [-Include <String[]>] -LiteralPath* <String[]> [-PassThru] [-UseTransaction] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Writes customized output to a host.",
      name: "Write-Host",
      params:
        "[[-Object] <Object>] [-BackgroundColor {Black | DarkBlue | DarkGreen | DarkCyan | DarkRed | DarkMagenta| DarkYellow | Gray | DarkGray | Blue | Green | Cyan | Red | Magenta | Yellow | White}] [-ForegroundColor {Black |DarkBlue | DarkGreen | DarkCyan | DarkRed | DarkMagenta | DarkYellow | Gray | DarkGray | Blue | Green | Cyan | Red| Magenta | Yellow | White}] [-NoNewline] [-Separator <Object>] [<CommonParameters>]"
    },
    %{
      description: "Creates a new self-signed certificate for testing purposes.",
      name: "New-SelfSignedCertificate",
      params:
        "[-AlternateSignatureAlgorithm] [-CertStoreLocation <String>] [-CloneCert <Certificate>][-Container <System.String>] [-CurveExport {None | CurveParameters | CurveName}] [-DnsName <String[]>][-ExistingKey] [-Extension <System.Security.Cryptography.X509Certificates.X509Extension[]>] [-FriendlyName<System.String>] [-HardwareKeyUsage <Microsoft.CertificateServices.Commands.HardwareKeyUsage[]>] [-HashAlgorithm<System.String>] [-KeyAlgorithm <System.String>] [-KeyDescription <System.String>] [-KeyExportPolicy<Microsoft.CertificateServices.Commands.KeyExportPolicy[]>] [-KeyFriendlyName <System.String>] [-KeyLength<System.Int32>] [-KeyLocation <System.String>] [-KeyProtection<Microsoft.CertificateServices.Commands.KeyProtection[]>] [-KeySpec {None | KeyExchange | Signature}] [-KeyUsage<Microsoft.CertificateServices.Commands.KeyUsage[]>] [-KeyUsageProperty<Microsoft.CertificateServices.Commands.KeyUsageProperty[]>] [-NotAfter <System.DateTime>] [-NotBefore<System.DateTime>] [-Pin <System.Security.SecureString>] [-Provider <System.String>] [-Reader <System.String>][-SecurityDescriptor <System.Security.AccessControl.FileSecurity>] [-SerialNumber <System.String>] [-Signer<Microsoft.CertificateServices.Commands.Certificate>] [-SignerPin <System.Security.SecureString>] [-SignerReader<System.String>] [-SmimeCapabilities] [-Subject <System.String>] [-SuppressOid <System.String[]>] [-TestRoot][-TextExtension <System.String[]>] [-Type {Custom | CodeSigningCert | DocumentEncryptionCert |SSLServerAuthentication | DocumentEncryptionCertLegacyCsp}] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Creates a new property for an item and sets its value.",
      name: "New-ItemProperty",
      params:
        "[-Name*] <String> [-Confirm] [-Credential <PSCredential>] [-Exclude <String[]>] [-Filter <String>][-Force] [-Include <String[]>] -LiteralPath* <String[]> [-PropertyType <String>] [-UseTransaction] [-Value<Object>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Gets the CIM instances of a class from a CIM server.",
      name: "Get-CimInstance",
      params:
        "[-ClassName*] <String> [-ComputerName <String[]>] [-Filter <String>] [-KeyOnly] [-Namespace<String>] [-OperationTimeoutSec <UInt32>] [-Property <String[]>] [-Query*Dialect <String>] [-Shallow][<CommonParameters>]"
    },
    %{
      description: "Removes modules from the current session.",
      name: "Remove-Module",
      params:
        "[-FullyQualifiedName*] <ModuleSpecification[]> [-Confirm] [-Force] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Converts encrypted standard strings to secure strings. It can also convert\n\n        plain text to secure strings. It isused with ConvertFrom-SecureString and Read-Host.",
      name: "ConvertTo-SecureString",
      params: "[-String*] <String> [[-AsPlainText]] [[-Force]] [<CommonParameters>]"
    },
    %{
      description:
        "Creates or changes an alias for a cmdlet or other command element in the\n\n        current Windows PowerShell session.",
      name: "Set-Alias",
      params:
        "[-Name*] <String> [-Value*] <String> [-Confirm] [-Description <String>] [-Force] [-Option {None | ReadOnly| Constant | Private | AllScope | Unspecified}] [-PassThru] [-Scope <String>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Creates an SMB share.",
      name: "New-SmbShare",
      params:
        "[-Name*] <String> [-Path*] <String> [[-ScopeName] <String>] [-CachingMode {None | Manual | Documents |Programs | BranchCache | Unknown}] [-CATimeout <UInt32>] [-ChangeAccess <String[]>] [-CimSession <CimSession[]>][-ConcurrentUserLimit <UInt32>] [-ContinuouslyAvailable <Boolean>] [-Description <String>] [-EncryptData<Boolean>] [-FolderEnumerationMode {AccessBased | Unrestricted}] [-FullAccess <String[]>] [-NoAccess <String[]>][-ReadAccess <String[]>] [-SecurityDescriptor <System.String>] [-Temporary] [-ThrottleLimit <Int32>] [-Confirm][-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Computes the hash value for a file by using a specified hash algorithm.",
      name: "Get-FileHash",
      params:
        "[-Algorithm {SHA1 | SHA256 | SHA384 | SHA512 | MACTripleDES | MD5 | RIPEMD160}] -InputStream* <Stream>[<CommonParameters>]"
    },
    %{
      description: "Gets installed modules on a computer.",
      name: "Get-InstalledModule",
      params:
        "[[-Name] <String[]>] [-AllVersions] [-MaximumVersion <Version>] [-MinimumVersion <Version>][-RequiredVersion <Version>] [<CommonParameters>]"
    },
    %{
      description: "Gets the execution policies for the current session.",
      name: "Get-ExecutionPolicy",
      params:
        "[[-Scope] {Process | CurrentUser | LocalMachine | UserPolicy | MachinePolicy}] [-List][<CommonParameters>]"
    },
    %{
      description: "Changes the user preference for the Windows PowerShell execution policy.",
      name: "Set-ExecutionPolicy",
      params:
        "[-ExecutionPolicy*] {Unrestricted | RemoteSigned | AllSigned | Restricted | Default | Bypass |Undefined} [[-Scope] {Process | CurrentUser | LocalMachine | UserPolicy | MachinePolicy}] [-Confirm] [-Force][-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Removes a printer from the specified computer.",
      name: "Remove-Printer",
      params:
        "[-Name*] <String[]> [-CimSession <CimSession[]>] [-ComputerName <String>] [-PassThru][-ThrottleLimit <Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Sends the output to the default formatter and to the default output cmdlet.",
      name: "Out-Default",
      params: "[-InputObject <PSObject>] [-Transcript] [<CommonParameters>]"
    },
    %{
      description: "Adds one or more Windows PowerShell snap-ins to the current session.",
      name: "Add-PSSnapin",
      params: "[-Name*] <String[]> [-PassThru] [<CommonParameters>]"
    },
    %{
      description: "Extracts files from a specified archive (zipped) file.",
      name: "Expand-Archive",
      params:
        "[[-DestinationPath] <String>] [-Confirm] [-Force] -LiteralPath* <String> [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Creates an instance of a Microsoft .NET Framework or COM object.",
      name: "New-Object",
      params:
        "[-TypeName*] <String> [[-ArgumentList] <Object[]>] [-Property <IDictionary>] [<CommonParameters>]"
    },
    %{
      description:
        "Exports all third-party drivers from a Windows image to a destination\n\n        folder.",
      name: "Export-WindowsDriver",
      params:
        "[-Destination <String>] [-LogLevel {Errors | Warnings | WarningsInfo}] [-LogPath <String>][-ScratchDirectory <String>] [-SystemDrive <String>] [-WindowsDirectory <String>] -Online* [<CommonParameters>]"
    },
    %{
      description:
        "Initializes a RAW disk for first time use, enabling the disk to be formatted\n\n        and used to store data.",
      name: "Initialize-Disk",
      params:
        "[-Number*] <UInt32[]> [-CimSession <CimSession[]>] [-PartitionStyle {Unknown | MBR | GPT}][-PassThru] [-ThrottleLimit <Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Deletes temporary Windows PowerShell drives and disconnects mapped network\n\n        drives.",
      name: "Remove-PSDrive",
      params:
        "[-LiteralName*] <String[]> [-Confirm] [-Force] [-PSProvider <String[]>] [-Scope <String>][-UseTransaction] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Deletes the property and its value from an item.",
      name: "Remove-ItemProperty",
      params:
        "[-Name*] <String[]> [-Confirm] [-Credential <PSCredential>] [-Exclude <String[]>] [-Filter<String>] [-Force] [-Include <String[]>] -LiteralPath* <String[]> [-UseTransaction] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Sets attributes on a specific physical disk.",
      name: "Set-PhysicalDisk",
      params:
        "[-CimSession <CimSession[]>] [-Description <String>] [-MediaType {HDD | SSD | SCM}][-NewFriendlyName <String>] [-ThrottleLimit <Int32>] [-Usage {AutoSelect | ManualSelect | HotSpare | Retired |Journal}] -UniqueId* <String> [<CommonParameters>]"
    },
    %{
      description: "Creates a new variable.",
      name: "New-Variable",
      params:
        "[-Name*] <String> [[-Value] <Object>] [-Confirm] [-Description <String>] [-Force] [-Option {None |ReadOnly | Constant | Private | AllScope | Unspecified}] [-PassThru] [-Scope <String>] [-Visibility {Public |Private}] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Gets the results of the Windows PowerShell background jobs in the current\n\n        session.",
      name: "Receive-Job",
      params:
        "[-Job*] <Job[]> [[-ComputerName] <String[]>] [-AutoRemoveJob] [-Force] [-Keep] [-NoRecurse] [-Wait][-WriteEvents] [-WriteJobInResults] [<CommonParameters>]"
    },
    %{
      description: "Deletes a variable and its value.",
      name: "Remove-Variable",
      params:
        "[-Name*] <String[]> [-Confirm] [-Exclude <String[]>] [-Force] [-Include <String[]>] [-Scope<String>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Gets the Windows PowerShell snap-ins on the computer.",
      name: "Get-PSSnapin",
      params: "[[-Name] <String[]>] [-Registered] [<CommonParameters>]"
    },
    %{
      description: "Writes an event to an event log.",
      name: "Write-EventLog",
      params:
        "[-LogName*] <String> [-Source*] <String> [-EventId*] <Int32> [[-EntryType] {Error | Information |FailureAudit | SuccessAudit | Warning}] [-Message*] <String> [-Category <Int16>] [-ComputerName <String>] [-RawData<Byte[]>] [<CommonParameters>]"
    },
    %{
      description: "Installs one or more Package Management package providers.",
      name: "Install-PackageProvider",
      params:
        "[-Name*] <String[]> [-AllVersions] [-Confirm] [-Credential <PSCredential>] [-Force][-ForceBootstrap] [-MaximumVersion <String>] [-MinimumVersion <String>] [-Proxy <Uri>] [-ProxyCredential<PSCredential>] [-RequiredVersion <String>] [-Scope {CurrentUser | AllUsers}] [-Source <String[]>] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Changes the configuration settings of an existing VPN connection profile.",
      name: "Set-VpnConnection",
      params:
        "[[-RememberCredential] <Boolean>] [[-UseWinlogonCredential] <Boolean>] [[-EapConfigXmlStream]<XmlDocument>] [-Name*] <String> [[-ServerAddress] <String>] [[-TunnelType] {Pptp | L2tp | Sstp | Ikev2 |Automatic}] [[-EncryptionLevel] {NoEncryption | Optional | Required | Maximum | Custom}] [[-AuthenticationMethod]{Pap | Chap | MSChapv2 | Eap | MachineCertificate}] [[-SplitTunneling] <Boolean>] [[-AllUserConnection]][[-L2tpPsk] <String>] [-CimSession <CimSession[]>] [-DnsSuffix <String>] [-Force] [-IdleDisconnectSeconds<UInt32>] [-MachineCertificateEKUFilter <String[]>] [-MachineCertificateIssuerFilter <X509Certificate2>][-PassThru] [-ServerList <CimInstance[]>] [-ThrottleLimit <Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Creates a new alias.",
      name: "New-Alias",
      params:
        "[-Name*] <String> [-Value*] <String> [-Confirm] [-Description <String>] [-Force] [-Option {None | ReadOnly| Constant | Private | AllScope | Unspecified}] [-PassThru] [-Scope <String>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Writes an object to the error stream.",
      name: "Write-Error",
      params:
        "[-Category {NotSpecified | OpenError | CloseError | DeviceError | DeadlockDetected | InvalidArgument |InvalidData | InvalidOperation | InvalidResult | InvalidType | MetadataError | NotImplemented | NotInstalled |ObjectNotFound | OperationStopped | OperationTimeout | SyntaxError | ParserError | PermissionDenied | ResourceBusy| ResourceExists | ResourceUnavailable | ReadError | WriteError | FromStdErr | SecurityError | ProtocolError |ConnectionError | AuthenticationError | LimitsExceeded | QuotaExceeded | NotEnabled}] [-CategoryActivity <String>][-CategoryReason <String>] [-CategoryTargetName <String>] [-CategoryTargetType <String>] [-ErrorId <String>]-Message* <String> [-RecommendedAction <String>] [-TargetObject <Object>] [<CommonParameters>]"
    },
    %{
      description:
        "Formats one or more existing volumes or a new volume on an existing\n\n        partition.",
      name: "Format-Volume",
      params:
        "[-DriveLetter*] <Char[]> [-AllocationUnitSize <UInt32>] [-CimSession <CimSession[]>] [-Compress][-DisableHeatGathering] [-FileSystem {FAT | FAT32 | exFAT | NTFS | ReFS}] [-Force] [-Full] [-IsDAX][-NewFileSystemLabel <String>] [-SetIntegrityStreams <Boolean>] [-ShortFileNameSupport <Boolean>] [-ThrottleLimit<Int32>] [-UseLargeFRS] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{description: "Creates a GUID.", name: "New-Guid", params: "[<CommonParameters>]"},
    %{
      description: "Creates a BITS transfer job.",
      name: "Start-BitsTransfer",
      params:
        "[-Source*] <String[]> [[-Destination] <String[]>] [-Asynchronous] [-Authentication {Basic |Digest | Ntlm | Negotiate | Passport}] [-Credential <PSCredential>] [-Description <String>] [-DisplayName<String>] [-Priority {Foreground | High | Normal | Low}] [-ProxyAuthentication {Basic | Digest | Ntlm | Negotiate| Passport}] [-ProxyBypass <String[]>] [-ProxyCredential <PSCredential>] [-ProxyList <Uri[]>] [-ProxyUsage{SystemDefault | NoProxy | AutoDetect | Override}] [-RetryInterval <Int32>] [-RetryTimeout <Int32>] [-Suspended][-TransferPolicy {Always | BelowCap | Capped | IgnoreCongestion | NearCap | None | NoSurcharge | NotRoaming |OverCapCharged | OverCapThrottled | PolicyUnrestricted | Roaming | Standard | Unrestricted | UsageBased}][-TransferType {Download | Upload | UploadReply}] [-UseStoredCredential {None | Proxy | Server}] [-Confirm][-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Exports a certificate from a certificate store into a file.",
      name: "Export-Certificate",
      params:
        "[-Force] [-NoClobber] [-Type {SST | CERT | P7B}] -Cert* <Certificate> -FilePath* <String>[-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Deletes the value of a variable.",
      name: "Clear-Variable",
      params:
        "[-Name*] <String[]> [-Confirm] [-Exclude <String[]>] [-Force] [-Include <String[]>] [-PassThru][-Scope <String>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Suspends the activity in a script or session for the specified period of\n\n        time.",
      name: "Start-Sleep",
      params: "-Milliseconds* <Int32> [<CommonParameters>]"
    },
    %{
      description: "Gets the local security groups.",
      name: "Get-LocalGroup",
      params: "[[-Name] <String[]>] [<CommonParameters>]"
    },
    %{
      description: "Creates and configures an IP address.",
      name: "New-NetIPAddress",
      params:
        "[-IPAddress*] <String> [-AddressFamily {IPv4 | IPv6}] [-CimSession <CimSession[]>][-DefaultGateway <String>] [-PolicyStore <String>] [-PreferredLifetime <TimeSpan>] [-PrefixLength <Byte>][-SkipAsSource <Boolean>] [-ThrottleLimit <Int32>] [-Type {Unicast | Anycast}] [-ValidLifetime <TimeSpan>]-InterfaceAlias* <String> [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Removes the local computer from its domain.",
      name: "Remove-Computer",
      params:
        "[-UnjoinDomainCredential] <PSCredential> [-ComputerName <String[]>] [-Confirm] [-Force][-LocalCredential <PSCredential>] [-PassThru] [-Restart] [-WhatIf] [-WorkgroupName <String>] [<CommonParameters>]"
    },
    %{
      description: "Creates a persistent connection to a local or remote computer.",
      name: "New-PSSession",
      params:
        "[-ConnectionUri*] <Uri[]> [-AllowRedirection] [-Authentication {Default | Basic | Negotiate |NegotiateWithImplicitCredential | Credssp | Digest | Kerberos}] [-CertificateThumbprint <String>][-ConfigurationName <String>] [-Credential <PSCredential>] [-EnableNetworkAccess] [-Name <String[]>][-SessionOption <PSSessionOption>] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Creates a new storage pool using a group of physical disks.",
      name: "New-StoragePool",
      params:
        "[-StorageSubSystemFriendlyName*] <String[]> [-AutoWriteCacheSize <Boolean>] [-CimSession<CimSession[]>] [-EnclosureAwareDefault <Boolean>] [-FaultDomainAwarenessDefault {PhysicalDisk | StorageEnclosure| StorageScaleUnit | StorageChassis | StorageRack}] [-LogicalSectorSizeDefault <UInt64>] [-MediaTypeDefault {HDD |SSD | SCM}] [-OtherUsageDescription <String>] [-ProvisioningTypeDefault {Unknown | Thin | Fixed}][-ResiliencySettingNameDefault <String>] [-ThrottleLimit <Int32>] [-Usage {Other | Unrestricted |ReservedForComputerSystem | ReservedAsDeltaReplicaContainer | ReservedForMigrationServices |ReservedForLocalReplicationServices | ReservedForRemoteReplicationServices | ReservedForSparing}][-WriteCacheSizeDefault <UInt64>] -FriendlyName* <String> -PhysicalDisks* <CimInstance[]> [<CommonParameters>]"
    },
    %{
      description: "Gets the IP address configuration.",
      name: "Get-NetIPAddress",
      params:
        "[[-IPAddress] <String[]>] [-AddressFamily <AddressFamily[]>] [-AddressState <AddressState[]>][-AssociatedIPInterface <CimInstance>] [-CimSession <CimSession[]>] [-IncludeAllCompartments] [-InterfaceAlias<String[]>] [-InterfaceIndex <UInt32[]>] [-PolicyStore <String>] [-PreferredLifetime <TimeSpan[]>] [-PrefixLength<Byte[]>] [-PrefixOrigin <PrefixOrigin[]>] [-SkipAsSource <Boolean[]>] [-SuffixOrigin <SuffixOrigin[]>][-ThrottleLimit <Int32>] [-Type <Type[]>] [-ValidLifetime <TimeSpan[]>] [<CommonParameters>]"
    },
    %{
      description: "Gets one or more host bus adapter (HBA) initiator ports.",
      name: "Get-InitiatorPort",
      params:
        "[[-NodeAddress] <String[]>] [-CimSession <CimSession[]>] [-ConnectionType <ConnectionType[]>][-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Creates a new Windows service.",
      name: "New-Service",
      params:
        "[-Name*] <String> [-BinaryPathName*] <String> [-Confirm] [-Credential <PSCredential>] [-DependsOn<String[]>] [-Description <String>] [-DisplayName <String>] [-StartupType {Boot | System | Automatic | Manual |Disabled}] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Gets the aliases for the current session.",
      name: "Get-Alias",
      params:
        "[-Definition <String[]>] [-Exclude <String[]>] [-Scope <String>] [<CommonParameters>]"
    },
    %{
      description: "Sets the system time zone to a specified time zone.",
      name: "Set-TimeZone",
      params: "[-Confirm] -Id* <String> [-PassThru] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Performs the default action on the specified item.",
      name: "Invoke-Item",
      params:
        "[-Confirm] [-Credential <PSCredential>] [-Exclude <String[]>] [-Filter <String>] [-Include <String[]>]-LiteralPath* <String[]> [-UseTransaction] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "undefined",
      name: "Resolve-DnsName",
      params:
        "[-Name*] <string> [[-Type] {UNKNOWN | A_AAAA | A | NS | MD | MF | CNAME | SOA | MB | MG | MR | NULL| WKS | PTR | HINFO | MINFO | MX | TXT | RP | AFSDB | X25 | ISDN | RT | AAAA | SRV | DNAME | OPT | DS | RRSIG |NSEC | DNSKEY | DHCID | NSEC3 | NSEC3PARAM | ANY | ALL | WINS}] [-Server <string[]>] [-DnsOnly] [-CacheOnly][-DnssecOk] [-DnssecCd] [-NoHostsFile] [-LlmnrNetbiosOnly] [-LlmnrFallback] [-LlmnrOnly] [-NetbiosFallback][-NoIdn] [-NoRecursion] [-QuickTimeout] [-TcpOnly]  [<CommonParameters>]"
    },
    %{
      description: "Disables a binding to a network adapter.",
      name: "Disable-NetAdapterBinding",
      params:
        "[-Name*] <String[]> [-AllBindings] [-AsJob] [-CimSession <CimSession[]>] [-ComponentID<String[]>] [-DisplayName <String[]>] [-IncludeHidden] [-PassThru] [-ThrottleLimit <Int32>] [-Confirm] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Gets the properties of a specified item.",
      name: "Get-ItemProperty",
      params:
        "[[-Name] <String[]>] [-Credential <PSCredential>] [-Exclude <String[]>] [-Filter <String>][-Include <String[]>] -LiteralPath* <String[]> [-UseTransaction] [<CommonParameters>]"
    },
    %{
      description: "Appends content, such as words or data, to a file.",
      name: "Add-Content",
      params:
        "[-Value*] <Object[]> [-Confirm] [-Credential <PSCredential>] [-Encoding {Unknown | String | Unicode |Byte | BigEndianUnicode | UTF8 | UTF7 | UTF32 | Ascii | Default | Oem | BigEndianUTF32}] [-Exclude <String[]>][-Filter <String>] [-Force] [-Include <String[]>] -LiteralPath* <String[]> [-NoNewline] [-PassThru] [-Stream<String>] [-UseTransaction] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Uninstalls one or more software packages.",
      name: "Uninstall-Package",
      params:
        "[-AdditionalArguments <String[]>] [-AllVersions] [-Confirm] [-Force] [-ForceBootstrap] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Adds a route to a VPN connection.",
      name: "Add-VpnConnectionRoute",
      params:
        "[-ConnectionName*] <String> [-DestinationPrefix*] <String> [[-RouteMetric] <UInt32>][[-AllUserConnection]] [-CimSession <CimSession[]>] [-PassThru] [-ThrottleLimit <Int32>] [-Confirm] [-WhatIf][<CommonParameters>]"
    },
    %{
      description:
        "Creates a new event log and a new event source on a local or remote\n\n        computer.",
      name: "New-EventLog",
      params:
        "[-LogName*] <String> [-Source*] <String[]> [[-ComputerName] <String[]>] [-CategoryResourceFile<String>] [-MessageResourceFile <String>] [-ParameterResourceFile <String>] [<CommonParameters>]"
    },
    %{
      description:
        "Deletes an instance of an existing Windows Management Instrumentation (WMI)\n\n        class.",
      name: "Remove-WmiObject",
      params:
        "[-Class*] <String> [-AsJob] [-Authentication {Default | None | Connect | Call | Packet |PacketIntegrity | PacketPrivacy | Unchanged}] [-Authority <String>] [-ComputerName <String[]>] [-Confirm][-Credential <PSCredential>] [-EnableAllPrivileges] [-Impersonation {Default | Anonymous | Identify | Impersonate| Delegate}] [-Locale <String>] [-Namespace <String>] [-ThrottleLimit <Int32>] [-WhatIf] [<CommonParameters>]"
    },
    %{description: "Gets IP network configuration.", name: "Get-NetIPConfiguration", params: ""},
    %{
      description:
        "Sets the system locale (the language for non-Unicode programs) for the current\n\n        computer.",
      name: "Set-WinSystemLocale",
      params: "[-SystemLocale*] <CultureInfo> [<CommonParameters>]"
    },
    %{
      description: "Returns the specified part of a path.",
      name: "Split-Path",
      params:
        "[-Path*] <String[]> [-Credential <PSCredential>] [-IsAbsolute] [-Resolve] [-UseTransaction][<CommonParameters>]"
    },
    %{
      description: "Displays information about Windows PowerShell commands and concepts.",
      name: "Get-Help",
      params:
        "[[-Name] <String>] [-Category {Alias | Cmdlet | Provider | General | FAQ | Glossary | HelpFile |ScriptCommand | Function | Filter | ExternalScript | All | DefaultHelp | Workflow | DscResource | Class |Configuration}] [-Component <String[]>] -Detailed* [-Functionality <String[]>] [-Path <String>] [-Role <String[]>][<CommonParameters>]"
    },
    %{
      description: "Sets the current working location to a specified location.",
      name: "Set-Location",
      params: "-LiteralPath* <String> [-PassThru] [-UseTransaction] [<CommonParameters>]"
    },
    %{
      description: "Saves a module locally without installing it.",
      name: "Save-Module",
      params:
        "[-InputObject*] <PSObject[]> [-Confirm] [-Credential <PSCredential>] [-Force] -LiteralPath* <String>[-Proxy <Uri>] [-ProxyCredential <PSCredential>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Adds modules to the current session.",
      name: "Import-Module",
      params:
        "[-Assembly*] <Assembly[]> [-Alias <String[]>] [-ArgumentList <Object[]>] [-AsCustomObject] [-Cmdlet<String[]>] [-DisableNameChecking] [-Force] [-Function <String[]>] [-Global] [-NoClobber] [-PassThru] [-Prefix<String>] [-Scope {Local | Global}] [-Variable <String[]>] [<CommonParameters>]"
    },
    %{
      description: "Gets content from a web page on the Internet.",
      name: "Invoke-WebRequest",
      params:
        "[-Uri*] <Uri> [-Body <Object>] [-Certificate <X509Certificate>] [-CertificateThumbprint <String>][-ContentType <String>] [-Credential <PSCredential>] [-DisableKeepAlive] [-Headers <IDictionary>] [-InFile<String>] [-MaximumRedirection <Int32>] [-Method {Default | Get | Head | Post | Put | Delete | Trace | Options |Merge | Patch}] [-OutFile <String>] [-PassThru] [-Proxy <Uri>] [-ProxyCredential <PSCredential>][-ProxyUseDefaultCredentials] [-SessionVariable <String>] [-TimeoutSec <Int32>] [-TransferEncoding {chunked |compress | deflate | gzip | identity}] [-UseBasicParsing] [-UseDefaultCredentials] [-UserAgent <String>][-WebSession <WebRequestSession>] [<CommonParameters>]"
    },
    %{
      description: "Gets the value for one or more properties of a specified item.",
      name: "Get-ItemPropertyValue",
      params:
        "[-Name*] <String[]> [-Credential <PSCredential>] [-Exclude <String[]>] [-Filter <String>][-Include <String[]>] -LiteralPath* <String[]> [-UseTransaction] [<CommonParameters>]"
    },
    %{
      description: "Extracts and parses structured properties from string content.",
      name: "ConvertFrom-String",
      params:
        "[-InputObject*] <String> [-Delimiter <String>] [-PropertyNames <String[]>] [<CommonParameters>]"
    },
    %{
      description: "Finds text in strings and files.",
      name: "Select-String",
      params:
        "[-Pattern*] <String[]> [-AllMatches] [-CaseSensitive] [-Context <Int32[]>] [-Encoding {unicode | utf7| utf8 | utf32 | ascii | bigendianunicode | default | oem}] [-Exclude <String[]>] [-Include <String[]>]-InputObject* <PSObject> [-List] [-NotMatch] [-Quiet] [-SimpleMatch] [<CommonParameters>]"
    },
    %{
      description: "Gets the current culture set in the operating system.",
      name: "Get-Culture",
      params: "[<CommonParameters>]"
    },
    %{
      description:
        "Adds custom properties and methods to an instance of a Windows PowerShell\n\n        object.",
      name: "Add-Member",
      params:
        "[-MemberType*] {AliasProperty | CodeProperty | Property | NoteProperty | ScriptProperty | Properties |PropertySet | Method | CodeMethod | ScriptMethod | Methods | ParameterizedProperty | MemberSet | Event | Dynamic |All} [-Name*] <String> [[-Value] <Object>] [[-SecondValue] <Object>] [-Force] -InputObject* <PSObject> [-PassThru][-TypeName* <String>] [<CommonParameters>]"
    },
    %{
      description: "Creates an object that contains a scheduled task principal.",
      name: "New-ScheduledTaskPrincipal",
      params:
        "[-UserId*] <String> [[-LogonType] {None | Password | S4U | Interactive | Group |ServiceAccount | InteractiveOrPassword}] [[-RunLevel] {Limited | Highest}] [[-ProcessTokenSidType] {None |Unrestricted | Default}] [[-RequiredPrivilege] <String[]>] [[-Id] <String>] [-CimSession <CimSession[]>][-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Returns App-V Client Packages.",
      name: "Get-AppvClientPackage",
      params: "[[-Name] <String>] [[-Version] <String>] [-All] [<CommonParameters>]"
    },
    %{
      description: "Changes the network category of a connection profile.",
      name: "Set-NetConnectionProfile",
      params:
        "[-CimSession <CimSession[]>] [-InterfaceAlias <String[]>] [-InterfaceIndex <UInt32[]>][-IPv4Connectivity <IPv4Connectivity[]>] [-IPv6Connectivity <IPv6Connectivity[]>] [-Name <String[]>][-NetworkCategory {Public | Private | DomainAuthenticated}] [-PassThru] [-ThrottleLimit <Int32>] [-Confirm][-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Creates a Web service proxy object that lets you use and manage the Web\n\n        service in Windows PowerShell.",
      name: "New-WebServiceProxy",
      params:
        "[-Uri*] <Uri> [[-Class] <String>] [[-Namespace] <String>] [-Credential <PSCredential>][<CommonParameters>]"
    },
    %{
      description:
        "Invokes Pester to run all tests (files containing *.Tests.ps1) recursively\n\n        under the Path",
      name: "Invoke-Pester",
      params:
        "[[-Script] <Object[]>] [[-TestName] <String[]>] [[-EnableExit]] [[-OutputXml] <String>] [[-Tag]<String[]>] [-ExcludeTag <String[]>] [-PassThru] [-CodeCoverage <Object[]>] [-Strict] [-Quiet] [-PesterOption<Object>] [<CommonParameters>]"
    },
    %{
      description:
        "Gets the specified Volume object, or all Volume objects if no filter is\n\n        provided.",
      name: "Get-Volume",
      params:
        "[[-DriveLetter] <Char[]>] [-CimSession <CimSession[]>] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Gets an object that represents the current host program.",
      name: "Get-Host",
      params: "[<CommonParameters>]"
    },
    %{
      description: "Enables encryption for a BitLocker volume.",
      name: "Enable-BitLocker",
      params:
        "[-MountPoint*] <String[]> [-AdAccountOrGroup*] <String> [-EncryptionMethod<BitLockerVolumeEncryptionMethodOnEnable>] [-HardwareEncryption] [-Service] [-SkipHardwareTest] [-UsedSpaceOnly]-AdAccountOrGroupProtector* [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Gets DNS server IP addresses from the TCP/IP properties on an interface.",
      name: "Get-DnsClientServerAddress",
      params:
        "[[-InterfaceAlias] <String[]>] [-AddressFamily <AddressFamily[]>] [-CimSession<CimSession[]>] [-InterfaceIndex <UInt32[]>] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Creates a new virtual disk in the specified storage pool.",
      name: "New-VirtualDisk",
      params:
        "[-StoragePoolFriendlyName*] <String[]> [-AllocationUnitSize <UInt64>] [-AutoNumberOfColumns][-AutoWriteCacheSize] [-CimSession <CimSession[]>] [-ColumnIsolation {PhysicalDisk | StorageEnclosure |StorageScaleUnit | StorageChassis | StorageRack}] [-FaultDomainAwareness {PhysicalDisk | StorageEnclosure |StorageScaleUnit | StorageChassis | StorageRack}] [-Interleave <UInt64>] [-IsEnclosureAware <Boolean>] [-MediaType{HDD | SSD | SCM}] [-NumberOfColumns <UInt16>] [-NumberOfDataCopies <UInt16>] [-NumberOfGroups <UInt16>][-OtherUsageDescription <String>] [-PhysicalDiskRedundancy <UInt16>] [-PhysicalDisksToUse <CimInstance[]>][-ProvisioningType {Unknown | Thin | Fixed}] [-ReadCacheSize <UInt64>] [-ResiliencySettingName <String>] [-Size<UInt64>] [-StorageTiers <CimInstance[]>] [-StorageTierSizes <UInt64[]>] [-ThrottleLimit <Int32>] [-Usage {Other |Unrestricted | ReservedForComputerSystem | ReservedForReplicationServices | ReservedForMigrationServices |LocalReplicaSource | RemoteReplicaSource | LocalReplicaTarget | RemoteReplicaTarget | LocalReplicaSourceOrTarget |RemoteReplicaSourceOrTarget | DeltaReplicaTarget | ElementComponent | ReservedAsPoolContributer |CompositeVolumeMember | CompositeVirtualDiskMember | ReservedForSparing}] [-UseMaximumSize] [-WriteCacheSize<UInt64>] -FriendlyName* <String> [<CommonParameters>]"
    },
    %{
      description: "Creates a scheduled task trigger object.",
      name: "New-ScheduledTaskTrigger",
      params:
        "[-Once*] [-RandomDelay <TimeSpan>] [-RepetitionDuration <TimeSpan>] [-RepetitionInterval<TimeSpan>] -At* <DateTime> [<CommonParameters>]"
    },
    %{
      description: "Gets performance counter data from local and remote computers.",
      name: "Get-Counter",
      params:
        "[[-Counter] <String[]>] [-ComputerName <String[]>] [-Continuous] [-MaxSamples <Int64>][-SampleInterval <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Gets a connection profile.",
      name: "Get-NetConnectionProfile",
      params:
        "[-CimSession <CimSession[]>] [-InterfaceAlias <String[]>] [-InterfaceIndex <UInt32[]>][-IPv4Connectivity <IPv4Connectivity[]>] [-IPv6Connectivity <IPv6Connectivity[]>] [-Name <String[]>][-NetworkCategory <NetworkCategory[]>] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Gets an IP interface.",
      name: "Get-NetIPInterface",
      params:
        "[[-InterfaceAlias] <String[]>] [-AddressFamily <AddressFamily[]>] [-AdvertiseDefaultRoute<AdvertiseDefaultRoute[]>] [-AdvertisedRouterLifetime <TimeSpan[]>] [-Advertising <Advertising[]>][-AutomaticMetric <AutomaticMetric[]>] [-BaseReachableTimeMs <UInt32[]>] [-CimSession <CimSession[]>] [-ClampMss<ClampMss[]>] [-CompartmentId <UInt32[]>] [-ConnectionState <ConnectionState[]>] [-CurrentHopLimit <UInt32[]>][-DadRetransmitTimeMs <UInt32[]>] [-DadTransmits <UInt32[]>] [-Dhcp <Dhcp[]>] [-DirectedMacWolPattern<DirectedMacWolPattern[]>] [-EcnMarking <EcnMarking[]>] [-ForceArpNdWolPattern <ForceArpNdWolPattern[]>][-Forwarding <Forwarding[]>] [-IgnoreDefaultRoutes <IgnoreDefaultRoutes[]>] [-IncludeAllCompartments][-InterfaceIndex <UInt32[]>] [-InterfaceMetric <UInt32[]>] [-ManagedAddressConfiguration<ManagedAddressConfiguration[]>] [-NeighborDiscoverySupported <NeighborDiscoverySupported[]>][-NeighborUnreachabilityDetection <NeighborUnreachabilityDetection[]>] [-NlMtuBytes <UInt32[]>][-OtherStatefulConfiguration <OtherStatefulConfiguration[]>] [-PolicyStore <String>] [-ReachableTimeMs <UInt32[]>][-RetransmitTimeMs <UInt32[]>] [-RouterDiscovery <RouterDiscovery[]>] [-ThrottleLimit <Int32>] [-WeakHostReceive<WeakHostReceive[]>] [-WeakHostSend <WeakHostSend[]>] [<CommonParameters>]"
    },
    %{
      description: "Gets the contents of a file.",
      name: "Get-Content",
      params:
        "[-Credential <PSCredential>] [-Delimiter <String>] [-Encoding {Unknown | String | Unicode | Byte |BigEndianUnicode | UTF8 | UTF7 | UTF32 | Ascii | Default | Oem | BigEndianUTF32}] [-Exclude <String[]>] [-Filter<String>] [-Force] [-Include <String[]>] -LiteralPath* <String[]> [-Raw] [-ReadCount <Int64>] [-Stream <String>][-Tail <Int32>] [-TotalCount <Int64>] [-UseTransaction] [-Wait] [<CommonParameters>]"
    },
    %{
      description: "Performs an operation against each item in a collection of input objects.",
      name: "ForEach-Object",
      params:
        "[-MemberName*] <String> [-ArgumentList <Object[]>] [-Confirm] [-InputObject <PSObject>] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Updates the configuration of an existing printer.",
      name: "Set-Printer",
      params:
        "[-Name*] <String[]> [-BranchOfficeOfflineLogSizeMB <UInt32>] [-CimSession <CimSession[]>] [-Comment<String>] [-ComputerName <String>] [-Datatype <String>] [-DisableBranchOfficeLogging <Boolean>] [-DriverName<String>] [-KeepPrintedJobs <Boolean>] [-Location <String>] [-PassThru] [-PermissionSDDL <String>] [-PortName<String>] [-PrintProcessor <String>] [-Priority <UInt32>] [-Published <Boolean>] [-RenderingMode {SSR | CSR |BranchOffice}] [-SeparatorPageFile <String>] [-Shared <Boolean>] [-ShareName <String>] [-StartTime <UInt32>][-ThrottleLimit <Int32>] [-UntilTime <UInt32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Creates a scheduled job.",
      name: "Register-ScheduledJob",
      params:
        "[-Name*] <String> [-FilePath*] <String> [-ArgumentList <Object[]>] [-Authentication {Default |Basic | Negotiate | NegotiateWithImplicitCredential | Credssp | Digest | Kerberos}] [-Confirm] [-Credential<PSCredential>] [-InitializationScript <ScriptBlock>] [-MaxResultCount <Int32>] [-RunAs32] [-RunEvery <TimeSpan>][-RunNow] [-ScheduledJobOption <ScheduledJobOptions>] [-Trigger <ScheduledJobTrigger[]>] [-WhatIf][<CommonParameters>]"
    },
    %{
      description:
        "Confirms that Secure Boot is enabled by checking the Secure Boot status on the\n\n        local computer.",
      name: "Confirm-SecureBootUEFI",
      params: "[<CommonParameters>]"
    },
    %{
      description: "Creates a new partition on an existing Disk object.",
      name: "New-Partition",
      params:
        "[-DiskNumber*] <UInt32[]> [-Alignment <UInt32>] [-AssignDriveLetter] [-CimSession <CimSession[]>][-DriveLetter <Char>] [-GptType <String>] [-IsActive] [-IsHidden] [-MbrType {FAT12 | FAT16 | Extended | Huge | IFS| FAT32}] [-Offset <UInt64>] [-Size <UInt64>] [-ThrottleLimit <Int32>] [-UseMaximumSize] [<CommonParameters>]"
    },
    %{
      description: "Creates a scheduled task instance.",
      name: "New-ScheduledTask",
      params:
        "[[-Action] <CimInstance[]>] [[-Trigger] <CimInstance[]>] [[-Settings] <CimInstance>][[-Principal] <CimInstance>] [[-Description] <String>] [-CimSession <CimSession[]>] [-ThrottleLimit <Int32>][<CommonParameters>]"
    },
    %{
      description: "Resizes a partition and the underlying file system.",
      name: "Resize-Partition",
      params:
        "[-Size*] <UInt64> [-CimSession <CimSession[]>] [-PassThru] [-ThrottleLimit <Int32>] -DriveLetter*<Char[]> [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Enables a previously disabled firewall rule.",
      name: "Enable-NetFirewallRule",
      params:
        "[-Action <Action[]>] [-AsJob] [-CimSession <CimSession[]>] [-Description <String[]>][-Direction <Direction[]>] [-DisplayGroup <String[]>] [-EdgeTraversalPolicy <EdgeTraversal[]>] [-Enabled<Enabled[]>] [-GPOSession <String>] [-Group <String[]>] [-LocalOnlyMapping <Boolean[]>] [-LooseSourceMapping<Boolean[]>] [-Owner <String[]>] [-PassThru] [-PolicyStore <String>] [-PolicyStoreSource <String[]>][-PolicyStoreSourceType <PolicyStoreType[]>] [-PrimaryStatus <PrimaryStatus[]>] [-Status <String[]>][-ThrottleLimit <Int32>] [-TracePolicyStore] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Invokes a method of a CIM class.",
      name: "Invoke-CimMethod",
      params:
        "[-ClassName*] <String> [[-Arguments] <IDictionary>] [-MethodName*] <String> [-ComputerName<String[]>] [-Namespace <String>] [-OperationTimeoutSec <UInt32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Gets information about the Authenticode signature for a file.",
      name: "Get-AuthenticodeSignature",
      params: "-Content* <Byte[]> -SourcePathOrExtension* <String[]> [<CommonParameters>]"
    },
    %{
      description: "Sets the SMB Service configuration.",
      name: "Set-SmbServerConfiguration",
      params:
        "[-AnnounceComment <String>] [-AnnounceServer <Boolean>] [-AsynchronousCredits <UInt32>][-AutoDisconnectTimeout <UInt32>] [-AutoShareServer <Boolean>] [-AutoShareWorkstation <Boolean>] [-CachedOpenLimit<UInt32>] [-CimSession <CimSession[]>] [-DurableHandleV2TimeoutInSeconds <UInt32>] [-EnableAuthenticateUserSharing<Boolean>] [-EnableDownlevelTimewarp <Boolean>] [-EnableForcedLogoff <Boolean>] [-EnableLeasing <Boolean>][-EnableMultiChannel <Boolean>] [-EnableOplocks <Boolean>] [-EnableSecuritySignature <Boolean>][-EnableSMB1Protocol <Boolean>] [-EnableSMB2Protocol <Boolean>] [-EnableStrictNameChecking <Boolean>][-EncryptData <Boolean>] [-Force] [-IrpStackSize <UInt32>] [-KeepAliveTime <UInt32>] [-MaxChannelPerSession<UInt32>] [-MaxMpxCount <UInt32>] [-MaxSessionPerConnection <UInt32>] [-MaxThreadsPerQueue <UInt32>][-MaxWorkItems <UInt32>] [-NullSessionPipes <String>] [-NullSessionShares <String>] [-OplockBreakWait <UInt32>][-PendingClientTimeoutInSeconds <UInt32>] [-RejectUnencryptedAccess <Boolean>] [-RequireSecuritySignature<Boolean>] [-ServerHidden <Boolean>] [-Smb2CreditsMax <UInt32>] [-Smb2CreditsMin <UInt32>][-SmbServerNameHardeningLevel <UInt32>] [-ThrottleLimit <Int32>] [-TreatHostAsStableStorage <Boolean>][-ValidateAliasNotCircular <Boolean>] [-ValidateShareScope <Boolean>] [-ValidateShareScopeNotAliased <Boolean>][-ValidateTargetName <Boolean>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Stops one or more running processes.",
      name: "Stop-Process",
      params: "[-Id*] <Int32[]> [-Confirm] [-Force] [-PassThru] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Gets the events in an event log, or a list of the event logs, on the local or\n\n        remote computers.",
      name: "Get-EventLog",
      params:
        "[-LogName*] <String> [[-InstanceId] <Int64[]>] [-After <DateTime>] [-AsBaseObject] [-Before<DateTime>] [-ComputerName <String[]>] [-EntryType {Error | Information | FailureAudit | SuccessAudit | Warning}][-Index <Int32[]>] [-Message <String>] [-Newest <Int32>] [-Source <String[]>] [-UserName <String[]>][<CommonParameters>]"
    },
    %{
      description:
        "Gets events from event logs and event tracing log files on local and remote\n\n        computers.",
      name: "Get-WinEvent",
      params:
        "[[-LogName] <String[]>] [-ComputerName <String>] [-Credential <PSCredential>] [-FilterXPath <String>][-Force] [-MaxEvents <Int64>] [-Oldest] [<CommonParameters>]"
    },
    %{
      description: "Deletes output instead of sending it down the pipeline.",
      name: "Out-Null",
      params: "[-InputObject <PSObject>] [<CommonParameters>]"
    },
    %{
      description:
        "Installs a Windows capability package on the specified operating system\n\n        image.",
      name: "Add-WindowsCapability",
      params:
        "[-LimitAccess] [-LogLevel {Errors | Warnings | WarningsInfo}] [-LogPath <String>][-ScratchDirectory <String>] [-Source <String[]>] [-SystemDrive <String>] [-WindowsDirectory <String>] -Name*<String> -Online* [<CommonParameters>]"
    },
    %{
      description: "Tests whether the WinRM service is running on a local or remote computer.",
      name: "Test-WSMan",
      params:
        "[[-ComputerName] <String>] [-ApplicationName <String>] [-Authentication {None | Default | Digest |Negotiate | Basic | Kerberos | ClientCertificate | Credssp}] [-CertificateThumbprint <String>] [-Credential<PSCredential>] [-Port <Int32>] [-UseSSL] [<CommonParameters>]"
    },
    %{
      description: "Moves an item from one location to another.",
      name: "Move-Item",
      params:
        "[[-Destination] <String>] [-Confirm] [-Credential <PSCredential>] [-Exclude <String[]>] [-Filter<String>] [-Force] [-Include <String[]>] -LiteralPath* <String[]> [-PassThru] [-UseTransaction] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Sends ICMP echo request packets (\"pings\") to one or more computers.",
      name: "Test-Connection",
      params:
        "[-ComputerName*] <String[]> [-AsJob] [-BufferSize <Int32>] [-Count <Int32>] [-DcomAuthentication{Default | None | Connect | Call | Packet | PacketIntegrity | PacketPrivacy | Unchanged}] [-Delay <Int32>][-Impersonation {Default | Anonymous | Identify | Impersonate | Delegate}] [-Protocol {DCOM | WSMan}][-ThrottleLimit <Int32>] [-TimeToLive <Int32>] [-WsmanAuthentication {Default | Basic | Negotiate | CredSSP |Digest | Kerberos}] [<CommonParameters>]"
    },
    %{
      description: "Adds a printer to the specified computer.",
      name: "Add-Printer",
      params:
        "[-Name*] <String> [-DriverName*] <String> [-BranchOfficeOfflineLogSizeMB <UInt32>] [-CimSession<CimSession[]>] [-Comment <String>] [-ComputerName <String>] [-Datatype <String>] [-DisableBranchOfficeLogging][-KeepPrintedJobs] [-Location <String>] [-PermissionSDDL <String>] [-PrintProcessor <String>] [-Priority <UInt32>][-Published] [-RenderingMode {SSR | CSR | BranchOffice}] [-SeparatorPageFile <String>] [-Shared] [-ShareName<String>] [-StartTime <UInt32>] [-ThrottleLimit <Int32>] [-UntilTime <UInt32>] -PortName* <String> [-Confirm][-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Changes the security descriptor of a specified item, such as a file or a\n\n        registry key.",
      name: "Set-Acl",
      params:
        "<String[]> [-AclObject*] <Object> [[-CentralAccessPolicy] <String>] [-ClearCentralAccessPolicy][-Confirm] [-Exclude <String[]>] [-Filter <String>] [-Include <String[]>] [-Passthru] [-UseTransaction] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Creates a volume with the specified file system.",
      name: "New-Volume",
      params:
        "[-StoragePool*] <CimInstance> [-AccessPath <String>] [-AllocationUnitSize <UInt32>] [-CimSession<CimSession>] [-DriveLetter <Char>] [-FileSystem <FileSystemType>] [-MediaType <New-Volume.MediaType>][-NumberOfColumns <UInt16>] [-NumberOfGroups <UInt16>] [-PhysicalDiskRedundancy <UInt16>] [-ProvisioningType<Microsoft.PowerShell.Cmdletization.GeneratedTypes.SetStoragePool.ProvisioningType>] [-ReadCacheSize <UInt64>][-ResiliencySettingName <String>] [-Size <UInt64>] [-StorageTierFriendlyNames <String[]>] [-StorageTiers<CimInstance[]>] [-StorageTierSizes <UInt64[]>] [-ThrottleLimit <Int32>] [-UseMaximumSize] [-WriteCacheSize<UInt64>] -FriendlyName* <String> [<CommonParameters>]"
    },
    %{
      description: "Creates a new scheduled task settings object.",
      name: "New-ScheduledTaskSettingsSet",
      params:
        "[-AllowStartIfOnBatteries] [-CimSession <CimSession[]>] [-Compatibility {At | V1 |Vista | Win7 | Win8}] [-DeleteExpiredTaskAfter <TimeSpan>] [-Disable] [-DisallowDemandStart][-DisallowHardTerminate] [-DisallowStartOnRemoteAppSession] [-DontStopIfGoingOnBatteries] [-DontStopOnIdleEnd][-ExecutionTimeLimit <TimeSpan>] [-Hidden] [-IdleDuration <TimeSpan>] [-IdleWaitTimeout <TimeSpan>][-MaintenanceDeadline <TimeSpan>] [-MaintenanceExclusive] [-MaintenancePeriod <TimeSpan>] [-MultipleInstances{Parallel | Queue | IgnoreNew}] [-NetworkId <String>] [-NetworkName <String>] [-Priority <Int32>] [-RestartCount<Int32>] [-RestartInterval <TimeSpan>] [-RestartOnIdle] [-RunOnlyIfIdle] [-RunOnlyIfNetworkAvailable][-StartWhenAvailable] [-ThrottleLimit <Int32>] [-WakeToRun] [<CommonParameters>]"
    },
    %{
      description: "Starts one or more stopped services.",
      name: "Start-Service",
      params:
        "[-Confirm] -DisplayName* <String[]> [-Exclude <String[]>] [-Include <String[]>] [-PassThru] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Gets the variables in the current console.",
      name: "Get-Variable",
      params:
        "[[-Name] <String[]>] [-Exclude <String[]>] [-Include <String[]>] [-Scope <String>] [-ValueOnly][<CommonParameters>]"
    },
    %{
      description: "Unregisters a scheduled task.",
      name: "Unregister-ScheduledTask",
      params:
        "[[-TaskName] <String[]>] [[-TaskPath] <String[]>] [-CimSession <CimSession[]>][-PassThru] [-ThrottleLimit <Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Gets the current Windows clipboard entry.",
      name: "Get-Clipboard",
      params:
        "[-Format {Text | FileDropList | Image | Audio}] [-Raw] [-TextFormatType {Text | UnicodeText | Rtf |Html | CommaSeparatedValue}] [<CommonParameters>]"
    },
    %{
      description: "Renames an item in a Windows PowerShell provider namespace.",
      name: "Rename-Item",
      params:
        "[-NewName*] <String> [-Confirm] [-Credential <PSCredential>] [-Force] -LiteralPath* <String> [-PassThru][-UseTransaction] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Returns a list of all partition objects visible on all disks, or optionally a\n\n        filtered list using specifiedparameters.",
      name: "Get-Partition",
      params:
        "[[-DiskNumber] <UInt32[]>] [[-PartitionNumber] <UInt32[]>] [-CimSession <CimSession[]>][-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Finds software packages in available package sources.",
      name: "Find-Package",
      params:
        "[[-Name] <String[]>] [-AllVersions] [-AllowPrereleaseVersions] [-ConfigFile <String>] [-Contains<String>] [-Credential <PSCredential>] [-FilterOnTag <String[]>] [-Force] [-ForceBootstrap] [-Headers <String[]>][-IncludeDependencies] [-MaximumVersion <String>] [-MinimumVersion <String>] [-ProviderName {msi | NuGet | msu |Programs | PowerShellGet | psl | chocolatey}] [-Proxy <Uri>] [-ProxyCredential <PSCredential>] [-RequiredVersion<String>] [-SkipValidate] [-Source <String[]>] [<CommonParameters>]"
    },
    %{
      description: "Sends objects to the host as a series of strings.",
      name: "Out-String",
      params: "[-InputObject <PSObject>] [-Stream] [-Width <Int32>] [<CommonParameters>]"
    },
    %{
      description:
        "Generates a new root key for the Microsoft Group KdsSvc within Active\n\n        Directory.",
      name: "Add-KdsRootKey",
      params:
        "[[-EffectiveTime] <DateTime>] [-LocalTestOnly] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Returns unique items from a sorted list.",
      name: "Get-Unique",
      params: "[-AsString] [-InputObject <PSObject>] [<CommonParameters>]"
    },
    %{
      description: "Configures the local computer for remote management.",
      name: "Set-WSManQuickConfig",
      params: "[-Force] [-SkipNetworkProfileCheck] [-UseSSL] [<CommonParameters>]"
    },
    %{
      description: "Creates temporary and persistent mapped network drives.",
      name: "New-PSDrive",
      params:
        "[-Name*] <String> [-PSProvider*] <String> [-Root*] <String> [-Confirm] [-Credential <PSCredential>][-Description <String>] [-Persist] [-Scope <String>] [-UseTransaction] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Merges Windows Update .etl files into a single log file.",
      name: "Get-WindowsUpdateLog",
      params:
        "[[-ETLPath] <String[]>] [[-LogPath] <String>] [[-SymbolServer] <String>] [-ForceFlush][-InformationAction {SilentlyContinue | Stop | Continue | Inquire | Ignore | Suspend}] [-InformationVariable<String>] [-ProcessingType {CSV | XML}] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Uses a customized view to format the output.",
      name: "Format-Custom",
      params:
        "[[-Property] <Object[]>] [-Depth <Int32>] [-DisplayError] [-Expand {CoreOnly | EnumOnly | Both}][-Force] [-GroupBy <Object>] [-InputObject <PSObject>] [-ShowError] [-View <String>] [<CommonParameters>]"
    },
    %{
      description: "Adds an ODBC DSN.",
      name: "Add-OdbcDsn",
      params:
        "[-Name*] <String> [-CimSession <CimSession[]>] [-PassThru] [-Platform {32-bit | 64-bit}][-SetPropertyValue <String[]>] [-ThrottleLimit <Int32>] -DriverName* <String> -DsnType* {User | System}[<CommonParameters>]"
    },
    %{
      description: "Gets one or more disks visible to the operating system.",
      name: "Get-Disk",
      params:
        "[[-Number] <UInt32[]>] [-CimSession <CimSession[]>] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Removes an app package from a user account.",
      name: "Remove-AppxPackage",
      params: "[-Package*] <String> [-AllUsers] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Gets the files and folders in a file system drive.",
      name: "Get-ChildItem",
      params:
        "[[-Filter] <String>] [-Attributes {ReadOnly | Hidden | System | Directory | Archive | Device |Normal | Temporary | SparseFile | ReparsePoint | Compressed | Offline | NotContentIndexed | Encrypted |IntegrityStream | NoScrubData}] [-Depth <UInt32>] [-Directory] [-Exclude <String[]>] [-File] [-Force] [-Hidden][-Include <String[]>] -LiteralPath* <String[]> [-Name] [-ReadOnly] [-Recurse] [-System] [-UseTransaction][<CommonParameters>]"
    },
    %{
      description: "Gets all commands.",
      name: "Get-Command",
      params:
        "[[-Name] <String[]>] [[-ArgumentList] <Object[]>] [-All] [-CommandType {Alias | Function | Filter |Cmdlet | ExternalScript | Application | Script | Workflow | Configuration | All}] [-FullyQualifiedModule<ModuleSpecification[]>] [-ListImported] [-Module <String[]>] [-ParameterName <String[]>] [-ParameterType<PSTypeName[]>] [-ShowCommandInfo] [-Syntax] [-TotalCount <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Sets values for a registered repository.",
      name: "Set-PSRepository",
      params:
        "[-Name*] <String> [[-SourceLocation] <Uri>] [-Credential <PSCredential>] [-InstallationPolicy{Trusted | Untrusted}] [-PackageManagementProvider <String>] [-Proxy <Uri>] [-ProxyCredential <PSCredential>][-PublishLocation <Uri>] [-ScriptPublishLocation <Uri>] [-ScriptSourceLocation <Uri>] [<CommonParameters>]"
    },
    %{
      description: "Gets a list of the commands entered during the current session.",
      name: "Get-History",
      params: "[[-Id] <Int64[]>] [[-Count] <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Adds an allow ACE for a trustee to the security descriptor of the SMB share.",
      name: "Grant-SmbShareAccess",
      params:
        "[-AccessRight {Full | Change | Read | Custom}] [-AccountName <String[]>] [-CimSession<CimSession[]>] [-Force] [-ThrottleLimit <Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Stops a transcript.",
      name: "Stop-Transcript",
      params: "[<CommonParameters>]"
    },
    %{
      description: "Retrieves a list of printers installed on a computer.",
      name: "Get-Printer",
      params:
        "[[-Name] <String[]>] [-CimSession <CimSession[]>] [-ComputerName <String>] [-Full] [-ThrottleLimit<Int32>] [<CommonParameters>]"
    },
    %{
      description:
        "Gets information about app packages (.appx) in an image that will be installed\n\n        for each new user.",
      name: "Get-AppxProvisionedPackage",
      params:
        "[-LogLevel {Errors | Warnings | WarningsInfo}] [-LogPath <String>] [-ScratchDirectory<String>] [-SystemDrive <String>] [-WindowsDirectory <String>] -Online* [<CommonParameters>]"
    },
    %{
      description: "Retrieves firewall rules from the target computer.",
      name: "Get-NetFirewallRule",
      params:
        "[-Action <Action[]>] [-AsJob] [-CimSession <CimSession[]>] [-Description <String[]>][-Direction <Direction[]>] [-DisplayGroup <String[]>] [-EdgeTraversalPolicy <EdgeTraversal[]>] [-Enabled<Enabled[]>] [-GPOSession <String>] [-Group <String[]>] [-LocalOnlyMapping <Boolean[]>] [-LooseSourceMapping<Boolean[]>] [-Owner <String[]>] [-PolicyStore <String>] [-PolicyStoreSource <String[]>] [-PolicyStoreSourceType<PolicyStoreType[]>] [-PrimaryStatus <PrimaryStatus[]>] [-Status <String[]>] [-ThrottleLimit <Int32>][-TracePolicyStore] [<CommonParameters>]"
    },
    %{
      description: "Add the local computer to a domain or workgroup.",
      name: "Add-Computer",
      params:
        "[-DomainName*] <String> [-ComputerName <String[]>] [-Confirm] -Credential* <PSCredential> [-Force][-LocalCredential <PSCredential>] [-NewName <String>] [-OUPath <String>] [-Options {AccountCreate | Win9XUpgrade |UnsecuredJoin | PasswordPass | DeferSPNSet | JoinWithNewName | JoinReadOnly | InstallInvoke}] [-PassThru][-Restart] [-Server <String>] [-UnjoinDomainCredential <PSCredential>] [-Unsecure] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Sets DNS server addresses associated with the TCP/IP properties on an\n\n        interface.",
      name: "Set-DnsClientServerAddress",
      params:
        "[-InterfaceAlias*] <String[]> [-CimSession <CimSession[]>] [-PassThru][-ResetServerAddresses] [-ServerAddresses <String[]>] [-ThrottleLimit <Int32>] [-Validate] [-Confirm] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Determines whether all elements of a file or directory path exist.",
      name: "Test-Path",
      params:
        "[-Credential <PSCredential>] [-Exclude <String[]>] [-Filter <String>] [-Include <String[]>] [-IsValid]-LiteralPath* <String[]> [-NewerThan <DateTime>] [-OlderThan <DateTime>] [-Path*Type {Any | Container | Leaf}][-UseTransaction] [<CommonParameters>]"
    },
    %{
      description: "Starts one or more processes on the local computer.",
      name: "Start-Process",
      params:
        "[-FilePath*] <String> [[-ArgumentList] <String[]>] [-Credential <PSCredential>] [-LoadUserProfile][-NoNewWindow] [-PassThru] [-RedirectStandardError <String>] [-RedirectStandardInput <String>][-RedirectStandardOutput <String>] [-UseNewEnvironment] [-Wait] [-WindowStyle {Normal | Hidden | Minimized |Maximized}] [-WorkingDirectory <String>] [<CommonParameters>]"
    },
    %{
      description: "Sets the user culture for the current user account.",
      name: "Set-Culture",
      params: "[-CultureInfo*] <CultureInfo> [<CommonParameters>]"
    },
    %{
      description: "Stops one or more running services.",
      name: "Stop-Service",
      params:
        "[-Confirm] -DisplayName* <String[]> [-Exclude <String[]>] [-Force] [-Include <String[]>] [-NoWait][-PassThru] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Selects objects or object properties.",
      name: "Select-Object",
      params:
        "[[-Property] <Object[]>] [-ExcludeProperty <String[]>] [-ExpandProperty <String>] [-First <Int32>][-InputObject <PSObject>] [-Last <Int32>] [-Skip <Int32>] [-Unique] [-Wait] [<CommonParameters>]"
    },
    %{
      description: "Modifies the properties of the SMB share.",
      name: "Set-SmbShare",
      params:
        "[-CachingMode {None | Manual | Documents | Programs | BranchCache | Unknown}] [-CATimeout <UInt32>][-CimSession <CimSession[]>] [-ConcurrentUserLimit <UInt32>] [-ContinuouslyAvailable <Boolean>] [-Description<String>] [-EncryptData <Boolean>] [-FolderEnumerationMode {AccessBased | Unrestricted}] [-Force] [-PassThru][-SecurityDescriptor <String>] [-ThrottleLimit <Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Imports certificates and private keys from a Personal Information Exchange\n\n        (PFX) file to the destination store.",
      name: "Import-PfxCertificate",
      params:
        "[-FilePath*] <String> [[-CertStoreLocation] <String>] [-Exportable] [-Password<SecureString>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Gets instances of WMI classes or information about the available classes.",
      name: "Get-WmiObject",
      params:
        "[-Class*] <String> [[-Property] <String[]>] [-Amended] [-AsJob] [-Authentication {Default | None |Connect | Call | Packet | PacketIntegrity | PacketPrivacy | Unchanged}] [-Authority <String>] [-ComputerName<String[]>] [-Credential <PSCredential>] [-DirectRead] [-EnableAllPrivileges] [-Filter <String>] [-Impersonation{Default | Anonymous | Identify | Impersonate | Delegate}] [-Locale <String>] [-Namespace <String>][-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Gets TCP connections.",
      name: "Get-NetTCPConnection",
      params:
        "[[-LocalAddress] <String[]>] [[-LocalPort] <UInt16[]>] [-AppliedSetting <AppliedSetting[]>][-CimSession <CimSession[]>] [-CreationTime <DateTime[]>] [-OffloadState <OffloadState[]>] [-OwningProcess<UInt32[]>] [-RemoteAddress <String[]>] [-RemotePort <UInt16[]>] [-State <State[]>] [-ThrottleLimit <Int32>][<CommonParameters>]"
    },
    %{
      description:
        "Mounts a previously created disk image (virtual hard disk or ISO), making it\n\n        appear as a normal disk.",
      name: "Mount-DiskImage",
      params:
        "[-ImagePath*] <String[]> [-Access {Unknown | ReadWrite | ReadOnly}] [-CimSession <CimSession[]>][-NoDriveLetter] [-PassThru] [-StorageType {Unknown | ISO | VHD | VHDX | VHDSet}] [-ThrottleLimit <Int32>][-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Creates table-like custom objects from the items in a CSV file.",
      name: "Import-Csv",
      params:
        "[[-Path] <String[]>] [[-Delimiter] <Char>] [-Encoding {Unicode | UTF7 | UTF8 | ASCII | UTF32 |BigEndianUnicode | Default | OEM}] [-Header <String[]>] [-LiteralPath <String[]>] [<CommonParameters>]"
    },
    %{
      description: "Restarts (\"reboots\") the operating system on local and remote computers.",
      name: "Restart-Computer",
      params:
        "[[-ComputerName] <String[]>] [[-Credential] <PSCredential>] [-AsJob] [-Confirm][-DcomAuthentication {Default | None | Connect | Call | Packet | PacketIntegrity | PacketPrivacy | Unchanged}][-Force] [-Impersonation {Default | Anonymous | Identify | Impersonate | Delegate}] [-ThrottleLimit <Int32>][-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Adds the current location to the top of a location stack.",
      name: "Push-Location",
      params:
        "[-LiteralPath <String>] [-PassThru] [-StackName <String>] [-UseTransaction] [<CommonParameters>]"
    },
    %{
      description: "Gets the Windows PowerShell sessions on local and remote computers.",
      name: "Get-PSSession",
      params:
        "[-ConnectionUri*] <Uri[]> [-AllowRedirection] [-Authentication {Default | Basic | Negotiate |NegotiateWithImplicitCredential | Credssp | Digest | Kerberos}] [-CertificateThumbprint <String>][-ConfigurationName <String>] [-Credential <PSCredential>] -InstanceId* <Guid[]> [-SessionOption <PSSessionOption>][-State {All | Opened | Disconnected | Closed | Broken}] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Adds a VPN connection to the Connection Manager phone book.",
      name: "Add-VpnConnection",
      params:
        "[[-RememberCredential]] [[-UseWinlogonCredential]] [[-EapConfigXmlStream] <XmlDocument>] [-Name*]<String> [-ServerAddress*] <String> [[-TunnelType] {Pptp | L2tp | Sstp | Ikev2 | Automatic}] [[-EncryptionLevel]{NoEncryption | Optional | Required | Maximum | Custom}] [[-AuthenticationMethod] {Pap | Chap | MSChapv2 | Eap |MachineCertificate}] [[-SplitTunneling]] [[-AllUserConnection]] [[-L2tpPsk] <String>] [-CimSession <CimSession[]>][-DnsSuffix <String>] [-Force] [-IdleDisconnectSeconds <UInt32>] [-MachineCertificateEKUFilter <String[]>][-MachineCertificateIssuerFilter <X509Certificate2>] [-PassThru] [-ServerList <CimInstance[]>] [-ThrottleLimit<Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Closes one or more Windows PowerShell sessions (PSSessions).",
      name: "Remove-PSSession",
      params: "[-ComputerName*] <String[]> [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Calculates the numeric properties of objects, and the characters, words, and\n\n        lines in string objects, such asfiles of text.",
      name: "Measure-Object",
      params:
        "[[-Property] <String[]>] [-Average] [-InputObject <PSObject>] [-Maximum] [-Minimum] [-Sum][<CommonParameters>]"
    },
    %{
      description:
        "Sets attributes of a partition, such as active, read-only, and offline\n\n        states.",
      name: "Set-Partition",
      params:
        "[-DiskNumber*] <UInt32> [-PartitionNumber*] <UInt32> [-CimSession <CimSession[]>] [-GptType<System.String>] [-IsActive <Boolean>] [-IsDAX] [-IsHidden <Boolean>] [-IsReadOnly <Boolean>] [-IsShadowCopy][-MbrType <System.UInt16>] [-NoDefaultDriveLetter <Boolean>] [-ThrottleLimit <Int32>] [-Confirm] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Registers a scheduled task definition on a local computer.",
      name: "Register-ScheduledTask",
      params:
        "[-TaskName*] <String> [[-TaskPath] <String>] [-Action*] <CimInstance[]> [[-Trigger]<CimInstance[]>] [[-Settings] <CimInstance>] [[-User] <String>] [[-Password] <String>] [[-RunLevel] {Limited |Highest}] [[-Description] <String>] [-CimSession <CimSession[]>] [-Force] [-ThrottleLimit <Int32>][<CommonParameters>]"
    },
    %{
      description: "Writes a debug message to the console.",
      name: "Write-Debug",
      params: "[-Message*] <String> [<CommonParameters>]"
    },
    %{
      description: "Sets the SMB client configuration.",
      name: "Set-SmbClientConfiguration",
      params:
        "[-CimSession <CimSession[]>] [-ConnectionCountPerRssNetworkInterface <UInt32>][-DirectoryCacheEntriesMax <UInt32>] [-DirectoryCacheEntrySizeMax <UInt32>] [-DirectoryCacheLifetime <UInt32>][-DormantFileLimit <UInt32>] [-EnableBandwidthThrottling <Boolean>] [-EnableByteRangeLockingOnReadOnlyFiles<Boolean>] [-EnableLargeMtu <Boolean>] [-EnableLoadBalanceScaleOut <System.Boolean>] [-EnableMultiChannel<Boolean>] [-EnableSecuritySignature <Boolean>] [-ExtendedSessionTimeout <UInt32>] [-FileInfoCacheEntriesMax<UInt32>] [-FileInfoCacheLifetime <UInt32>] [-FileNotFoundCacheEntriesMax <UInt32>] [-FileNotFoundCacheLifetime<UInt32>] [-Force] [-KeepConn <UInt32>] [-MaxCmds <UInt32>] [-MaximumConnectionCountPerServer <UInt32>][-OplocksDisabled <Boolean>] [-RequireSecuritySignature <Boolean>] [-SessionTimeout <UInt32>] [-ThrottleLimit<Int32>] [-UseOpportunisticLocking <Boolean>] [-WindowSizeThreshold <UInt32>] [-Confirm] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Installs a printer port on the specified computer.",
      name: "Add-PrinterPort",
      params:
        "[-Name*] <String> [-CimSession <CimSession[]>] [-ComputerName <String>] [-ThrottleLimit <Int32>][-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Modifies a local user account.",
      name: "Set-LocalUser",
      params:
        "[-InputObject*] <LocalUser> [-AccountExpires <DateTime>] [-AccountNeverExpires] [-Confirm][-Description <String>] [-FullName <String>] [-Password <SecureString>] [-PasswordNeverExpires <Boolean>][-UserMayChangePassword <Boolean>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Gets members from a local group.",
      name: "Get-LocalGroupMember",
      params: "[-Group*] <LocalGroup> [[-Member] <String>] [<CommonParameters>]"
    },
    %{
      description: "Optimizes a volume.",
      name: "Optimize-Volume",
      params:
        "[-DriveLetter*] <Char[]> [-Analyze] [-CimSession <CimSession[]>] [-Defrag] [-NormalPriority][-ReTrim] [-SlabConsolidate] [-ThrottleLimit <Int32>] [-TierOptimize] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Formats the output as a table.",
      name: "Format-Table",
      params:
        "[[-Property] <Object[]>] [-AutoSize] [-DisplayError] [-Expand {CoreOnly | EnumOnly | Both}] [-Force][-GroupBy <Object>] [-HideTableHeaders] [-InputObject <PSObject>] [-ShowError] [-View <String>] [-Wrap][<CommonParameters>]"
    },
    %{
      description: "Sends an email message.",
      name: "Send-MailMessage",
      params:
        "[-To*] <String[]> [-Subject*] <String> [[-Body] <String>] [[-SmtpServer] <String>] [-Attachments<String[]>] [-Bcc <String[]>] [-BodyAsHtml] [-Cc <String[]>] [-Credential <PSCredential>][-DeliveryNotificationOption {None | OnSuccess | OnFailure | Delay | Never}] [-Encoding <Encoding>] -From* <String>[-Port <Int32>] [-Priority {Normal | Low | High}] [-UseSsl] [<CommonParameters>]"
    },
    %{
      description: "Gets the current date and time.",
      name: "Get-Date",
      params:
        "[[-Date] <DateTime>] [-Day <Int32>] [-DisplayHint {Date | Time | DateTime}] [-Format <String>] [-Hour<Int32>] [-Millisecond <Int32>] [-Minute <Int32>] [-Month <Int32>] [-Second <Int32>] [-Year <Int32>][<CommonParameters>]"
    },
    %{
      description: "Gets PowerShell repositories.",
      name: "Get-PSRepository",
      params: "[[-Name] <String[]>] [<CommonParameters>]"
    },
    %{
      description:
        "Retrieves basic information about the files that are open on behalf of the\n\n        clients of the SMB server.",
      name: "Get-SmbOpenFile",
      params:
        "[[-FileId] <UInt64[]>] [[-SessionId] <UInt64[]>] [[-ClientComputerName] <String[]>][[-ClientUserName] <String[]>] [[-ScopeName] <String[]>] [[-ClusterNodeName] <String[]>] [-CimSession<CimSession[]>] [-IncludeHidden] [-SmbInstance {Default | CSV}] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Removes a physical disk from a specified storage pool.",
      name: "Remove-PhysicalDisk",
      params:
        "[-VirtualDisk*] <CimInstance> [-CimSession <CimSession[]>] [-ThrottleLimit <Int32>]-PhysicalDisks* <CimInstance[]> [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Configures preferences for Windows Defender scans and updates.",
      name: "Set-MpPreference",
      params:
        "[-CheckForSignaturesBeforeRunningScan <Boolean>] [-CimSession <CimSession[]>][-DisableArchiveScanning <Boolean>] [-DisableAutoExclusions <Boolean>] [-DisableBehaviorMonitoring <Boolean>][-DisableCatchupFullScan <Boolean>] [-DisableCatchupQuickScan <Boolean>] [-DisableEmailScanning <Boolean>][-DisableIntrusionPreventionSystem <Boolean>] [-DisableIOAVProtection <Boolean>] [-DisablePrivacyMode <Boolean>][-DisableRealtimeMonitoring <Boolean>] [-DisableRemovableDriveScanning <Boolean>] [-DisableRestorePoint <Boolean>][-DisableScanningMappedNetworkDrivesForFullScan <Boolean>] [-DisableScanningNetworkFiles <Boolean>][-DisableScriptScanning <Boolean>] [-ExclusionExtension <String[]>] [-ExclusionPath <String[]>] [-ExclusionProcess<String[]>] [-Force] [-HighThreatDefaultAction {Clean | Quarantine | Remove | Allow | UserDefined | NoAction |Block}] [-LowThreatDefaultAction {Clean | Quarantine | Remove | Allow | UserDefined | NoAction | Block}][-MAPSReporting {Disabled | Basic | Advanced}] [-ModerateThreatDefaultAction {Clean | Quarantine | Remove | Allow| UserDefined | NoAction | Block}] [-QuarantinePurgeItemsAfterDelay <UInt32>] [-RandomizeScheduleTaskTimes<Boolean>] [-RealTimeScanDirection {Both | Incoming | Outcoming}] [-RemediationScheduleDay {Everyday | Sunday |Monday | Tuesday | Wednesday | Thursday | Friday | Saturday | Never}] [-RemediationScheduleTime <DateTime>][-ReportingAdditionalActionTimeOut <UInt32>] [-ReportingCriticalFailureTimeOut <UInt32>][-ReportingNonCriticalTimeOut <UInt32>] [-ScanAvgCPULoadFactor <Byte>] [-ScanOnlyIfIdleEnabled <Boolean>][-ScanParameters {QuickScan | FullScan}] [-ScanPurgeItemsAfterDelay <UInt32>] [-ScanScheduleDay {Everyday | Sunday| Monday | Tuesday | Wednesday | Thursday | Friday | Saturday | Never}] [-ScanScheduleQuickScanTime <DateTime>][-ScanScheduleTime <DateTime>] [-SevereThreatDefaultAction {Clean | Quarantine | Remove | Allow | UserDefined |NoAction | Block}] [-SignatureAuGracePeriod <UInt32>] [-SignatureDefinitionUpdateFileSharesSources <String>][-SignatureDisableUpdateOnStartupWithoutEngine <Boolean>] [-SignatureFallbackOrder <String>][-SignatureFirstAuGracePeriod <UInt32>] [-SignatureScheduleDay {Everyday | Sunday | Monday | Tuesday | Wednesday |Thursday | Friday | Saturday | Never}] [-SignatureScheduleTime <DateTime>] [-SignatureUpdateCatchupInterval<UInt32>] [-SignatureUpdateInterval <UInt32>] [-SubmitSamplesConsent {None | Always | Never}][-ThreatIDDefaultAction_Actions <ThreatAction[]>] [-ThreatIDDefaultAction_Ids <Int64[]>] [-ThrottleLimit <Int32>][-UILockdown <Boolean>] [-UnknownThreatDefaultAction {Clean | Quarantine | Remove | Allow | UserDefined | NoAction| Block}] [<CommonParameters>]"
    },
    %{
      description: "Updates a script.",
      name: "Update-Script",
      params:
        "[[-Name] <String[]>] [-Confirm] [-Credential <PSCredential>] [-Force] [-MaximumVersion <Version>][-Proxy <Uri>] [-ProxyCredential <PSCredential>] [-RequiredVersion <Version>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Gets run-time information for a scheduled task.",
      name: "Get-ScheduledTaskInfo",
      params:
        "[-TaskName*] <String> [[-TaskPath] <String>] [-CimSession <CimSession[]>] [-ThrottleLimit<Int32>] [<CommonParameters>]"
    },
    %{
      description: "Creates a new NIC team.",
      name: "New-NetLbfoTeam",
      params:
        "[-Name*] <String> [-TeamMembers*] <WildcardPattern[]> [[-TeamNicName] <String>] [[-TeamingMode]<TeamingModes>] [[-LoadBalancingAlgorithm] <LBAlgos>] [-AsJob] [-CimSession <CimSession[]>] [-ThrottleLimit<Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Converts a string containing one or more key and value pairs to a hash\n\n        table.",
      name: "ConvertFrom-StringData",
      params: "[-StringData*] <String> [<CommonParameters>]"
    },
    %{
      description:
        "Returns a list of VirtualDisk objects, across all storage pools, across all\n\n        providers, or optionally a filteredsubset based on provided criteria.",
      name: "Get-VirtualDisk",
      params:
        "[[-FriendlyName] <String[]>] [-CimSession <CimSession[]>] [-HealthStatus <HealthStatus[]>][-IsSnapshot <Boolean[]>] [-OtherUsageDescription <String[]>] [-ThrottleLimit <Int32>] [-Usage <Usage[]>][<CommonParameters>]"
    },
    %{
      description:
        "Formats objects as a wide table that displays only one property of each\n\n        object.",
      name: "Format-Wide",
      params:
        "[[-Property] <Object>] [-AutoSize] [-Column <Int32>] [-DisplayError] [-Expand {CoreOnly | EnumOnly |Both}] [-Force] [-GroupBy <Object>] [-InputObject <PSObject>] [-ShowError] [-View <String>] [<CommonParameters>]"
    },
    %{
      description:
        "Gets a list of all PhysicalDisk objects visible across any available Storage\n\n        Management Providers, or optionally afiltered list.",
      name: "Get-PhysicalDisk",
      params:
        "[-CanPool] [-CimSession <CimSession>] [-Description <String>] [-HealthStatus<Get-PhysicalDisk.PhysicalDiskHealthStatus>] [-Manufacturer <String>] [-Model <String>] [-UniqueId <String>][-Usage <Get-PhysicalDisk.PhysicalDiskUsage>] [<CommonParameters>]"
    },
    %{
      description: "Uninstalls a module.",
      name: "Uninstall-Module",
      params:
        "[-Name*] <String[]> [-AllVersions] [-Confirm] [-Force] [-MaximumVersion <Version>][-MinimumVersion <Version>] [-RequiredVersion <Version>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Ends an interactive session with a remote computer.",
      name: "Exit-PSSession",
      params: "[<CommonParameters>]"
    },
    %{
      description: "Creates a TimeSpan object.",
      name: "New-TimeSpan",
      params:
        "[-Days <Int32>] [-Hours <Int32>] [-Minutes <Int32>] [-Seconds <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Calls WMI methods.",
      name: "Invoke-WmiMethod",
      params:
        "[-Class*] <String> [-Name*] <String> [-ArgumentList <Object[]>] [-AsJob] [-Authentication {Default| None | Connect | Call | Packet | PacketIntegrity | PacketPrivacy | Unchanged}] [-Authority <String>][-ComputerName <String[]>] [-Confirm] [-Credential <PSCredential>] [-EnableAllPrivileges] [-Impersonation {Default| Anonymous | Identify | Impersonate | Delegate}] [-Locale <String>] [-Namespace <String>] [-ThrottleLimit<Int32>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Imports commands from another session into the current session.",
      name: "Import-PSSession",
      params:
        "[-Session*] <PSSession> [[-CommandName] <String[]>] [[-FormatTypeName] <String[]>] [-AllowClobber][-ArgumentList <Object[]>] [-Certificate <X509Certificate2>] [-CommandType {Alias | Function | Filter | Cmdlet |ExternalScript | Application | Script | Workflow | Configuration | All}] [-DisableNameChecking][-FullyQualifiedModule <ModuleSpecification[]>] [-Module <String[]>] [-Prefix <String>] [<CommonParameters>]"
    },
    %{
      description: "Sends output to a printer.",
      name: "Out-Printer",
      params: "[[-Name] <String>] [-InputObject <PSObject>] [<CommonParameters>]"
    },
    %{
      description:
        "Imports a CLIXML file and creates corresponding objects in Windows\n\n        PowerShell.",
      name: "Import-Clixml",
      params:
        "[-First <UInt64>] [-IncludeTotalCount] -LiteralPath* <String[]> [-Skip <UInt64>] [<CommonParameters>]"
    },
    %{
      description: "Runs commands on local and remote computers.",
      name: "Invoke-Command",
      params:
        "[[-ConnectionUri] <Uri[]>] [-ScriptBlock*] <ScriptBlock> [-AllowRedirection] [-ArgumentList<Object[]>] [-AsJob] [-Authentication {Default | Basic | Negotiate | NegotiateWithImplicitCredential | Credssp |Digest | Kerberos}] [-CertificateThumbprint <String>] [-ConfigurationName <String>] [-Credential <PSCredential>][-EnableNetworkAccess] [-HideComputerName] [-InDisconnectedSession] [-InputObject <PSObject>] [-JobName <String>][-SessionOption <PSSessionOption>] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Creates a local user account.",
      name: "New-LocalUser",
      params:
        "[-Name*] <String> [-AccountExpires <DateTime>] [-AccountNeverExpires] [-Confirm] [-Description<String>] [-Disabled] [-FullName <String>] -NoPassword* [-UserMayNotChangePassword] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Creates or changes the value of a property of an item.",
      name: "Set-ItemProperty",
      params:
        "[-Path*] <String[]> [-Confirm] [-Credential <PSCredential>] [-Exclude <String[]>] [-Filter<String>] [-Force] [-Include <String[]>] -InputObject* <PSObject> [-PassThru] [-UseTransaction] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Changes the properties of a registered session configuration.",
      name: "Set-PSSessionConfiguration",
      params:
        "[-Name*] <String> [-AccessMode {Disabled | Local | Remote}] [-ApplicationBase <String>][-Confirm] [-Force] [-MaximumReceivedDataSizePerCommandMB <Double>] [-MaximumReceivedObjectSizeMB <Double>][-ModulesToImport <Object[]>] [-NoServiceRestart] [-PSVersion <Version>] [-RunAsCredential <PSCredential>][-SecurityDescriptorSddl <String>] [-SessionTypeOption <PSSessionTypeOption>] [-ShowSecurityDescriptorUI][-StartupScript <String>] [-ThreadApartmentState {STA | MTA | Unknown}] [-ThreadOptions {Default | UseNewThread |ReuseThread | UseCurrentThread}] [-TransportOption <PSTransportOption>] [-UseSharedProcess] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Gets the VMQ properties of a network adapter.",
      name: "Get-NetAdapterVmq",
      params:
        "[[-Name] <String[]>] [-AsJob] [-CimSession <CimSession[]>] [-IncludeHidden] [-ThrottleLimit<Int32>] [<CommonParameters>]"
    },
    %{
      description: "Copies an item from one location to another.",
      name: "Copy-Item",
      params:
        "[[-Destination] <String>] [-Confirm] [-Container] [-Credential <PSCredential>] [-Exclude <String[]>][-Filter <String>] [-Force] [-FromSession <PSSession>] [-Include <String[]>] -LiteralPath* <String[]> [-PassThru][-Recurse] [-ToSession <PSSession>] [-UseTransaction] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Starts an interactive session with a remote computer.",
      name: "Enter-PSSession",
      params:
        "[[-ConnectionUri] <Uri>] [-AllowRedirection] [-Authentication {Default | Basic | Negotiate |NegotiateWithImplicitCredential | Credssp | Digest | Kerberos}] [-CertificateThumbprint <String>][-ConfigurationName <String>] [-Credential <PSCredential>] [-EnableNetworkAccess] [-SessionOption<PSSessionOption>] [<CommonParameters>]"
    },
    %{
      description: "Gets a consolidated object of system and operating system properties.",
      name: "Get-ComputerInfo",
      params: "[[-Property] <String[]>] [<CommonParameters>]"
    },
    %{
      description:
        "Sets the value of a variable. Creates the variable if one with the requested\n\n        name does not exist.",
      name: "Set-Variable",
      params:
        "[-Name*] <String[]> [[-Value] <Object>] [-Confirm] [-Description <String>] [-Exclude <String[]>][-Force] [-Include <String[]>] [-Option {None | ReadOnly | Constant | Private | AllScope | Unspecified}][-PassThru] [-Scope <String>] [-Visibility {Public | Private}] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Retrieves the ACL of the SMB share.",
      name: "Get-SmbShareAccess",
      params:
        "[-Name*] <String[]> [[-ScopeName] <String[]>] [-CimSession <CimSession[]>] [-SmbInstance{Default | CSV}] [-ThrottleLimit <Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Adds an Authenticode signature to a Windows PowerShell script or other file.",
      name: "Set-AuthenticodeSignature",
      params:
        "[-Certificate*] <X509Certificate2> [-Confirm] -Content* <Byte[]> [-Force] [-HashAlgorithm<String>] [-IncludeChain {signer | notroot | all}] -SourcePathOrExtension* <String[]> [-TimestampServer <String>][-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Converts a JSON-formatted string to a custom object.",
      name: "ConvertFrom-Json",
      params: "[-InputObject*] <String> [<CommonParameters>]"
    },
    %{
      description: "Gets information about optional features in a Windows image.",
      name: "Get-WindowsOptionalFeature",
      params:
        "[-FeatureName <String>] [-LogLevel {Errors | Warnings | WarningsInfo}] [-LogPath<String>] [-PackageName <String>] [-PackagePath <String>] [-ScratchDirectory <String>] [-SystemDrive <String>][-WindowsDirectory <String>] -Online* [<CommonParameters>]"
    },
    %{
      description: "Combines a path and a child path into a single path.",
      name: "Join-Path",
      params:
        "[-Path*] <String[]> [-ChildPath*] <String> [-Credential <PSCredential>] [-Resolve] [-UseTransaction][<CommonParameters>]"
    },
    %{
      description: "Sets the VMQ properties of a network adapter.",
      name: "Set-NetAdapterVmq",
      params:
        "[-Name*] <String[]> [-AsJob] [-BaseProcessorGroup <UInt16>] [-BaseProcessorNumber <Byte>][-CimSession <CimSession[]>] [-Enabled <Boolean>] [-IncludeHidden] [-MaxProcessorNumber <Byte>] [-MaxProcessors<UInt32>] [-NoRestart] [-NumaNode <UInt16>] [-PassThru] [-ThrottleLimit <Int32>] [-Confirm] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Adds a.NET Framework type (a class) to a Windows PowerShell session.",
      name: "Add-Type",
      params:
        "[-Name*] <String> [-MemberDefinition*] <String[]> [-CodeDomProvider <CodeDomProvider>] [-CompilerParameters<CompilerParameters>] [-IgnoreWarnings] [-Language {CSharp | CSharpVersion3 | CSharpVersion2 | VisualBasic |JScript}] [-Namespace <String>] [-OutputAssembly <String>] [-OutputType {Library | ConsoleApplication |WindowsApplication}] [-PassThru] [-ReferencedAssemblies <String[]>] [-UsingNamespace <String[]>][<CommonParameters>]"
    },
    %{
      description: "Imports one or more certificates into a certificate store.",
      name: "Import-Certificate",
      params:
        "[-FilePath*] <String> [-CertStoreLocation <String>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Adds an app package (.appx) that will install for each new user to a Windows\n\n        image.",
      name: "Add-AppxProvisionedPackage",
      params:
        "[-CustomDataPath <String>] [-DependencyPackagePath <String[]>] [-FolderPath <String>][-LicensePath <String>] [-LogLevel {Errors | Warnings | WarningsInfo}] [-LogPath <String>] [-PackagePath <String>][-ScratchDirectory <String>] [-SkipLicense] [-SystemDrive <String>] [-WindowsDirectory <String>] -Online*[<CommonParameters>]"
    },
    %{
      description: "Gets information about volumes that BitLocker can protect.",
      name: "Get-BitLockerVolume",
      params: "[[-MountPoint] <String[]>] [<CommonParameters>]"
    },
    %{
      description: "Gets scheduled jobs on the local computer.",
      name: "Get-ScheduledJob",
      params: "[[-Id] <Int32[]>] [<CommonParameters>]"
    },
    %{
      description: "Exports the layout of the Start screen.",
      name: "Export-StartLayout",
      params:
        "[-Path*] <String> [-InformationAction {SilentlyContinue | Stop | Continue | Inquire | Ignore |Suspend}] [-InformationVariable <System.String>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Changes the system time on the computer to a time that you specify.",
      name: "Set-Date",
      params:
        "[-Adjust*] <TimeSpan> [-Confirm] [-DisplayHint {Date | Time | DateTime}] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Deletes files and folders.",
      name: "Remove-Item",
      params:
        "[-Confirm] [-Credential <PSCredential>] [-Exclude <String[]>] [-Filter <String>] [-Force] [-Include<String[]>] -LiteralPath* <String[]> [-Recurse] [-Stream <String[]>] [-UseTransaction] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Specifies the module members that are exported.",
      name: "Export-ModuleMember",
      params:
        "[[-Function] <String[]>] [-Alias <String[]>] [-Cmdlet <String[]>] [-Variable <String[]>][<CommonParameters>]"
    },
    %{
      description: "Applies LCM settings to nodes.",
      name: "Set-DscLocalConfigurationManager",
      params:
        "[-Path*] <String> -CimSession* <CimSession[]> [-Confirm] [-Force] [-ThrottleLimit<Int32>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Downloads and installs the newest help files on your computer.",
      name: "Update-Help",
      params:
        "[[-Module] <String[]>] [[-UICulture] <CultureInfo[]>] [-Confirm] [-Credential <PSCredential>] [-Force][-FullyQualifiedModule <ModuleSpecification[]>] [-LiteralPath <String[]>] [-Recurse] [-UseDefaultCredentials][-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Registers a PowerShell repository.",
      name: "Register-PSRepository",
      params:
        "[-Name*] <String> [-SourceLocation*] <Uri> [-Credential <PSCredential>] [-InstallationPolicy{Trusted | Untrusted}] [-PackageManagementProvider <String>] [-Proxy <Uri>] [-ProxyCredential <PSCredential>][-PublishLocation <Uri>] [-ScriptPublishLocation <Uri>] [-ScriptSourceLocation <Uri>] [<CommonParameters>]"
    },
    %{
      description:
        "Establishes and enforces coding rules in expressions, scripts, and script\n\n        blocks.",
      name: "Set-StrictMode",
      params: "-Off* [<CommonParameters>]"
    },
    %{
      description: "Creates an SMB mapping.",
      name: "New-SmbMapping",
      params:
        "[[-LocalPath] <String>] [[-RemotePath] <String>] [-CimSession <CimSession[]>] [-HomeFolder][-Password <String>] [-Persistent <Boolean>] [-SaveCredentials] [-ThrottleLimit <Int32>] [-UserName <String>][-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Gets Windows PowerShell background jobs that are running in the current\n\n        session.",
      name: "Get-Job",
      params:
        "[[-Id] <Int32[]>] [-After <DateTime>] [-Before <DateTime>] [-ChildJobState {NotStarted | Running |Completed | Failed | Stopped | Blocked | Suspended | Disconnected | Suspending | Stopping | AtBreakpoint}][-HasMoreData <Boolean>] [-IncludeChildJob] [-Newest <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Stops and then starts one or more services.",
      name: "Restart-Service",
      params:
        "[-Confirm] -DisplayName* <String[]> [-Exclude <String[]>] [-Force] [-Include <String[]>][-PassThru] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Sets the current Windows clipboard entry.",
      name: "Set-Clipboard",
      params:
        "[-Append] [-AsHtml] [-Confirm] -LiteralPath* <String[]> [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Creates a NAT object.",
      name: "New-NetNat",
      params:
        "[-Name*] <String> [-AsJob] [-CimSession <CimSession[]>] [-InternalRoutingDomainId <String>][-ThrottleLimit <Int32>] -ExternalIPInterfaceAddressPrefix* <String> [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Installs one or more software packages.",
      name: "Install-Package",
      params:
        "[-AdditionalArguments <String[]>] [-AllVersions] [-Confirm] [-Credential <PSCredential>] [-Force][-ForceBootstrap] [-Proxy <Uri>] [-ProxyCredential <PSCredential>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Installs a printer driver on the specified computer.",
      name: "Add-PrinterDriver",
      params:
        "[-Name*] <String> [[-InfPath] <String>] [-CimSession <CimSession[]>] [-ComputerName <String>][-PrinterEnvironment <String>] [-ThrottleLimit <Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Removes an IP address and its configuration.",
      name: "Remove-NetIPAddress",
      params:
        "[[-IPAddress] <String[]>] [-AddressFamily <AddressFamily[]>] [-AddressState <AddressState[]>][-CimSession <CimSession[]>] [-DefaultGateway <String>] [-IncludeAllCompartments] [-InterfaceAlias <String[]>][-InterfaceIndex <UInt32[]>] [-PassThru] [-PolicyStore <String>] [-PreferredLifetime <TimeSpan[]>] [-PrefixLength<Byte[]>] [-PrefixOrigin <PrefixOrigin[]>] [-SkipAsSource <Boolean[]>] [-SuffixOrigin <SuffixOrigin[]>][-ThrottleLimit <Int32>] [-Type <Type[]>] [-ValidLifetime <TimeSpan[]>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Submits a certificate request to an enrollment server and installs the\n\n        response or retrieves a certificate for apreviously submitted request.",
      name: "Get-Certificate",
      params:
        "[-CertStoreLocation <String>] [-Credential <PkiCredential>] [-DnsName <String[]>] [-SubjectName<String>] [-Url <Uri>] -Template* <String> [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description:
        "Tests and repairs the secure channel between the local computer and its\n\n        domain.",
      name: "Test-ComputerSecureChannel",
      params:
        "[-Confirm] [-Credential <PSCredential>] [-Repair] [-Server <String>] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Gets information about the current working location or a location stack.",
      name: "Get-Location",
      params:
        "[-PSDrive <String[]>] [-PSProvider <String[]>] [-UseTransaction] [<CommonParameters>]"
    },
    %{
      description:
        "Downloads and installs the newest version of specified modules from an online\n\n        gallery to the local computer.",
      name: "Update-Module",
      params:
        "[[-Name] <String[]>] [-Confirm] [-Credential <PSCredential>] [-Force] [-MaximumVersion <Version>][-Proxy <Uri>] [-ProxyCredential <PSCredential>] [-RequiredVersion <Version>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Modifies settings for Windows Defender.",
      name: "Add-MpPreference",
      params:
        "[-CimSession <CimSession[]>] [-ExclusionExtension <String[]>] [-ExclusionPath <String[]>][-ExclusionProcess <String[]>] [-Force] [-ThreatIDDefaultAction_Actions <ThreatAction[]>][-ThreatIDDefaultAction_Ids <Int64[]>] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description:
        "Gets the modules that have been imported or that can be imported into the\n\n        current session.",
      name: "Get-Module",
      params:
        "[[-Name] <String[]>] [-All] [-FullyQualifiedName <ModuleSpecification[]>] [<CommonParameters>]"
    },
    %{
      description:
        "Gets the processes that are running on the local computer or a remote\n\n        computer.",
      name: "Get-Process",
      params:
        "[[-Name] <String[]>] [-ComputerName <String[]>] [-FileVersionInfo] [-Module] [<CommonParameters>]"
    },
    %{
      description:
        "Suppresses the command prompt until one or all of the Windows PowerShell\n\n        background jobs running in the sessionare completed.",
      name: "Wait-Job",
      params: "[-Filter*] <Hashtable> [-Any] [-Force] [-Timeout <Int32>] [<CommonParameters>]"
    },
    %{
      description:
        "Gets the task definition object of a scheduled task that is registered on the\n\n        local computer.",
      name: "Get-ScheduledTask",
      params:
        "[[-TaskName] <String[]>] [[-TaskPath] <String[]>] [-CimSession <CimSession[]>] [-ThrottleLimit<Int32>] [<CommonParameters>]"
    },
    %{
      description:
        "Retrieves the connections established from the SMB client to the SMB\n\n        servers.",
      name: "Get-SmbConnection",
      params:
        "[[-ServerName] <String[]>] [[-UserName] <String[]>] [-CimSession <CimSession[]>] [-SmbInstance{Default | CSV}] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description:
        "Returns information about long-running Storage module jobs, such as a repair\n\n        task.",
      name: "Get-StorageJob",
      params:
        "[-CimSession <CimSession[]>] [-JobState <JobState[]>] [-ThrottleLimit <Int32>] [-UniqueId<String[]>] [<CommonParameters>]"
    },
    %{
      description: "Creates a CIM session.",
      name: "New-CimSession",
      params:
        "[[-ComputerName] <String[]>] [[-Credential] <PSCredential>] [-Authentication {Default | Digest |Negotiate | Basic | Kerberos | NtlmDomain | CredSsp}] [-Name <String>] [-OperationTimeoutSec <UInt32>] [-Port<UInt32>] [-SessionOption <CimSessionOptions>] [-SkipTestConnection] [<CommonParameters>]"
    },
    %{
      description: "Measures the time it takes to run script blocks and cmdlets.",
      name: "Measure-Command",
      params: "[-Expression*] <ScriptBlock> [-InputObject <PSObject>] [<CommonParameters>]"
    },
    %{
      description: "Displays diagnostic information for a connection.",
      name: "Test-NetConnection",
      params:
        "[[-ComputerName] <String>] [-CommonTCPPort*] {HTTP | RDP | SMB | WINRM} [-InformationLevel{Quiet | Detailed}] [<CommonParameters>]"
    },
    %{
      description: "Creates an XML-based representation of an object.",
      name: "ConvertTo-Xml",
      params:
        "[-InputObject*] <PSObject> [-As {Stream | String | Document}] [-Depth <Int32>] [-NoTypeInformation][<CommonParameters>]"
    },
    %{
      description:
        "Converts a path from a Windows PowerShell path to a Windows PowerShell\n\n        provider path.",
      name: "Convert-Path",
      params: "-LiteralPath* <String[]> [-UseTransaction] [<CommonParameters>]"
    },
    %{
      description: "Renames a computer.",
      name: "Rename-Computer",
      params:
        "[-NewName*] <String> [-ComputerName <String>] [-Confirm] [-DomainCredential <PSCredential>][-Force] [-LocalCredential <PSCredential>] [-PassThru] [-Protocol {DCOM | WSMan}] [-Restart] [-WhatIf][-WsmanAuthentication {Default | Basic | Negotiate | CredSSP | Digest | Kerberos}] [<CommonParameters>]"
    },
    %{
      description:
        "Downloads one or more modules from an online gallery, and installs them on the\n\n        local computer.",
      name: "Install-Module",
      params:
        "[-InputObject*] <PSObject[]> [-AllowClobber] [-Confirm] [-Credential <PSCredential>] [-Force][-Proxy <Uri>] [-ProxyCredential <PSCredential>] [-Scope {CurrentUser | AllUsers}] [-SkipPublisherCheck] [-WhatIf][<CommonParameters>]"
    },
    %{
      description:
        "Creates an XML-based representation of an object or objects and stores it in a\n\n        file.",
      name: "Export-Clixml",
      params:
        "[-Confirm] [-Depth <Int32>] [-Encoding {Unicode | UTF7 | UTF8 | ASCII | UTF32 | BigEndianUnicode |Default | OEM}] [-Force] -InputObject* <PSObject> -LiteralPath* <String> [-NoClobber] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Modifies the configuration of an IP address.",
      name: "Set-NetIPAddress",
      params:
        "[[-IPAddress] <String[]>] [-AddressFamily <AddressFamily[]>] [-AddressState <AddressState[]>][-CimSession <CimSession[]>] [-IncludeAllCompartments] [-InterfaceAlias <String[]>] [-InterfaceIndex <UInt32[]>][-PassThru] [-PolicyStore <String>] [-PreferredLifetime <TimeSpan>] [-PrefixLength <Byte>] [-PrefixOrigin<PrefixOrigin[]>] [-SkipAsSource <Boolean>] [-SuffixOrigin <SuffixOrigin[]>] [-ThrottleLimit <Int32>] [-Type<Type[]>] [-ValidLifetime <TimeSpan>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Creates an object that contains advanced options for a PSSession.",
      name: "New-PSSessionOption",
      params:
        "[-ApplicationArguments <PSPrimitiveDictionary>] [-CancelTimeout <Int32>] [-Culture<CultureInfo>] [-IdleTimeout <Int32>] [-IncludePortInSPN] [-MaxConnectionRetryCount <Int32>][-MaximumReceivedDataSizePerCommand <Int32>] [-MaximumReceivedObjectSize <Int32>] [-MaximumRedirection <Int32>][-NoCompression] [-NoEncryption] [-NoMachineProfile] [-OpenTimeout <Int32>] [-OperationTimeout <Int32>][-OutputBufferingMode {None | Drop | Block}] [-ProxyAccessType {None | IEConfig | WinHttpConfig | AutoDetect |NoProxyServer}] [-ProxyAuthentication {Default | Basic | Negotiate | NegotiateWithImplicitCredential | Credssp |Digest | Kerberos}] [-ProxyCredential <PSCredential>] [-SkipCACheck] [-SkipCNCheck] [-SkipRevocationCheck][-UICulture <CultureInfo>] [-UseUTF16] [<CommonParameters>]"
    },
    %{
      description: "Enables CredSSP authentication on a computer.",
      name: "Enable-WSManCredSSP",
      params:
        "[-Role*] {Client | Server} [[-DelegateComputer] <String[]>] [-Force] [<CommonParameters>]"
    },
    %{
      description: "Gets the associated BitsJob object for an existing BITS transfer job.",
      name: "Get-BitsTransfer",
      params: "[[-Name] <String[]>] [[-AllUsers]] [<CommonParameters>]"
    },
    %{
      description:
        "Sets the language list and associated properties for the current user\n\n        account.",
      name: "Set-WinUserLanguageList",
      params:
        "[-LanguageList*] <List<WinUserLanguage>> [-Force] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Gets the names and AppIDs of installed apps.",
      name: "Get-StartApps",
      params: "[[-Name] <Object>] [<CommonParameters>]"
    },
    %{
      description:
        "Mounts a Windows image in a WIM or VHD file to a directory on the local\n\n        computer.",
      name: "Mount-WindowsImage",
      params:
        "[-CheckIntegrity] [-LogLevel {Errors | Warnings | WarningsInfo}] [-LogPath <String>][-Optimize] [-ReadOnly] [-ScratchDirectory <String>] -ImagePath* <String> -Index* <UInt32> -Path* <String>[<CommonParameters>]"
    },
    %{
      description: "Repairs a Windows image in a WIM or VHD file.",
      name: "Repair-WindowsImage",
      params:
        "[-CheckHealth] [-LimitAccess] [-LogLevel {Errors | Warnings | WarningsInfo}] [-LogPath<String>] [-NoRestart] [-RestoreHealth] [-ScanHealth] [-ScratchDirectory <String>] [-Source <String[]>][-SystemDrive <String>] [-WindowsDirectory <String>] -Online* [<CommonParameters>]"
    },
    %{
      description: "Enables a feature in a Windows image.",
      name: "Enable-WindowsOptionalFeature",
      params:
        "[-All] [-LimitAccess] [-LogLevel {Errors | Warnings | WarningsInfo}] [-LogPath<String>] [-NoRestart] [-PackageName <String>] [-ScratchDirectory <String>] [-Source <String[]>] [-SystemDrive<String>] [-WindowsDirectory <String>] -FeatureName* <String[]> -Online* [<CommonParameters>]"
    },
    %{
      description: "Creates a scheduled task action.",
      name: "New-ScheduledTaskAction",
      params:
        "[-Execute*] <String> [[-Argument] <String>] [[-WorkingDirectory] <String>] [-CimSession<CimSession[]>] [-Id <String>] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Sends output to a file.",
      name: "Out-File",
      params:
        "[-FilePath*] <String> [[-Encoding] {unknown | string | unicode | bigendianunicode | utf8 | utf7 | utf32 |ascii | default | oem}] [-Append] [-Confirm] [-Force] [-InputObject <PSObject>] [-NoClobber] [-NoNewline][-WhatIf] [-Width <Int32>] [<CommonParameters>]"
    },
    %{
      description:
        "Retrieves information about the SMB sessions that are currently established\n\n        between the SMB server and theassociated clients.",
      name: "Get-SmbSession",
      params:
        "[[-SessionId] <UInt64[]>] [[-ClientComputerName] <String[]>] [[-ClientUserName] <String[]>][[-ScopeName] <String[]>] [[-ClusterNodeName] <String[]>] [-CimSession <CimSession[]>] [-IncludeHidden][-SmbInstance {Default | CSV}] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Modifies a scheduled task.",
      name: "Set-ScheduledTask",
      params:
        "[-TaskName*] <String> [[-TaskPath] <String>] [[-Action] <CimInstance[]>] [[-Trigger]<CimInstance[]>] [[-Settings] <CimInstance>] [[-User] <String>] [[-Password] <String>] [-CimSession<CimSession[]>] [-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Resets the machine account password for the computer.",
      name: "Reset-ComputerMachinePassword",
      params:
        "[-Confirm] [-Credential <PSCredential>] [-Server <String>] [-WhatIf][<CommonParameters>]"
    },
    %{
      description:
        "Creates a record of all or part of a Windows PowerShell session to a text\n\n        file.",
      name: "Start-Transcript",
      params:
        "[[-LiteralPath] <String>] [-Append] [-Confirm] [-Force] [-IncludeInvocationHeader] [-NoClobber][-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Gets the events in the event queue.",
      name: "Get-Event",
      params: "[-EventIdentifier*] <Int32> [<CommonParameters>]"
    },
    %{
      description: "Sends output to an interactive table in a separate window.",
      name: "Out-GridView",
      params:
        "[-InputObject <PSObject>] [-OutputMode {None | Single | Multiple}] [-Title <String>][<CommonParameters>]"
    },
    %{
      description:
        "Creates a new inbound or outbound firewall rule and adds the rule to the\n\n        target computer.",
      name: "New-NetFirewallRule",
      params:
        "[-Action <Action>] [-AsJob] [-Authentication <Authentication>] [-CimSession <CimSession[]>][-Description <String>] [-Direction <Direction>] [-DynamicTarget <DynamicTransport>] [-EdgeTraversalPolicy<EdgeTraversal>] [-Enabled <Enabled>] [-Encryption <Encryption>] [-GPOSession <String>] [-Group <String>][-IcmpType <String[]>] [-InterfaceAlias <WildcardPattern[]>] [-InterfaceType <InterfaceType>] [-LocalAddress<String[]>] [-LocalOnlyMapping <Boolean>] [-LocalPort <String[]>] [-LocalUser <String>] [-LooseSourceMapping<Boolean>] [-Name <String>] [-OverrideBlockRules <Boolean>] [-Owner <String>] [-Package <String>] [-Platform<String[]>] [-PolicyStore <String>] [-Profile <Profile>] [-Program <String>] [-Protocol <String>] [-RemoteAddress<String[]>] [-RemoteMachine <String>] [-RemotePort <String[]>] [-RemoteUser <String>] [-Service <String>][-ThrottleLimit <Int32>] -DisplayName* <String> [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Removes an app package (.appx) from a Windows image.",
      name: "Remove-AppxProvisionedPackage",
      params:
        "[-LogLevel {Errors | Warnings | WarningsInfo}] [-LogPath <String>][-ScratchDirectory <String>] [-SystemDrive <String>] [-WindowsDirectory <String>] -Online* -PackageName* <String>[<CommonParameters>]"
    },
    %{
      description: "Performs repairs on a volume.",
      name: "Repair-Volume",
      params:
        "[-DriveLetter*] <Char[]> [-CimSession <CimSession[]>] [-OfflineScanAndFix] [-Scan] [-SpotFix][-ThrottleLimit <Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Creates a new item.",
      name: "New-Item",
      params:
        "[[-Path*] <String[]>] [-Confirm] [-Credential <PSCredential>] [-Force] [-ItemType <String>] -Name* <String>[-UseTransaction] [-Value <Object>] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Modifies existing firewall rules.",
      name: "Set-NetFirewallRule",
      params:
        "[-Action <Action>] [-AsJob] [-Authentication <Authentication>] [-CimSession <CimSession[]>][-Description <String>] [-Direction <Direction>] [-DynamicTarget <DynamicTransport>] [-EdgeTraversalPolicy<EdgeTraversal>] [-Enabled <Enabled>] [-Encryption <Encryption>] [-GPOSession <String>] [-IcmpType <String[]>][-InterfaceAlias <WildcardPattern[]>] [-InterfaceType <InterfaceType>] [-LocalAddress <String[]>][-LocalOnlyMapping <Boolean>] [-LocalPort <String[]>] [-LocalUser <String>] [-LooseSourceMapping <Boolean>][-NewDisplayName <String>] [-OverrideBlockRules <Boolean>] [-Owner <String>] [-Package <String>] [-PassThru][-Platform <String[]>] [-PolicyStore <String>] [-Profile <Profile>] [-Program <String>] [-Protocol <String>][-RemoteAddress <String[]>] [-RemoteMachine <String>] [-RemotePort <String[]>] [-RemoteUser <String>] [-Service<String>] [-ThrottleLimit <Int32>] -DisplayGroup* <String[]> [-Confirm] [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Creates an archive, or zipped file, from specified files and folders.",
      name: "Compress-Archive",
      params:
        "[-Path*] <String[]> [-DestinationPath*] <String> [-CompressionLevel {Optimal | NoCompression |Fastest}] [-Confirm] -Force* [-WhatIf] [<CommonParameters>]"
    },
    %{
      description: "Gets the basic network adapter properties.",
      name: "Get-NetAdapter",
      params:
        "[[-Name] <String[]>] [-AsJob] [-CimSession <CimSession[]>] [-IncludeHidden] [-Physical][-ThrottleLimit <Int32>] [<CommonParameters>]"
    },
    %{
      description: "Reads a line of input from the console.",
      name: "Read-Host",
      params: "[[-Prompt] <Object>] [-AsSecureString] [<CommonParameters>]"
    },
    %{
      description: "Selects objects from a collection based on their property values.",
      name: "Where-Object",
      params:
        "[-Property*] <String> [[-Value] <Object>] -CContains* [-In*putObject <PSObject>] [<CommonParameters>]"
    },
    %{
      description:
        "Configures settings that apply to the per-profile configurations of the\n\n        Windows Firewall with Advanced Security.",
      name: "Set-NetFirewallProfile",
      params:
        "[-All] [-AllowInboundRules <GpoBoolean>] [-AllowLocalFirewallRules <GpoBoolean>][-AllowLocalIPsecRules <GpoBoolean>] [-AllowUnicastResponseToMulticast <GpoBoolean>] [-AllowUserApps <GpoBoolean>][-AllowUserPorts <GpoBoolean>] [-AsJob] [-CimSession <CimSession[]>] [-DefaultInboundAction <Action>][-DefaultOutboundAction <Action>] [-DisabledInterfaceAliases <String[]>] [-Enabled <GpoBoolean>][-EnableStealthModeForIPsec <GpoBoolean>] [-GPOSession <String>] [-LogAllowed <GpoBoolean>] [-LogBlocked<GpoBoolean>] [-LogFileName <String>] [-LogIgnored <GpoBoolean>] [-LogMaxSizeKilobytes <UInt64>] [-NotifyOnListen<GpoBoolean>] [-PassThru] [-PolicyStore <String>] [-ThrottleLimit <Int32>] [-Confirm] [-WhatIf][<CommonParameters>]"
    },
    %{
      description: "Adds members to a local group.",
      name: "Add-LocalGroupMember",
      params:
        "[-Group*] <LocalGroup> [-Member*] <LocalPrincipal[]> [-Confirm] [-WhatIf] [<CommonParameters>]"
    }
  ]

  @commands_by_id Enum.with_index(@commands, fn e, i -> {i, e} end) |> Map.new()

  @spec commands() :: [command()]
  def commands, do: @commands

  @spec commands_by_id() :: map()
  def commands_by_id, do: @commands_by_id
end
