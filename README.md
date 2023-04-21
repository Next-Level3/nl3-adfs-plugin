# Installation Steps for AD FS 2019 and 2022
### 1 - Download code and build in Visual Studio 2022
### 2 - Install the following files from the appropriate binary build folder (e.g., bin/Debug, bin/Release) on each AD FS server in your farm to a folder (e.g., C:\extensions).
- Microsoft.IdentityModel.JsonWebTokens.dll
- Microsoft.IdentityModel.Logging.dll
- Microsoft.IdentityModel.Tokens.dll
- Newtonsoft.Json.dll
- System.IdentityModel.Tokens.Jwt.dll
- ThreatDetectionModule.dll
### 3 - Download and install the .NET 4.7.2 Developer Pack (https://dotnet.microsoft.com/en-us/download/dotnet-framework/net472)
### 4 - Run gacutil.exe to register EACH of the DLLs from an elevated command prompt (e.g., Gacutil /IF C:\extensions\ThreatDetectionModule.dll) on each server in the farm.
### 5 - Install the configuraion file appConfig.csv to a folder (e.g., C:\extensions) on each server in the farm.
Update the configuration file fields as appropriate for each protected application
- LookupKey - This is either the Client ID for Oauth and applications that send a Client ID or the Issuer for SAML/WS-Fed integrations.
- SigningKey - This is the key used to sign the JSON Web Tokens send to the Next Level3 API and can be obtained from your Company Portal. It is recommended you store this key in a secrets manager vs. in the configuration file, but updates will need to be made to the plugin to support retrieving the value from a secrets manager.
- AppName - The signing key should be associated with the AppName listed in this field
- APIUrl - The URL for the Next Level3 API you will target for this environment (e.g., api.nextlevel3.com, api.dev.nextlevel3.com)
- APIVersion - The version of the API you are targeting (e.g., v1)
- IPInfoToken - An API Token for https://ipinfo.io if you want to include IP and Geolocation information
### 6 - Register the plugin and configuration file on each server in the farm (e.g., Register-AdfsThreatDetectionModule -Name "AccountProtectionCheckPlugin" -TypeName "ThreatDetectionModule.UserRiskAnalyzer, ThreatDetectionModule, Version=10.0.0.0, Culture=neutral, PublicKeyToken=4afaf2b6a3a6959d" -ConfigurationFilePath "C:\extensions\apcConfig.csv")
### 7 - Restart the "Active Directory Federation Services" service in services.msc. (Redo this step any time you update a .DLL or make other significant changes)
## Other useful commands
- UnRegister-AdfsThreatDetectionModule -Name "AccountProtectionCheckPlugin"
- Import-AdfsThreatDetectionModuleConfiguration -name "AccountProtectionCheckPlugin" -ConfigurationFilePath "C:\extensions\apcConfig.csv"

#### Based on Sample Plugin from Microsoft that can be found here https://github.com/microsoft/adfs-sample-RiskAssessmentModel-RiskyIPBlock
