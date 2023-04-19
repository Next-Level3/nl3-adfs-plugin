# Installation Steps for AD FS 2019 and 2022
### 1 - Download code and build in Visual Studio 2022
### 2 - Install the following files from the appropriate binary build folder (e.g., bin/Debug, bin/Release) on each AD FS server in your farm to a folder (e.g., C:\extensions).
- Microsoft.IdentityModel.JsonWebTokens.dll
- Microsoft.IdentityModel.Logging.dll
- Microsoft.IdentityModel.Tokens.dll
- Newtonsoft.Json.dll
- System.IdentityModel.Tokens.Jwt.dll
- ThreatDetectionModule.dll
### 3 - Run gacutil.exe to register each of the DLLs from an elevated command prompt (e.g., Gacutil /IF C:\extensions\ThreatDetectionModule.dll) on each server in the farm.
### 4 - Install the configuraion file appConfig.csv to a folder (e.g., C:\extensions) on each server in the farm.
Update the configuration file fields as appropriate for each protected application
- LookupKey - This is either the Client ID for Oauth and applications that send a Client ID or the Issuer for SAML/WS-Fed integrations.
- SigningKey - This is the key used to sign the JSON Web Tokens send to the Next Level3 API and can be obtained from your Company Portal. It is recommended you store this key in a secrets manager vs. in the configuration file, but updates will need to be made to the plugin to support retrieving the value from a secrets manager.
- AppName - The signing key should be associated with the AppName listed in this field
- APIUrl - The URL for the Next Level3 API you will target for this environment (e.g., api.nextlevel3.com, api.dev.nextlevel3.com)
- APIVersion - The version of the API you are targeting (e.g., v1)
- IPInfoToken - An API Token for https://ipinfo.io if you want to include IP and Geolocation information
### 5 - Register the plugin and configuration file on each server in the farm (e.g., Register-AdfsThreatDetectionModule -Name "AccountProtectionCheckPlugin" -TypeName "ThreatDetectionModule.UserRiskAnalyzer, ThreatDetectionModule, Version=10.0.0.0, Culture=neutral, PublicKeyToken=4afaf2b6a3a6959d" -ConfigurationFilePath "C:\extensions\apcConfig.csv")
### 6 - Restart the "Active Directory Federation Services" service in services.msc. (Redo this step any time you update a .DLL or make other significant changes)
## Other useful commands
- UnRegister-AdfsThreatDetectionModule -Name "AccountProtectionCheckPlugin"
- Import-AdfsThreatDetectionModuleConfiguration -name "AccountProtectionCheckPlugin" -ConfigurationFilePath "C:\extensions\apcConfig.csv"

# Build Plug-ins with AD FS 2019 Risk Assessment Model

You can now build your own plug-ins to block or assign a risk score to authentication requests during various stages – request received, pre-authentication and post-authentication. This can be accomplished using the new Risk Assessment Model introduced with AD FS 2019. 

## What is the Risk Assessment Model?

The Risk Assessment Model is a set of interfaces and classes which enable developers to read authentication request headers and implement their own risk assessment logic. The implemented code (plug-in) then runs in line with AD FS authentication process. For eg, using the interfaces and classes included with the model, you can implement code to either block or allow authentication request based on the client IP address included in the request header. AD FS will execute the code for each authentication request and take appropriate action as per the implemented logic.

For more details please visit [AD FS Risk Assessment Model documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/development/ad-fs-risk-assessment-model)

## About this sample

This sample plug-in is meant to better understand how to build a risk assessment plug-in and run it in line with AD FS process. The code in this sample uses the new interfaces and classes introduced with the risk assessment model to block the requests coming from certain extranet IPs identified as risky. 

To learn how to build this sample plug-in please visit [Building a sample plug-in documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/development/ad-fs-risk-assessment-model#building-a-sample-plug-in)

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
