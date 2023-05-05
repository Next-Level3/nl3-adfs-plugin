using Microsoft.IdentityServer.Public.ThreatDetectionFramework;
using Microsoft.VisualBasic.FileIO;
using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Microsoft.IdentityServer.Public;
using System.Security.Claims;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Text.RegularExpressions;
using System.IdentityModel.Tokens.Jwt;
using System.IdentityModel;
using Microsoft.IdentityModel.Tokens;
using System.Web;
using System.IO.Compression;

namespace ThreatDetectionModule
{
    /// <summary>
    /// IPConverter is a class for fixing the serialization of NetworkLocation objects
    /// </summary>
    //public class IPConverter : JsonConverter<IPAddress>
    public class IPConverter : JsonConverter<IPAddress>
    {
        public override void WriteJson(JsonWriter writer, IPAddress value, JsonSerializer serializer)
        {
            writer.WriteValue(value.ToString());
        }

        public override IPAddress ReadJson(JsonReader reader, Type objectType, IPAddress existingValue, bool hasExistingValue, JsonSerializer serializer)
        {
            var s = (string)reader.Value;
            return IPAddress.Parse(s);
        }
    }
    /// <summary>
    /// UserRiskAnalyzer is the main class implementing the ThreatDetectionModule abstract class and IPreAuthenticationThreatDetectionModule interface.
    /// During registration of the module with ADFS, pass a config file with list of Client IDs and Signing Keys seperated with ","
    /// This module will check with Next Level3 to determine if the current user account status is locked or unlocked.
    /// If the acocunt is locked, the method returns Throttelstatus as 2 (Block), else it returns 1 (Allow).
    /// </summary>
    //public class UserRiskAnalyzer : Microsoft.IdentityServer.Public.ThreatDetectionFramework.ThreatDetectionModule, IRequestReceivedThreatDetectionModule
    public class UserRiskAnalyzer : Microsoft.IdentityServer.Public.ThreatDetectionFramework.ThreatDetectionModule, IPreAuthenticationThreatDetectionModule
    {
        private JObject APCConfig;
        public override string VendorName => "Microsoft";
        public override string ModuleIdentifier => "UserRiskAnalyzer";

        /// <summary>
        /// ADFS calls this method while loading the module and it passes the contents of Config file through configData
        /// This method caches the IPs from it so that it can used when authentication requests are evaluated
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="configData"></param>
        public override void OnAuthenticationPipelineLoad(ThreatDetectionLogger logger, ThreatDetectionModuleConfiguration configData)
        {
            try
            {
                ReadConfigFile(logger, configData);
            }
            catch (Exception ex)
            {
                logger.WriteAdminLogErrorMessage(ex.ToString());
                throw;
            }
        }

        /// <summary>
        /// Stored config data stream
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="configData"></param>
        private void ReadConfigFile(ThreatDetectionLogger logger, ThreatDetectionModuleConfiguration configData)
        {
            APCConfig = new JObject();
            using (StreamReader sr = new StreamReader(configData.ReadData()))
            {
                string line;
                string headerLine;
                headerLine = sr.ReadLine();
                string[] headers;
                headers = headerLine.Split(',');
                if (headerLine != null)
                {
                    JArray jObjects = new JArray();
                    while ((line = sr.ReadLine()) != null)
                    {
                        string[] parts = line.Split(',');
                        if (parts[0] != null)
                        {
                            JObject jObject = new JObject();
                            int i = 0;
                            foreach (string part in parts)
                            {
                                jObject[headers[i].Trim()] = part.Trim();
                                i++;
                            }
                            jObjects.Add(jObject);
                        }
                    }
                    APCConfig["applications"] = jObjects;
                }
            }
        }

        /// <summary>
        /// Parses the config file and store it in JObject
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="apcConfig"></param>
        /// <param name="clientId"></param>
        private string GetSigningKey(ThreatDetectionLogger logger, String lookupKey, out String appName, out String apiUrl, out String apiVersion, out string ipInfoToken, out bool failOpen)
        {
            JToken applicationToken = APCConfig.SelectToken("$.applications[?(@.LookupKey == '" + lookupKey + "')]");
            if (applicationToken.HasValues)
            {
                JObject application = applicationToken.ToObject<JObject>();
                JToken signingKey;
                JToken tAppName;
                JToken tAPIUrl;
                JToken tAPIVersion;
                JToken tIPInfoToken;
                JToken tFailOpen;
                if (application.TryGetValue("SigningKey", out signingKey) && application.TryGetValue("AppName", out tAppName) && application.TryGetValue("APIUrl", out tAPIUrl) && application.TryGetValue("APIVersion", out tAPIVersion) && application.TryGetValue("IPInfoToken", out tIPInfoToken) && application.TryGetValue("FailOpen", out tFailOpen))
                {
                    string sk = signingKey.Value<string>();
                    appName = tAppName.Value<string>();
                    apiUrl = tAPIUrl.Value<string>();
                    apiVersion = tAPIVersion.Value<string>();
                    ipInfoToken = tIPInfoToken.Value<string>();
                    failOpen = tFailOpen.Value<bool>();
                    return sk;
                }
                else
                {
                    logger?.WriteAdminLogErrorMessage($"TryGetValue failed!");
                }
            }
            appName = "";
            apiUrl = "";
            apiVersion = "";
            ipInfoToken = "";
            failOpen = true;
            return null;
        }

        public override void OnAuthenticationPipelineUnload(ThreatDetectionLogger logger)
        {
        }

        /// <summary>
        /// ADFS calls this method when there is any change in the configuration. This typically happens when Import-AdfsThreatDetectionModuleConfiguration cmdlet is executed
        /// ADFS passes the contents of Config file through configData
        /// This method caches the IPs from it so that it can used when authentication requests are evaluated
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="configData"></param>
        public override void OnConfigurationUpdate(ThreatDetectionLogger logger, ThreatDetectionModuleConfiguration configData)
        {
            ReadConfigFile(logger, configData);
        }

        /// <summary>
        /// Implements the interface method. 
        /// This method checks the lock status in NL3 for the user that is authenticating.
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="requestContext"></param>
        /// <param name="securityContext"></param>
        /// <param name="protocolContext"></param>
        /// <param name="additionalClaims"></param>
        /// <returns></returns>
        public Task<ThrottleStatus> EvaluatePreAuthentication(ThreatDetectionLogger logger, RequestContext requestContext, SecurityContext securityContext, ProtocolContext protocolContext, IList<Claim> additionalClaims)
        {
            bool failOpen = false;
            try
            {
                var referer = requestContext.Headers.Get("Referer").Replace("??", "?").Replace("'%'", "%");
                string username = securityContext.UserIdentifier;
                logger?.WriteAdminLogErrorMessage($"Referer = {referer}");
                Uri refererUri = new Uri(referer);
                string issuerOrClientId = null;
                string[] mSamlRequestCookies;
                string mSamlRequest = "";
                string appName;
                string apiVersion;
                string apiUrl;
                string ipInfoToken;
                logger?.WriteAdminLogErrorMessage($"Correlation Id = {requestContext.CorrelationId}");
                System.Collections.Specialized.NameValueCollection nvc = requestContext.Headers;
                string headersString = "";
                foreach (string headerKey in nvc)
                {
                    headersString += string.Format("{0} {1}\r\n", headerKey, nvc[headerKey]);
                }
                logger?.WriteAdminLogErrorMessage($"Headers = {headersString}");
                logger?.WriteAdminLogErrorMessage($"Local EndPoint Absolute Path = {requestContext.LocalEndPointAbsolutePath}");
                logger?.WriteAdminLogErrorMessage($"Proxy Server = {requestContext.ProxyServer}");
                logger?.WriteAdminLogErrorMessage($"Username = {username}");
                logger?.WriteAdminLogErrorMessage($"Authority = {securityContext.Authority}");
                if (requestContext.Headers.HasKeys())
                {
                    if (requestContext.Headers["Cookie"] != null)
                    {
                        string cookieHeader = requestContext.Headers.Get("Cookie");
                        if (cookieHeader.Length > 0)
                        {
                            Match M = Regex.Match(cookieHeader, string.Format("{0}=(?<value>.*?)$", "MSISSamlRequest"));
                            if (M.Success)
                            {
                                mSamlRequestCookies = M.ToString().Split(';');
                                foreach (string cookie in mSamlRequestCookies)
                                {
                                    mSamlRequest += cookie.Split(new char[] { '=' }, 2)[1];
                                }
                                mSamlRequest = HttpUtility.UrlDecode(Encoding.UTF8.GetString(Convert.FromBase64String(mSamlRequest)));
                                M = Regex.Match(mSamlRequest, string.Format("(?<={0})(?<value>[A-Za-z0-9+\\/]{{4}})*(?:[A-Za-z0-9+\\/]{{4}}|[A-Za-z0-9+\\/]{{3}}=|[A-Za-z0-9+\\/]{{2}}={{2}}?)(?=\\\\)", "SAMLRequest="));
                                if (M.Success)
                                {
                                    mSamlRequest = Encoding.UTF8.GetString(Convert.FromBase64String(M.ToString()));
                                    XmlDocument xmlDoc = new XmlDocument();
                                    xmlDoc.LoadXml(mSamlRequest);
                                    XmlNode issuerNode = xmlDoc.SelectSingleNode("/");
                                    issuerOrClientId = issuerNode.InnerText;
                                    if ((username == null || username.Length == 0) && referer.ToLower().Contains("microsoftonline"))
                                    {
                                        username = HttpUtility.ParseQueryString(refererUri.Query).Get("username");
                                        if (username == null || username.Length == 0)
                                        {
                                            username = HttpUtility.ParseQueryString(refererUri.Query).Get("login_hint");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                logger?.WriteAdminLogErrorMessage($"After SAML Cookie Parsing!");
                if (issuerOrClientId == null && referer.ToLower().Contains("samlrequest"))
                {
                    mSamlRequest = HttpUtility.ParseQueryString(refererUri.Query).Get("SAMLRequest").Replace("%25", "%").Replace("%2B", "+").Replace("%2F", "/").Replace("%3D", "=");
                    logger?.WriteAdminLogErrorMessage($"mSamlRequest After ParseQueryString = {mSamlRequest}");
                    if (mSamlRequest != null & mSamlRequest.Length > 0)
                    {
                        logger?.WriteAdminLogErrorMessage($"mSamlRequest After Url Decode = {mSamlRequest}");
                        MemoryStream memStream = new MemoryStream(Convert.FromBase64String(mSamlRequest));
                        DeflateStream deflate = new DeflateStream(memStream, CompressionMode.Decompress);
                        mSamlRequest = new StreamReader(deflate, System.Text.Encoding.UTF8).ReadToEnd();
                        XmlDocument xmlDoc = new XmlDocument();
                        xmlDoc.LoadXml(mSamlRequest);
                        XmlNode issuerNode = xmlDoc.SelectSingleNode("/");
                        issuerOrClientId = issuerNode.InnerText;
                    }
                }
                logger?.WriteAdminLogErrorMessage($"mSamlRequest = {mSamlRequest}");
                if (issuerOrClientId == null)
                {
                    issuerOrClientId = protocolContext.ClientId;
                }
                if (issuerOrClientId == null || issuerOrClientId.Length == 0 && !referer.ToLower().Contains("microsoftonline"))
                {
                    issuerOrClientId = HttpUtility.ParseQueryString(refererUri.Query).Get("client_id");
                }
                if ((issuerOrClientId == null || issuerOrClientId.Length == 0) && referer.ToLower().Contains("microsoftonline"))
                {
                    issuerOrClientId = "urn:federation:MicrosoftOnline";
                    if ((username == null || username.Length == 0))
                    {
                        username = HttpUtility.ParseQueryString(refererUri.Query).Get("username");
                        if (username == null || username.Length == 0)
                        {
                            username = HttpUtility.ParseQueryString(refererUri.Query).Get("login_hint");
                        }
                    }
                }
                logger?.WriteAdminLogErrorMessage($"Issuer or Client ID = {issuerOrClientId}");
                string base64SigningKey = GetSigningKey(logger, issuerOrClientId, out appName, out apiUrl, out apiVersion, out ipInfoToken, out failOpen);
                if (base64SigningKey != null && base64SigningKey.Length > 5)
                {
                    byte[] key = Convert.FromBase64String(base64SigningKey);
                    SymmetricSecurityKey securityKey = new SymmetricSecurityKey(key);

                    JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                    JwtSecurityToken token = handler.CreateJwtSecurityToken(appName, apiUrl, new ClaimsIdentity(new[] {
                          new Claim("sub", username)}), DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(5), DateTime.UtcNow.AddMinutes(-1), new SigningCredentials(securityKey,
                        SecurityAlgorithms.HmacSha256Signature));

                    HttpWebRequest requestIPDetails = (HttpWebRequest)WebRequest.Create("https://ipinfo.io/" + requestContext.ClientIpAddresses[0].ToString() + "/json?token=" + ipInfoToken);
                    JObject jsonIPDetails = new JObject();
                    string location = "";
                    string geo = "";
                    using (HttpWebResponse responseIPDetails = (HttpWebResponse)requestIPDetails.GetResponse())
                    using (Stream stream = responseIPDetails.GetResponseStream())
                    using (StreamReader reader = new StreamReader(stream))
                    {
                        jsonIPDetails = JObject.Parse(reader.ReadToEnd());
                        if (jsonIPDetails.HasValues)
                        {
                            location = jsonIPDetails["city"] + ", " + jsonIPDetails["region"];
                            geo = jsonIPDetails["loc"] + "";
                        }
                    }
                    HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://" + apiUrl + "/nl3/api/" + apiVersion + "/accountProtectionCheck");
                    var jsonSettings = new JsonSerializerSettings();
                    jsonSettings.Converters.Add(new IPConverter());
                    JObject jPostData = new JObject
                    {
                        ["userIP"] = requestContext.ClientIpAddresses[0].ToString(),
                        ["userDevice"] = requestContext.UserAgentString,
                        ["userLocation"] = location,
                        ["integrationType"] = "adfs"
                    };
                    jPostData.Add(new JProperty("integrationData", JObject.Parse(JsonConvert.SerializeObject(requestContext, Newtonsoft.Json.Formatting.Indented, jsonSettings))));
                    jPostData["integrationData"]["locationInfo"] = jsonIPDetails;
                    logger?.WriteAdminLogErrorMessage($"jPostData = {jPostData.ToString()}");
                    byte[] byteArray = Encoding.UTF8.GetBytes(jPostData.ToString());
                    request.Method = "POST";
                    request.ContentType = "application/json";
                    request.ContentLength = byteArray.Length;
                    request.Headers.Add("x-nl3-authorization-token", handler.WriteToken(token));
                    request.Headers.Add("x-nl3-device-location", geo);
                    request.Headers.Add("x-forwarded-for", requestContext.ClientIpAddresses[0].ToString());
                    request.UserAgent = requestContext.UserAgentString;
                    request.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
                    Stream requestStream = request.GetRequestStream();
                    requestStream.Write(byteArray, 0, byteArray.Length);
                    requestStream.Close();

                    using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                    using (Stream stream = response.GetResponseStream())
                    using (StreamReader reader = new StreamReader(stream))
                    {
                        JObject jsonResponse = JObject.Parse(reader.ReadToEnd());
                        JToken locked;
                        if (jsonResponse.TryGetValue("locked", out locked))
                        {
                            if (locked.Value<bool>())
                            {
                                logger?.WriteAdminLogErrorMessage($"Locked Status = True");
                                return Task.FromResult<ThrottleStatus>(ThrottleStatus.Block);
                            }
                            else
                            {
                                logger?.WriteAdminLogErrorMessage($"Locked Status = False");
                                return Task.FromResult<ThrottleStatus>(ThrottleStatus.Allow);
                            }
                        }
                        else
                        {
                            if (username == null || username.Length == 0)
                            {
                                logger?.WriteAdminLogErrorMessage($"Username Missing!");
                                return Task.FromResult<ThrottleStatus>(ThrottleStatus.Block);
                            }
                            else
                            {
                                logger?.WriteAdminLogErrorMessage($"Locked Status = False");
                                return Task.FromResult<ThrottleStatus>(ThrottleStatus.Allow);
                            }
                        }
                    }

                }
                else
                {
                    logger?.WriteAdminLogErrorMessage($"No signing key identified for Client ID = " + issuerOrClientId + ", please check configuration file!");
                    if (failOpen)
                    {
                        return Task.FromResult<ThrottleStatus>(ThrottleStatus.Allow);
                    } else
                    {
                        return Task.FromResult<ThrottleStatus>(ThrottleStatus.Block);
                    }
                }
            }
            catch (Exception ex)
            {
                logger?.WriteAdminLogErrorMessage($"Exception = " + ex.ToString());
                if (failOpen)
                {
                    return Task.FromResult<ThrottleStatus>(ThrottleStatus.Allow);
                }
                else
                {
                    return Task.FromResult<ThrottleStatus>(ThrottleStatus.Block);
                }
            }
        }
    }
}
