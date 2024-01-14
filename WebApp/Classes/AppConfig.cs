using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;

namespace AppConfig
{
    public static class Setting
    {
#if DEBUG
        //this is purely to make dev running easiesr
        public static string JWTsigningSecret = ConfigDefault("JWTsigningSecret", "BigLongSecretForTestingandAllthatHappyJazzOKHMMMM");
        public static string JWTapiSite       = ConfigDefault("JWTapiSite",       "http://localhost:50191");
        public static string JWTclientSite    = ConfigDefault("JWTclientSite",    "http://localhost:3000");
        public static double JWTMinutesToLive = ConfigDefault("JWTMinutesToLive",  3);
        public static string CORSorigin       = ConfigDefault("CORSorigin",        "http://localhost:3000");
        public static bool   EnableSwagger    = ConfigDefault("EnableSwagger",     true);
#else
        // prod should ALWAYS fail out of the box if no configuring on the server takes place - Mr T says: PROD requires a higher level of attention FOOL! 
        public static string JWTsigningSecret = ConfigDefault("JWTsigningSecret", "");
        public static string JWTapiSite       = ConfigDefault("JWTapiSite",       "");
        public static string JWTclientSite    = ConfigDefault("JWTclientSite",    "");
        public static double JWTMinutesToLive = ConfigDefault("JWTMinutesToLive",  1);
        public static string CORSorigin       = ConfigDefault("CORSorigin",       "");
        public static bool   EnableSwagger    = ConfigDefault("EnableSwagger",     false);
#endif
        private static string ConfigDefault(string givenAppSetting, string defaultValueIfError)
        {
            string givenSettingTextValue = ConfigurationManager.AppSettings[givenAppSetting];
            string result = defaultValueIfError;
            if ( givenSettingTextValue != "" && !(givenSettingTextValue is null) ) { result = givenSettingTextValue; }
            if (givenSettingTextValue == "INTENTIONALLYEMPTY") { result = ""; }
            return result;
        }

        private static double ConfigDefault(string givenAppSetting, double defaultValueIfError)
        {
            string givenSettingTextValue = ConfigurationManager.AppSettings[givenAppSetting];
            double result = defaultValueIfError;
            if ( !(givenSettingTextValue == "") && !(givenSettingTextValue is null) ) // "" parse to 0 - don't want 0 unintentionally!
            {
                double.TryParse(givenSettingTextValue, out result);
            }            
            return result;
        }

        private static bool ConfigDefault(string givenAppSetting, bool defaultValueIfError)
        {
            string givenSettingTextValue = ConfigurationManager.AppSettings[givenAppSetting];
            bool result = defaultValueIfError;
            if (!(givenSettingTextValue == "") && !(givenSettingTextValue is null)) 
            {
                bool.TryParse(givenSettingTextValue, out result);
            }
            return result;
        }

    }


}

