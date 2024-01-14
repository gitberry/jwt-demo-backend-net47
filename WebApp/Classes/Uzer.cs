using JWT;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Uzer
{
    public static class helper
    {
        private static string SomeUzers = "a|b;Bob|booya;Betty|wont;billy|bob;bare|ash";

        public static List<MockUzer> GimmeMockUzers()
        {
            List<MockUzer> result = new List<MockUzer>();
            var tmplist = SomeUzers.Split(';');
            foreach (var uzer in tmplist)
            {
                var u = uzer.Split('|');
                if (u.Length > 1) { result.Add(new MockUzer(result.Count + 1, u[0], u[1], JWT.helper.GenRandomSeed())); }
            }
            return result;
        }
    }

    public class MockUzer
    {
        public int id;
        public string uzer;
        public string hashedPassword;
        public string hashseed;
        public string firstName;
        public string lastName;
        public string name;
        public MockUzer(int givenid, string givenU, string givenP, string givenS)                                                                                   
        {
            id = givenid;
            uzer = givenU;
            hashedPassword = JWT.helper.HashPassword(givenP, givenS);
            hashseed = givenS;
            firstName = uzer;
            lastName = uzer;
            name = givenU + " " + givenP;
        }
    }
}