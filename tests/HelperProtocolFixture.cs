using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

public static class HelperProtocolFixture
{
    public static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--child") { Thread.Sleep(60000); return 0; }
        var json = new JavaScriptSerializer();
        string line; using (var reader = new StreamReader(Console.OpenStandardInput(), Encoding.UTF8)) line = reader.ReadLine();
        var request = json.Deserialize<Dictionary<string, object>>(line);
        bool scan = !request.ContainsKey("mode");
        string mode = scan ? Convert.ToString(((Dictionary<string, object>)request["secrets"])["ios_password"]) : Convert.ToString(request["mode"]);
        string secret = scan ? "scratch-canary" : Convert.ToString(request["secret"]);
        if (scan) {
            string scratch = Convert.ToString(((Dictionary<string, object>)request["options"])["scratch"]);
            File.WriteAllText(Path.Combine(scratch, "decrypted-copy.tmp"), secret);
            if (mode == "cancel-scratch") {
                var child = Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--child") { UseShellExecute = false, CreateNoWindow = true });
                File.WriteAllText(Convert.ToString(request["destination"]) + ".pid", child.Id.ToString()); Thread.Sleep(60000); return 0;
            }
        }
        if (mode == "cancel") {
            var child = Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--child") { UseShellExecute = false, CreateNoWindow = true });
            File.WriteAllText(Convert.ToString(request["marker"]), child.Id.ToString());
            Thread.Sleep(60000); return 0;
        }
        for (int i = 0; i < 2000; i++) Console.Error.WriteLine(secret + " third-party private diagnostic");
        Console.WriteLine("not-json " + secret);
        Console.WriteLine(json.Serialize(new { type = "progress", message = secret }));
        if (mode == "invalid") { Console.WriteLine("{\"type\":\"result\",\"status\":\"invented\"}"); return 0; }
        if (mode == "mismatch") { Console.WriteLine("{\"type\":\"result\",\"status\":\"complete\",\"code\":\"OK\"}"); return 1; }
        Console.WriteLine(json.Serialize(new { type = "result", status = mode == "error" ? "error" : "complete", code = mode == "error" ? secret : "OK", messages = secret.Length, media = 0 }));
        return mode == "error" ? 1 : 0;
    }
}
