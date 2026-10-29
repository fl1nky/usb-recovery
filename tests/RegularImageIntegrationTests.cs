using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using UsbRecovery;

public static class RegularImageIntegrationTests
{
    static void Assert(bool value,string message) { if(!value) throw new Exception(message); }
    static void Progress(long a,long b) { }
    public static int Main()
    {
        string appBase=AppDomain.CurrentDomain.BaseDirectory;
        bool packaged=!Directory.Exists(Path.Combine(appBase,"tests"));
        string root=packaged ? Path.GetFullPath(Path.Combine(appBase,"..")) : appBase;
        string resultName=packaged ? "RegularImageIntegrationTests.packaged.result.txt" : "RegularImageIntegrationTests.result.txt";
        string fixture=Path.Combine(root,"tests","photorec-20261011T231546120952Z");
        string run=Path.Combine(root,"tests","Проверка фото с пробелами "+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff"));
        string oldCompatibility=Environment.GetEnvironmentVariable("__COMPAT_LAYER");
        var stopwatch=Stopwatch.StartNew();
        using(var cancel=new CancellationTokenSource(25000))
        {
            try
            {
                Directory.CreateDirectory(run);
                string original=Path.Combine(fixture,"synthetic-usb.dd");
                string image=Path.Combine(run,"Копия флешки usb.dd");
                Assert(File.Exists(original),"Synthetic image fixture is missing");
                string before=RecoveryCore.HashFile(original,cancel.Token,Progress);
                File.Copy(original,image);
                string imageBefore=RecoveryCore.HashFile(image,cancel.Token,Progress);
                Assert(before==imageBefore,"Copied fixture hash differs");
                File.WriteAllText(image+".sha256",imageBefore+"  Копия флешки usb.dd\r\n",new UTF8Encoding(false));
                // Offline fixture test only: suppress elevation of the bundled child executable.
                Environment.SetEnvironmentVariable("__COMPAT_LAYER","RunAsInvoker");
                int count;
                using(var guard=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read))
                {
                    RecoveryCore.VerifyImage(image,cancel.Token,Progress);
                    count=RecoveryCore.Recover(image,run,cancel.Token,delegate(int n) { });
                }
                string gallery=UsbRecovery.Program.WriteGallery(run);
                Assert(count>0,"No candidates recovered");
                string expectedJpg=RecoveryCore.HashFile(Path.Combine(fixture,"fixtures","expected.jpg"),cancel.Token,Progress);
                string expectedPng=RecoveryCore.HashFile(Path.Combine(fixture,"fixtures","expected.png"),cancel.Token,Progress);
                string[] recovered=RecoveryCore.RecoveredFiles(run).ToArray();
                Assert(recovered.Any(p=>Path.GetExtension(p).Equals(".jpg",StringComparison.OrdinalIgnoreCase) && RecoveryCore.HashFile(p,cancel.Token,Progress)==expectedJpg),"Recovered JPEG does not match fixture SHA256");
                Assert(recovered.Any(p=>Path.GetExtension(p).Equals(".png",StringComparison.OrdinalIgnoreCase) && RecoveryCore.HashFile(p,cancel.Token,Progress)==expectedPng),"Recovered PNG does not match fixture SHA256");
                Assert(File.Exists(gallery),"Gallery file missing");
                string html=File.ReadAllText(gallery,Encoding.UTF8);
                Assert(html.StartsWith("<!doctype html>") && html.Contains("Найденные фотографии"),"Gallery markup is invalid");
                MatchCollection links=Regex.Matches(html,"(?:href|src)='([^']+)'");
                Assert(links.Count>=5,"Expected image and page links are missing");
                foreach(Match match in links)
                {
                    string link=Uri.UnescapeDataString(match.Groups[1].Value).Replace('/',Path.DirectorySeparatorChar);
                    string target=Path.GetFullPath(Path.Combine(run,link));
                    Assert(target.StartsWith(run+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase),"Gallery link escapes result directory");
                    Assert(File.Exists(target),"Gallery target missing: "+link);
                }
                Assert(RecoveryCore.HashFile(original,cancel.Token,Progress)==before,"Original synthetic image changed");
                Assert(RecoveryCore.HashFile(image,cancel.Token,Progress)==imageBefore,"Scanned synthetic image changed");
                string log=File.ReadAllText(Path.Combine(run,"photorec.log"),Encoding.UTF8);
                Assert(log.Contains("PhotoRec exited normally.") && log.Contains("Total: "),"Completion evidence missing");
                Assert(!File.Exists(Path.Combine(run,"photorec.ses")),"Incomplete recovery session remains");
                string summary="PASS regular-image integration; packaged="+packaged+"; candidates="+count+"; JPEG+PNG SHA256 match; gallery links="+links.Count+"; source hashes unchanged; elapsed="+stopwatch.Elapsed.TotalSeconds.ToString("0.00")+"s; directory="+run+"; tool="+RecoveryCore.ToolPath;
                Console.WriteLine(summary);
                File.WriteAllText(Path.Combine(root,"tests",resultName),summary+"\r\n",new UTF8Encoding(false));
                return 0;
            }
            catch(Exception ex)
            {
                string summary="FAIL regular-image integration: "+ex+"\r\nDirectory="+run;
                Console.WriteLine(summary);
                File.WriteAllText(Path.Combine(root,"tests",resultName),summary+"\r\n",new UTF8Encoding(false));
                return 1;
            }
            finally { Environment.SetEnvironmentVariable("__COMPAT_LAYER",oldCompatibility); }
        }
    }
}
