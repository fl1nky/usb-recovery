// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    internal static class RecoveryNativeTools
    {
        sealed class Manifest { public int Schema {get;set;} public string Profile {get;set;} public List<Entry> Files {get;set;} }
        sealed class Entry { public string Name {get;set;} public string Sha256 {get;set;} }
        static readonly string[] Names = { "ntfs_worker.exe", "cygwin1.dll", "cygz.dll", "cygiconv-2.dll", "cygcharset-1.dll" };
        internal static List<RecoveryNativeToolFile> Ntfs()
        {
            string root=ApplicationPaths.RuntimeRoot;
            string path=RecoveryCatalog.SafeFile(root,"tools/native-recovery/runtime.json");
            using(var lease=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                if(lease.Length<1 || lease.Length>65536)throw new IOException("NATIVE_TOOLS_MANIFEST_INVALID");
                Manifest manifest;
                try {manifest=new JavaScriptSerializer {MaxJsonLength=65536}.Deserialize<Manifest>(File.ReadAllText(path));}
                catch(ArgumentException){throw new IOException("NATIVE_TOOLS_MANIFEST_INVALID");}
                catch(InvalidOperationException){throw new IOException("NATIVE_TOOLS_MANIFEST_INVALID");}
                if(manifest==null || manifest.Schema!=1 || manifest.Profile!="ntfs-plan-v1" || manifest.Files==null || manifest.Files.Count!=Names.Length)
                    throw new IOException("NATIVE_TOOLS_MANIFEST_INVALID");
                var files=new Dictionary<string,Entry>(StringComparer.Ordinal);
                foreach(var item in manifest.Files) {
                    if(item==null || !Names.Contains(item.Name) || files.ContainsKey(item.Name) || item.Sha256==null || item.Sha256.Length!=64 ||
                        item.Sha256.Any(ch=>!(ch>='0'&&ch<='9'||ch>='a'&&ch<='f')))throw new IOException("NATIVE_TOOLS_MANIFEST_INVALID");
                    files.Add(item.Name,item);
                }
                return Names.Select(name=>new RecoveryNativeToolFile {Path=RecoveryCatalog.SafeFile(root,"tools/native-recovery/"+name),Sha256=files[name].Sha256}).ToList();
            }
        }
    }
}
