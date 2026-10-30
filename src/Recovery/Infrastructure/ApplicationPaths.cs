using System;
using System.IO;

namespace UsbRecovery
{
    // Installed runtimes are self-contained. Development builds resolve only the
    // documented .build/app or .build/tests layout, never arbitrary ancestors.
    public static class ApplicationPaths
    {
        public static string RuntimeRoot { get { return Resolve(AppDomain.CurrentDomain.BaseDirectory); } }
        public static string Resolve(string baseDirectory)
        {
            var directory=new DirectoryInfo(Path.GetFullPath(baseDirectory));
            if(Directory.Exists(Path.Combine(directory.FullName,"tools")))return directory.FullName;
            if(directory.Parent!=null&&directory.Parent.Name==".build"&&(directory.Name=="app"||directory.Name=="tests")){
                var repository=directory.Parent.Parent;
                if(repository!=null&&File.Exists(Path.Combine(repository.FullName,"src","Recovery","Recovery.csproj")))return repository.FullName;
            }
            return directory.FullName;
        }
        static string Under(string root,string relative)
        {
            if(String.IsNullOrWhiteSpace(relative)||Path.IsPathRooted(relative))throw new ArgumentException("A relative resource path is required.");
            foreach(string part in relative.Replace('\\','/').Split('/'))if(part==""||part=="."||part==".."||part.IndexOf(':')>=0)throw new ArgumentException("Unsafe resource path.");
            return Path.Combine(root,relative.Replace('/',Path.DirectorySeparatorChar));
        }
        public static string Tool(string relative){return Under(Path.Combine(RuntimeRoot,"tools"),relative);}
        public static string Document(string relative){return Under(Path.Combine(RuntimeRoot,"docs"),relative);}
    }
}
