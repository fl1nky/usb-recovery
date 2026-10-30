using System;
using System.IO;
using UsbRecovery;

// Generated directory layouts and existence checks for delivered resources only.
// No helper is launched and no profiles, device paths or recovery inputs are opened.
public static class ApplicationPathsTests
{
    static int checks;
    static string work;

    static void Check(bool condition, string description)
    {
        checks++;
        if (!condition) throw new Exception(description);
    }
    static bool Same(string first, string second)
    {
        return String.Equals(Path.GetFullPath(first).TrimEnd('\\', '/'),
            Path.GetFullPath(second).TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase);
    }
    static string Folder(params string[] components)
    {
        string path = Path.Combine(work, Path.Combine(components));
        Directory.CreateDirectory(path);
        return path;
    }
    static void Marker(string repository)
    {
        string directory = Path.Combine(repository, "src", "Recovery");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "Recovery.csproj"), "<Project />");
    }
    static void ResolveLayouts()
    {
        string portable = Folder("portable");
        Folder("portable", "tools");
        Check(Same(ApplicationPaths.Resolve(portable), portable), "self-contained tools resolve beside executable");

        string repository = Folder("repository");
        Marker(repository);
        string app = Folder("repository", ".build", "app");
        string tests = Folder("repository", ".build", "tests");
        Check(Same(ApplicationPaths.Resolve(app), repository), "documented app build resolves repository marker");
        Check(Same(ApplicationPaths.Resolve(tests), repository), "documented test build resolves repository marker");

        foreach (string directory in new[] {
            Folder("repository", "other", "app"),
            Folder("repository", ".build", "other"),
            Folder("repository", ".build", "app", "nested"),
            Folder("repository", ".build"),
            Folder("unmarked", ".build", "app"),
            Folder("unmarked", ".build", "tests")
        })
            Check(Same(ApplicationPaths.Resolve(directory), directory),
                "unrecognized layout or absent marker never climbs: " + directory);

        Folder("ancestor-tools", "tools");
        string child = Folder("ancestor-tools", ".build", "app");
        Check(Same(ApplicationPaths.Resolve(child), child), "ancestor tools alone never select an unrelated runtime");
        Folder("repository", ".build", "app", "tools");
        Folder("repository", ".build", "tests", "tools");
        Check(Same(ApplicationPaths.Resolve(app), app), "local app tools take priority over repository");
        Check(Same(ApplicationPaths.Resolve(tests), tests), "local test tools take priority over repository");
    }
    static void Reject(Action action, string description)
    {
        try { action(); }
        catch (ArgumentException) { Check(true, description); return; }
        throw new Exception(description);
    }
    static void ResourceNames()
    {
        foreach (string relative in new[] {
            null, "", " ", "/absolute", @"C:\absolute", @"\\server\share\file",
            @"\rooted", "C:drive-relative", ".", "..", "./file", "../file",
            "nested/./file", "nested/../file", @"nested\..\file", "nested//file",
            @"nested\\file", "nested/", "nested:", "nested/file:stream"
        }) {
            string value = relative;
            Reject(() => ApplicationPaths.Tool(value), "unsafe tool resource rejected: " + value);
            Reject(() => ApplicationPaths.Document(value), "unsafe document resource rejected: " + value);
        }
        Check(Same(ApplicationPaths.Tool("recovery-helper/recovery-helper.exe"),
            Path.Combine(ApplicationPaths.RuntimeRoot, "tools", "recovery-helper", "recovery-helper.exe")),
            "valid nested tool uses runtime tools root");
        Check(Same(ApplicationPaths.Document(@"guides\recovery.md"),
            Path.Combine(ApplicationPaths.RuntimeRoot, "docs", "guides", "recovery.md")),
            "valid document accepts Windows separators");
        Check(Same(ApplicationPaths.Tool("cache/.hidden/image..jpg"),
            Path.Combine(ApplicationPaths.RuntimeRoot, "tools", "cache", ".hidden", "image..jpg")),
            "literal hidden names and dots inside filenames remain valid");
    }
    static void DeliveredResources(string project)
    {
        string current = AppDomain.CurrentDomain.BaseDirectory;
        string runtime = ApplicationPaths.RuntimeRoot;
        if (Directory.Exists(Path.Combine(current, "tools")))
            Check(Same(runtime, current), "portable harness resolves its own delivered runtime");
        else {
            Check(Same(current, Path.Combine(project, ".build", "app")) ||
                Same(current, Path.Combine(project, ".build", "tests")),
                "development harness runs in a documented build directory");
            Check(Same(runtime, project), "development harness resolves current project");
        }
        Check(File.Exists(ApplicationPaths.Tool("recovery-helper/recovery-helper.exe")),
            "resolved delivered helper exists");
        Check(Same(HelperClient.Executable, ApplicationPaths.Tool("recovery-helper/recovery-helper.exe")),
            "actual helper client uses shared resolver");
        Check(File.Exists(ApplicationPaths.Tool("testdisk-7.2/photorec_win.exe")),
            "resolved delivered PhotoRec exists");
        Check(File.Exists(ApplicationPaths.Document("guides/recovery.md")),
            "resolved recovery guide exists");
    }
    public static int Main(string[] args)
    {
        string project = Path.GetFullPath(args[0]);
        string prefix = Path.Combine(project, ".build", "application-paths-");
        work = prefix + Guid.NewGuid().ToString("N");
        Directory.CreateDirectory(work);
        try {
            ResolveLayouts();
            ResourceNames();
            DeliveredResources(project);
            Console.WriteLine("PASS ApplicationPaths: " + checks +
                " checks; synthetic layouts, resource path rejection and delivered helper/PhotoRec/guide presence. No devices or helper processes.");
            return 0;
        } catch (Exception error) {
            Console.Error.WriteLine(error);
            return 1;
        } finally {
            if (Path.GetFullPath(work).StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                Directory.Delete(work, true);
        }
    }
}
