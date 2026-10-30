using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class SessionArtifact { public string Path,Sha256;public long Bytes; }
    public sealed class SessionStage
    {
        public string Key,Status,Message;
        public int Candidates;
        public bool Warnings;
        public List<SessionArtifact> Artifacts=new List<SessionArtifact>();
    }
    public sealed class RecoverySessionState
    {
        public int Schema=1;
        public string SourcePath,SourceSha256,Status,UpdatedUtc,ReadMapSha256,SourceReadMapSha256;
        public long SourceBytes;
        public bool ExternalImage,SourceInWorkingDirectory;
        public RecoveryOptions Options;
        public List<SessionStage> Stages=new List<SessionStage>();
    }
    // Checkpoints completed methods, not arbitrary byte offsets inside a parser.
    // An interrupted method restarts; its finished candidates remain in history.
    public sealed class RecoverySession
    {
        public const string FileName="recovery-session.json";
        public readonly RecoverySessionState State;
        readonly string root;
        static readonly string[] Keys={"partitions","fat","ntfs","ext4","ntfs-records","photorec","photos","containers","archive-members","fragmented-zip","fragmented-photos","fragmented-media","user-signatures","text"};
        RecoverySession(string directory,RecoverySessionState state){root=Path.GetFullPath(directory);State=state;}
        static bool Hash(string value){return value!=null&&value.Length==64&&value.All(Uri.IsHexDigit);}
        static void SourceLocation(string root,string source)
        {
            if(!Path.IsPathRooted(source))throw new IOException("Путь образа в сессии должен быть абсолютным.");
            string folder=Path.GetFullPath(root).TrimEnd('\\','/'),image=Path.GetFullPath(source);
            if(image.StartsWith(folder+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)&&!String.Equals(image,Path.Combine(folder,"usb.dd"),StringComparison.OrdinalIgnoreCase))throw new IOException("Внутри папки поиска допускается только рабочий usb.dd. Другой исходный образ должен находиться отдельно от отчётов.");
        }
        public static RecoverySessionState Read(string root)
        {
            string file=RecoveryCatalog.SafeFile(root,FileName);if(!File.Exists(file)||new FileInfo(file).Length>64L*1024*1024)throw new IOException("Сохранённая сессия не найдена или слишком велика.");
            try{
                var state=new JavaScriptSerializer{MaxJsonLength=64*1024*1024}.Deserialize<RecoverySessionState>(File.ReadAllText(file,Encoding.UTF8));
                if(state==null||state.Schema!=1||state.Options==null||!Hash(state.SourceSha256)||state.SourceBytes<=0||String.IsNullOrEmpty(state.SourcePath)||state.Stages==null||state.Stages.Count>Keys.Length)throw new IOException("Сессия повреждена или имеет неподдерживаемую версию.");
                if(state.SourceInWorkingDirectory)state.SourcePath=RecoveryCatalog.SafeFile(root,"usb.dd");
                if(!new[]{"running","cancelled","error","finished","finished_with_warnings"}.Contains(state.Status))throw new IOException("Неизвестное состояние сессии.");state.Options.Validate();SourceLocation(root,state.SourcePath);var seen=new HashSet<string>(StringComparer.Ordinal);
                foreach(var stage in state.Stages){if(stage==null||!Keys.Contains(stage.Key)||!seen.Add(stage.Key)||stage.Artifacts==null||stage.Artifacts.Count>100000||stage.Candidates<0||!new[]{"running","complete","incomplete","cancelled"}.Contains(stage.Status))throw new IOException("Некорректные этапы сохранённой сессии.");var artifactNames=new HashSet<string>(StringComparer.OrdinalIgnoreCase);foreach(var artifact in stage.Artifacts){if(artifact==null||!artifactNames.Add(artifact.Path)||!Hash(artifact.Sha256)||artifact.Bytes<0)throw new IOException("Некорректная контрольная сумма результата.");RecoveryCatalog.SafeFile(root,artifact.Path);}}
                if(state.ReadMapSha256!=null&&!Hash(state.ReadMapSha256)||state.SourceReadMapSha256!=null&&!Hash(state.SourceReadMapSha256))throw new IOException("Некорректная карта пропусков сессии.");return state;
            }catch(ArgumentException){throw new IOException("Не удалось прочитать сессию поиска.");}catch(InvalidOperationException){throw new IOException("Не удалось прочитать сессию поиска.");}
        }
        public static RecoverySession Start(string root,string source,string sha,RecoveryOptions options,CancellationToken cancel)
        {
            SourceLocation(root,source);
            if(File.Exists(RecoveryCatalog.SafeFile(root,FileName)))throw new IOException("В этой папке уже есть сессия. Нажми «Продолжить…» или создай новый поиск.");
            if(Directory.Exists(RecoveryCatalog.SafeFile(root,"attempt-history")))throw new IOException("В папке есть история предыдущих попыток. Нужна новая папка поиска.");
            foreach(string key in Keys)if(Paths(root,key).Any())throw new IOException("Папка уже содержит результаты. Для нового поиска нужна новая папка.");
            var state=new RecoverySessionState{SourcePath=Path.GetFullPath(source),SourceBytes=new FileInfo(source).Length,SourceSha256=sha,Options=options,Status="running",SourceInWorkingDirectory=String.Equals(Path.GetFullPath(source),RecoveryCatalog.SafeFile(root,"usb.dd"),StringComparison.OrdinalIgnoreCase)};
            string map=RecoveryCatalog.SafeFile(root,"source-read-errors.json");if(File.Exists(map))state.ReadMapSha256=RecoveryCore.HashFile(map,cancel,(a,b)=>{});
            if(File.Exists(source+".read-errors.json"))state.SourceReadMapSha256=RecoveryCore.HashFile(source+".read-errors.json",cancel,(a,b)=>{});
            var session=new RecoverySession(root,state);session.Save();return session;
        }
        public static RecoverySession Open(string root,string image,RecoveryOptions options,CancellationToken cancel,Action<string> progress)
        {
            var state=Read(root);
            if(state.SourceBytes!=new FileInfo(image).Length||!String.Equals(state.SourcePath,Path.GetFullPath(image),StringComparison.OrdinalIgnoreCase))throw new IOException("Источник сессии изменился.");
            string map=RecoveryCatalog.SafeFile(root,"source-read-errors.json");if((state.ReadMapSha256!=null)!=File.Exists(map)||(File.Exists(map)&&!String.Equals(state.ReadMapSha256,RecoveryCore.HashFile(map,cancel,(a,b)=>{}),StringComparison.OrdinalIgnoreCase)))throw new IOException("Карта пропусков изменилась после поиска. Выполни новый анализ образа.");
            string sourceMap=image+".read-errors.json";if((state.SourceReadMapSha256!=null)!=File.Exists(sourceMap)||File.Exists(sourceMap)&&!String.Equals(state.SourceReadMapSha256,RecoveryCore.HashFile(sourceMap,cancel,(a,b)=>{}),StringComparison.OrdinalIgnoreCase))throw new IOException("Карта пропусков рядом с образом изменилась. Создай новый поиск.");
            if(new JavaScriptSerializer().Serialize(options)!=new JavaScriptSerializer().Serialize(state.Options))throw new IOException("Параметры сессии изменились. Для других методов нужен новый поиск.");
            var session=new RecoverySession(root,state);int checkedFiles=0;
            foreach(string key in Keys)if(!state.Stages.Any(s=>s.Key==key)&&Paths(root,key).Any())throw new IOException("В папке появились результаты незаписанного этапа. Создай новый поиск, чтобы не смешивать данные.");
            foreach(var stage in state.Stages.Where(x=>x.Status=="complete")){
                var names=new HashSet<string>(stage.Artifacts.Select(x=>x.Path),StringComparer.OrdinalIgnoreCase);
                var actual=session.Files(stage.Key).Select(x=>x.Substring(session.root.TrimEnd('\\').Length+1).Replace('\\','/')).ToArray();
                if(actual.Length!=names.Count||actual.Any(x=>!names.Contains(x)))throw new IOException("Состав сохранённого этапа изменился. Создай новый поиск; исходные результаты сохранены.");
                foreach(var artifact in stage.Artifacts){cancel.ThrowIfCancellationRequested();string file=RecoveryCatalog.SafeFile(root,artifact.Path);if(!File.Exists(file)||new FileInfo(file).Length!=artifact.Bytes||!String.Equals(RecoveryCore.HashFile(file,cancel,(a,b)=>{}),artifact.Sha256,StringComparison.OrdinalIgnoreCase))throw new IOException("Изменён сохранённый результат: "+artifact.Path+". Сессия не продолжена; исходные файлы сохранены.");if(progress!=null&&++checkedFiles%100==0)progress("Проверка сохранённых результатов: "+checkedFiles);}
            }
            state.Status="running";session.Save();return session;
        }
        public SessionStage Completed(string key){return State.Stages.FirstOrDefault(x=>x.Key==key&&x.Status=="complete");}
        public void Begin(string key)
        {
            SessionStage old=State.Stages.FirstOrDefault(x=>x.Key==key);
            if(old!=null&&old.Status!="complete")Archive(key);
            if(old!=null)State.Stages.Remove(old);State.Stages.Add(new SessionStage{Key=key,Status="running"});Save();
        }
        public void Finish(string key,int count,bool warnings,CancellationToken cancel)
        {
            var stage=State.Stages.Single(x=>x.Key==key);var artifacts=new List<SessionArtifact>();
            foreach(string file in Files(key)){
                cancel.ThrowIfCancellationRequested();if(artifacts.Count>=100000)throw new IOException("Слишком много файлов для безопасного сохранения этапа.");string relative=file.Substring(root.TrimEnd('\\').Length+1).Replace('\\','/');RecoveryCatalog.SafeFile(root,relative);
                artifacts.Add(new SessionArtifact{Path=relative,Bytes=new FileInfo(file).Length,Sha256=RecoveryCore.HashFile(file,cancel,(a,b)=>{})});
            }
            cancel.ThrowIfCancellationRequested();stage.Artifacts=artifacts;stage.Candidates=count;stage.Warnings=warnings;stage.Status="complete";Save();
        }
        public void Fail(string key,string status,string message){var stage=State.Stages.FirstOrDefault(x=>x.Key==key);if(stage!=null){stage.Status=status;stage.Message=message;}Save();}
        public void Status(string value){State.Status=value;Save();}
        void Save(){State.UpdatedUtc=DateTime.UtcNow.ToString("o");RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(root,FileName),State);}
        static IEnumerable<string> Paths(string root,string key)
        {
            string[] names=key=="partitions"?new[]{"partition-search.json"}:key=="fat"?new[]{"filesystem"}:key=="ntfs"?new[]{"ntfs"}:key=="ext4"?new[]{"ext4"}:key=="ntfs-records"?new[]{"metadata-rescue"}:key=="photos"?new[]{"extra-photos","extra-photo-search.json"}:key=="containers"?new[]{"containers","container-search.json"}:key=="archive-members"?new[]{"salvage-content","archive-salvage.json"}:key=="fragmented-zip"?new[]{"fragmented-archives","fragmented-zip.json"}:key=="fragmented-photos"?new[]{"fragmented-photos","fragmented-photo-search.json"}:key=="fragmented-media"?new[]{"fragmented-media","fragmented-media.json"}:key=="user-signatures"?new[]{"user-signatures","user-signatures.json"}:key=="text"?new[]{"text-fragments","text-search.json"}:new[]{"photorec.log","photorec.ses"};
            foreach(string name in names){string path=RecoveryCatalog.SafeFile(root,name);if(File.Exists(path)||Directory.Exists(path))yield return path;}
            if(key=="photorec")foreach(string path in Directory.EnumerateDirectories(root,"files.*")){RecoveryCatalog.SafeFile(root,Path.GetFileName(path)+"/guard");yield return path;}
        }
        IEnumerable<string> Files(string key)
        {
            foreach(string path in Paths(root,key)){
                if(File.Exists(path)){yield return path;continue;}
                var todo=new Stack<string>();todo.Push(path);
                while(todo.Count>0){string at=todo.Pop();RecoveryCatalog.SafeFile(root,at.Substring(root.TrimEnd('\\').Length+1)+"/guard");foreach(string file in Directory.EnumerateFiles(at))if(!file.EndsWith(".partial",StringComparison.OrdinalIgnoreCase))yield return file;foreach(string child in Directory.EnumerateDirectories(at))todo.Push(child);}
            }
        }
        void Archive(string key)
        {
            string[] paths=Paths(root,key).ToArray();if(paths.Length==0)return;
            int files=0;foreach(string path in Files(key)){if(++files>100000)throw new IOException("Слишком много файлов предыдущей попытки. Создай новый поиск.");RecoveryCatalog.SafeFile(root,path.Substring(root.TrimEnd('\\').Length+1));}
            string target=RecoveryCatalog.SafeFile(root,"attempt-history/"+key.Substring(0,Math.Min(4,key.Length))+"-"+Guid.NewGuid().ToString("N").Substring(0,8)+"/note.json");
            foreach(string path in Files(key)){string start=paths.First(p=>path==p||path.StartsWith(p+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase));string name=Path.GetFileName(start);string future=Path.Combine(Path.GetDirectoryName(target),name)+path.Substring(start.Length);if(future.Length>245)throw new IOException("Путь предыдущей попытки слишком длинный. Перенеси всю папку съёма ближе к корню диска и продолжи.");}
            Directory.CreateDirectory(Path.GetDirectoryName(target));
            foreach(string path in paths){string dest=RecoveryCatalog.SafeFile(root,Path.GetDirectoryName(target).Substring(root.TrimEnd('\\').Length+1)+"/"+Path.GetFileName(path));if(Directory.Exists(path))Directory.Move(path,dest);else File.Move(path,dest);}
            RecoveryCore.SaveJson(target,new{stage=key,status="previous_interrupted_attempt",note="Completed candidates retained. An interrupted method restarted from its beginning; previous output may be partial."});
        }
    }
}
