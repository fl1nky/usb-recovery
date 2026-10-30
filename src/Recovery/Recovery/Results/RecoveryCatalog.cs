using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class OriginalLocation { public string Path,Status,Evidence,CandidatePath,FileSystem,VolumeId,SnapshotId,CheckpointId;public long? VolumeOffset;public List<string> Components; }
    public sealed class RecoveredItem
    {
        public string Name, Path, Extension, Category, Method, Status, Sha256, Note;
        public string Quality, QualityLabel, IntegrityDetail;
        public string OriginalPath,OriginalPathStatus,OriginalPathEvidence;
        public string SourceCandidatePath;
        public long? SourceVolumeOffset;
        public List<OriginalLocation> OriginalLocations=new List<OriginalLocation>();
        public long? SourceOffset, UnreadBytes;
        public List<FileExtent> SourceRanges = new List<FileExtent>();
        public long Bytes;
        public List<string> Copies = new List<string>();
    }
    public sealed class RecoveryFileIndex { public int Candidates; public List<RecoveredItem> Items = new List<RecoveredItem>(); }
    public static class RecoveryCatalog
    {
        static JavaScriptSerializer Json() { return new JavaScriptSerializer { MaxJsonLength=256*1024*1024 }; }
        public static string LogicalPath(string relative)
        {
            if(relative.StartsWith("attempt-history/",StringComparison.Ordinal)){int end=relative.IndexOf('/',16);if(end>=0)return relative.Substring(end+1);}return relative;
        }
        public static string Category(string ext)
        {
            ext=(ext??"").ToLowerInvariant();
            if(new[]{".jpg",".jpeg",".jpe",".jfif",".png",".gif",".bmp",".tif",".tiff",".webp",".heic",".heif",".avif",".dng",".cr2",".cr3",".nef",".nrw",".arw",".sr2",".srf",".raf",".rw2",".orf",".pef",".raw"}.Contains(ext))return "Фотографии";
            if(new[]{".mp4",".mov",".avi",".mkv",".mpg",".mpeg",".mts",".m2ts",".3gp",".webm"}.Contains(ext))return "Видео";
            if(new[]{".mp3",".wav",".m4a",".aac",".flac",".ogg",".amr"}.Contains(ext))return "Аудио";
            if(new[]{".pdf",".doc",".docx",".xls",".xlsx",".ppt",".pptx",".odt",".ods",".rtf",".txt",".csv"}.Contains(ext))return "Документы";
            if(new[]{".zip",".rar",".7z",".gz",".tar",".bz2",".xz"}.Contains(ext))return "Архивы";
            return "Прочее";
        }
        public static string SafeFile(string root,string relative)
        {
            string fullRoot=System.IO.Path.GetFullPath(root).TrimEnd('\\','/'),full=System.IO.Path.GetFullPath(System.IO.Path.Combine(fullRoot,relative??""));
            if(!full.StartsWith(fullRoot+System.IO.Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Путь вне архива.");
            for(var entry=new DirectoryInfo(System.IO.Path.GetDirectoryName(full));entry!=null;entry=entry.Parent)
                if(entry.Exists && (entry.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Перенаправление пути недопустимо.");
            if(File.Exists(full) && (File.GetAttributes(full)&FileAttributes.ReparsePoint)!=0)throw new IOException("Файл-ссылка недопустим.");
            return full;
        }
        public static RecoveryFileIndex Build(string root,CancellationToken cancel,Action<string> progress)
        {
            bool unreadImage=FileEvidence.HasUnreadSource(root);
            var result=new RecoveryFileIndex();var grouped=new Dictionary<string,RecoveredItem>(StringComparer.Ordinal);var photos=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            string photoIndex=System.IO.Path.Combine(root,"photo-catalog.json");
            if(File.Exists(photoIndex)) {
                var index=Json().Deserialize<Dictionary<string,object>>(File.ReadAllText(photoIndex,Encoding.UTF8));object values;
                if(index.TryGetValue("items",out values))foreach(var raw in (System.Collections.IEnumerable)values) {
                    var item=raw as Dictionary<string,object>;if(item!=null && item.ContainsKey("Path") && item.ContainsKey("Status"))photos[Convert.ToString(item["Path"])]=Convert.ToString(item["Status"]);
                }
            }
            foreach(string file in RecoveryCore.RecoveredFiles(root)) {
                cancel.ThrowIfCancellationRequested();if(result.Candidates>=100000)throw new IOException("Каталог ограничен 100 000 файлами. Исходные результаты движков сохранены.");
                string relative=file.Substring(System.IO.Path.GetFullPath(root).TrimEnd('\\').Length+1).Replace('\\','/');SafeFile(root,relative);
                string sha=RecoveryCore.HashFile(file,cancel,(a,b)=>{});result.Candidates++;
                RecoveredItem old;if(grouped.TryGetValue(sha,out old)){
                    if((LogicalPath(relative).StartsWith("filesystem/",StringComparison.Ordinal)||LogicalPath(relative).StartsWith("ntfs/",StringComparison.Ordinal))&&old.Method=="PhotoRec"){
                        old.Copies.Add(old.Path);old.Path=relative;old.Name=System.IO.Path.GetFileName(file);old.Extension=System.IO.Path.GetExtension(file);old.Category=Category(old.Extension);old.Method=LogicalPath(relative).StartsWith("ntfs/",StringComparison.Ordinal)?"NTFS":"FAT/exFAT";
                    }else old.Copies.Add(relative);continue;
                }
                string ext=System.IO.Path.GetExtension(file),status;photos.TryGetValue(relative,out status);
                string method=LogicalPath(relative).StartsWith("apfs-files/",StringComparison.Ordinal)?"APFS":LogicalPath(relative).StartsWith("user-signatures/",StringComparison.Ordinal)?"Своя сигнатура":LogicalPath(relative).StartsWith("filesystem/",StringComparison.Ordinal)?"FAT/exFAT":LogicalPath(relative).StartsWith("ntfs/",StringComparison.Ordinal)?"NTFS":LogicalPath(relative).StartsWith("metadata-rescue/",StringComparison.Ordinal)?"Независимые записи NTFS":LogicalPath(relative).StartsWith("fragmented-archives/",StringComparison.Ordinal)?"Сборка ZIP / Office":LogicalPath(relative).StartsWith("salvage-content/",StringComparison.Ordinal)?"Часть ZIP / Office":LogicalPath(relative).StartsWith("extra-photos/",StringComparison.Ordinal)?"JPEG/PNG внутри данных":LogicalPath(relative).StartsWith("containers/",StringComparison.Ordinal)?"Контейнер по смещению":"PhotoRec";
                var item=new RecoveredItem { Name=System.IO.Path.GetFileName(file),Path=relative,Extension=ext,Category=Category(ext),Method=method,Bytes=new FileInfo(file).Length,Sha256=sha,Status=status=="decoded"?"Изображение открывается":status=="partial"||status=="damaged_candidate"?"Повреждённый кандидат":"Требует проверки",Note="Наличие файла не доказывает целостность или факт удаления. Сравни содержимое с ожидаемым. Все копии сохранены." };
                if(method=="Контейнер по смещению")item.Note="Найдена структура контейнера; содержимое/CRC и фрагментация полностью не подтверждены. Имя и дата неизвестны.";
                if(LogicalPath(relative).StartsWith("text-fragments/",StringComparison.Ordinal)){item.Method="Текстовый остаток";item.Status="Фрагмент, не документ";item.Note="Только найденная строка. Границы документа, автор, дата и факт удаления неизвестны. Позиция и исходная кодировка: text-search.json.";}
                if(relative.Contains("/orphan-")){item.Status="Потерянный каталог";item.Note+=" Каталог не связан с корнем. Исходный родитель и факт удаления файла неизвестны.";}
                if(unreadImage){item.Status="Образ с пропусками";item.Note+=" В исходном образе есть непрочитанные участки, заменённые нулями. Карта пересечений и ограничения приведены в проверке содержимого; см. source-read-errors.json.";}
                grouped.Add(sha,item);result.Items.Add(item);if(progress!=null && result.Candidates%100==0)progress("Каталог файлов: "+result.Candidates+"; уникальных: "+result.Items.Count);
            }
            var evidence=FileEvidence.Load(root);int checkedFiles=0;
            foreach(var item in result.Items) {
                cancel.ThrowIfCancellationRequested();ContentVerification verification;
                try { verification=ContentVerifier.Verify(SafeFile(root,item.Path),cancel); }
                catch(IOException){ verification=new ContentVerification{Code="unverified",Label="Проверка не завершена",Detail="Не удалось завершить дополнительную проверку содержимого. Сравни сохранённый файл с ожидаемым."}; }
                item.Quality=verification.Code;item.QualityLabel=verification.Label;item.IntegrityDetail=verification.Detail;
                string photoState;photos.TryGetValue(item.Path,out photoState);
                if(photoState=="decoded"){item.Quality="decoded";item.QualityLabel="Изображение декодируется";item.IntegrityDetail="Изображение открылось декодером. Это не доказывает, что оно полное и совпадает с исходным. "+item.IntegrityDetail;}
                if(photoState=="partial"||photoState=="damaged_candidate"){item.Quality="damaged";item.QualityLabel="Изображение повреждено";}
                if(LogicalPath(item.Path).StartsWith("text-fragments/",StringComparison.Ordinal)){item.Quality="fragment";item.QualityLabel="Текстовый фрагмент";item.IntegrityDetail="Сохранившаяся строка, границы исходного документа неизвестны. "+item.IntegrityDetail;}
                if(LogicalPath(item.Path).StartsWith("salvage-content/",StringComparison.Ordinal)){
                    item.Status="Часть архива";item.Note="Отдельный член ZIP. Целостность и полнота целого архива или Office-документа не заявляются.";
                    var proof=evidence.For(item.Path);
                    if(proof!=null&&proof.VerificationStatus=="member_crc_verified"&&String.Equals(proof.VerifiedSha256,item.Sha256,StringComparison.OrdinalIgnoreCase)&&proof.VerifiedBytes==item.Bytes){item.Quality="member_crc";item.QualityLabel="CRC части архива проверен";item.IntegrityDetail="Размер, CRC и SHA256 отдельной ZIP-записи подтверждены манифестом извлечения. "+item.IntegrityDetail;}
                    else {item.Quality=proof==null?"unverified":"changed";item.QualityLabel=proof==null?"Нет подтверждения извлечения":"Изменён после извлечения";item.IntegrityDetail="Манифест извлечения отсутствует или не совпадает с текущими размером/SHA256. Прежняя проверка CRC не переносится на этот файл. "+item.IntegrityDetail;}
                }
                if(LogicalPath(item.Path).StartsWith("user-signatures/",StringComparison.Ordinal)){item.Status="По своей сигнатуре";item.Quality="signature_candidate";item.QualityLabel="Граница по правилу";item.Note="Непрерывные байты по заданным началу и границе. Исходное имя, удаление и полнота неизвестны.";item.IntegrityDetail="Граница задана пользовательским правилом; это не проверка формата или первоначальной полноты. "+item.IntegrityDetail;}
                if(LogicalPath(item.Path).StartsWith("metadata-rescue/",StringComparison.Ordinal))item.Note+=" Уцелевшая запись NTFS; имя и карта данных проверяются отдельно от содержимого. См. metadata-rescue/report.json.";
                evidence.Apply(item);if(item.OriginalPathStatus=="verified_parent_chain"&&!String.IsNullOrEmpty(item.OriginalPath))item.Name=System.IO.Path.GetFileName(item.OriginalPath.Replace('/','\\'));if(progress!=null&&++checkedFiles%50==0)progress("Проверка содержимого: "+checkedFiles+" / "+result.Items.Count);
            }
            cancel.ThrowIfCancellationRequested();RecoveryCore.SaveJson(System.IO.Path.Combine(root,"files-index.json"),result);
            var csv=new StringBuilder("name,relative_path,category,method,status,bytes,sha256,copies,quality,integrity_detail,source_offset,unread_bytes,original_path,path_evidence,original_volume_offset,all_original_paths\r\n");foreach(var item in result.Items)csv.AppendLine(String.Join(",",new[]{item.Name,item.Path,item.Category,item.Method,item.Status,item.Bytes.ToString(System.Globalization.CultureInfo.InvariantCulture),item.Sha256,(item.Copies.Count+1).ToString(),item.QualityLabel,item.IntegrityDetail,item.SourceOffset.HasValue?item.SourceOffset.Value.ToString(System.Globalization.CultureInfo.InvariantCulture):"",item.UnreadBytes.HasValue?item.UnreadBytes.Value.ToString(System.Globalization.CultureInfo.InvariantCulture):"",item.OriginalPath,item.OriginalPathEvidence,item.SourceVolumeOffset.HasValue?item.SourceVolumeOffset.Value.ToString(System.Globalization.CultureInfo.InvariantCulture):"",String.Join("; ",item.OriginalLocations.Select(x=>x.Path))}.Select(Cell)));
            File.WriteAllText(System.IO.Path.Combine(root,"files-index.csv"),csv.ToString(),new UTF8Encoding(true));
            string payload=Json().Serialize(result.Items).Replace("<","\\u003c").Replace("\u2028","\\u2028").Replace("\u2029","\\u2029");
            string html="<!doctype html><html lang=ru><meta charset=utf-8><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'\"><title>Найденные файлы</title><style>body{font:15px Segoe UI,sans-serif;margin:32px;color:#24272b}input,select,button{font:inherit;padding:8px;border:1px solid #ccc;background:white}table{border-collapse:collapse;width:100%;margin:20px 0}td,th{padding:10px;text-align:left;border-bottom:1px solid #ddd}small{color:#666}h1{font-size:28px}</style><h1>Найденные файлы</h1><p>Проверяй содержимое перед использованием. Имена по смещению придуманы программой; даты удаления неизвестны. Повторы объединены только по SHA256; оригиналы сохранены.</p><input id=q placeholder='Имя, путь, SHA256'><select id=cat><option value=''>Все типы</option><option>Фотографии</option><option>Видео</option><option>Аудио</option><option>Документы</option><option>Архивы</option><option>Прочее</option></select><p id=count></p><table><thead><tr><th>Файл</th><th>Тип</th><th>Способ</th><th>Состояние</th><th>Байт</th><th>Копий</th></tr></thead><tbody id=rows></tbody></table><button id=prev>Назад</button> <button id=next>Далее</button><p>Для копирования выбранных файлов открой «Все файлы» в программе. Машинные списки: files-index.json / files-index.csv. Не восстанавливай поверх исходной флешки.</p><script type=application/json id=data>"+payload+"</script><script>const data=JSON.parse(document.getElementById('data').textContent);let page=0;function draw(){const q=document.getElementById('q').value.toLocaleLowerCase(),cat=document.getElementById('cat').value;const list=data.filter(x=>(!cat||x.Category===cat)&&[x.Name,x.Path,x.Sha256,x.OriginalPath||''].concat((x.OriginalLocations||[]).map(y=>y.Path||'')).some(t=>t.toLocaleLowerCase().includes(q)));page=Math.max(0,Math.min(page,Math.ceil(list.length/100)-1));document.getElementById('count').textContent='Уникальных файлов: '+list.length;const root=document.getElementById('rows');root.replaceChildren();for(const x of list.slice(page*100,page*100+100)){const row=document.createElement('tr');for(const t of [x.Path,x.Category,x.Method,(x.QualityLabel||x.Status),x.Bytes,x.Copies.length+1]){const c=document.createElement('td');c.textContent=t;row.append(c)}root.append(row)}}document.getElementById('q').oninput=document.getElementById('cat').onchange=()=>{page=0;draw()};document.getElementById('prev').onclick=()=>{page--;draw()};document.getElementById('next').onclick=()=>{page++;draw()};draw()</script></html>";
            string path=System.IO.Path.Combine(root,"Все файлы.html");File.WriteAllText(path,html,new UTF8Encoding(false));return result;
        }
        static string Cell(string value) { value=value??"";if(value.Length>0 && "=+-@\t\r".IndexOf(value[0])>=0)value="'"+value;return "\""+value.Replace("\"","\"\"")+"\""; }
        public static RecoveryFileIndex Load(string root) {
            string file=SafeFile(root,"files-index.json");if(new FileInfo(file).Length>256L*1024*1024)throw new IOException("Слишком большой каталог.");
            try {
                var index=Json().Deserialize<RecoveryFileIndex>(File.ReadAllText(file,Encoding.UTF8));
                if(index==null||index.Items==null||index.Items.Count>100000)throw new IOException("Каталог не завершён или повреждён.");
                foreach(var item in index.Items){if(item==null||String.IsNullOrEmpty(item.Name)||String.IsNullOrEmpty(item.Path)||item.Sha256==null||item.Sha256.Length!=64||item.Sha256.Any(c=>!Uri.IsHexDigit(c)))throw new IOException("Некорректная запись каталога.");SafeFile(root,item.Path);if(item.Copies==null)item.Copies=new List<string>();if(item.OriginalLocations==null)item.OriginalLocations=new List<OriginalLocation>();}
                return index;
            }catch(ArgumentException){throw new IOException("Не удалось прочитать каталог. Возможно, его создание не завершилось.");}catch(InvalidOperationException){throw new IOException("Не удалось прочитать каталог.");}
        }
        public static string Export(string root,string destination,IEnumerable<RecoveredItem> selected,CancellationToken cancel)
        { return ExportChecked(root,destination,selected,cancel,false); }
        public static string ExportPreservingFolders(string root,string destination,IEnumerable<RecoveredItem> selected,CancellationToken cancel)
        { return ExportChecked(root,destination,selected,cancel,true); }
        static string ExportChecked(string root,string destination,IEnumerable<RecoveredItem> selected,CancellationToken cancel,bool preserveFolders)
        {
            root=System.IO.Path.GetFullPath(root).TrimEnd('\\');destination=RecoveryCore.CanonicalDirectory(destination);
            if(destination.Equals(root,StringComparison.OrdinalIgnoreCase)||destination.StartsWith(root+"\\",StringComparison.OrdinalIgnoreCase))throw new IOException("Выбери отдельную папку для экспорта.");
            string capture=System.IO.Path.Combine(root,"capture.json");if(!File.Exists(capture))capture=System.IO.Path.Combine(root,"source-image.json");
            if(File.Exists(capture)) {
                var data=Json().Deserialize<Dictionary<string,object>>(File.ReadAllText(capture,Encoding.UTF8));object disk;int targetNumber=RecoveryCore.DiskForDirectory(destination);
                if(data.TryGetValue("sourceDisk",out disk)&&Convert.ToInt32(disk)==targetNumber)throw new IOException("Нельзя копировать результаты на исходную флешку.");
                object unique,serial;data.TryGetValue("sourceUniqueId",out unique);data.TryGetValue("sourceSerial",out serial);
                if(!String.IsNullOrEmpty(Convert.ToString(unique))||!String.IsNullOrEmpty(Convert.ToString(serial))) {
                    var target=RecoveryCore.ListDisks().FirstOrDefault(x=>x.Number==targetNumber);if(target==null)throw new IOException("Не удалось проверить диск назначения.");
                    if((!String.IsNullOrEmpty(Convert.ToString(unique))&&Convert.ToString(unique)==target.UniqueId)||(!String.IsNullOrEmpty(Convert.ToString(serial))&&Convert.ToString(serial)==target.Serial))throw new IOException("Это исходная флешка, даже если её номер изменился.");
                }
            }
            return ExportFilesCore(root,destination,selected,cancel,preserveFolders);
        }
        // The UI calls Export, including physical-destination checks. This
        // separate primitive permits synthetic tests without touching hardware.
        internal static string ExportFiles(string root,string destination,IEnumerable<RecoveredItem> selected,CancellationToken cancel)
        { return ExportFilesCore(root,destination,selected,cancel,false); }
        internal static string ExportFilesPreservingFolders(string root,string destination,IEnumerable<RecoveredItem> selected,CancellationToken cancel)
        { return ExportFilesCore(root,destination,selected,cancel,true); }
        sealed class ExportLocation { public string Relative,Original,Status;public long? Volume; }
        static string ShortHash(string value)
        {
            using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(value??""))).Replace("-","").Substring(0,12).ToLowerInvariant();
        }
        static string ExportComponent(string value,int maximum)
        {
            string original=value??"";var text=new StringBuilder();foreach(char c in original)text.Append(c<32||c==127||"<>:\"/\\|?*".IndexOf(c)>=0||Char.IsSurrogate(c)?'_':c);
            string name=text.ToString().TrimEnd(' ','.');if(name.Length==0)name="_";
            string stem=name.Split('.')[0].TrimEnd(' ');if(new[]{"CON","PRN","AUX","NUL","CONIN$","CONOUT$","CLOCK$","COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9","COM¹","COM²","COM³","LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9","LPT¹","LPT²","LPT³"}.Contains(stem,StringComparer.OrdinalIgnoreCase))name="_"+name;
            if(name.Length>maximum)name=name.Substring(0,maximum-13)+"~"+ShortHash(original);
            if(name!=original&&name.Length+13<=maximum)name+="~"+ShortHash(original);
            return name;
        }
        static IEnumerable<ExportLocation> ExportLocations(RecoveredItem item)
        {
            var seen=new HashSet<string>(StringComparer.Ordinal);if(item.OriginalLocations!=null)foreach(var location in item.OriginalLocations){
                if(location==null||(location.Status!="verified_parent_chain"&&location.Status!="apfs_referenced_path"&&location.Status!="apfs_snapshot_path"&&location.Status!="apfs_checkpoint_path")||!location.VolumeOffset.HasValue||location.VolumeOffset.Value<0||String.IsNullOrEmpty(location.Path)||String.IsNullOrEmpty(location.Evidence)||String.IsNullOrEmpty(location.CandidatePath))continue;
                // Metadata paths are virtual root paths. Windows drive, UNC and
                // traversal forms must never become filesystem instructions.
                string path=location.Path;string[] parts;
                if(location.FileSystem=="APFS"&&location.Components!=null){parts=location.Components.ToArray();if(parts.Any(x=>x==null||x.IndexOf('/')>=0||x.IndexOf('\0')>=0))continue;path=String.Join("/",parts);}
                else{path=path.Replace('\\','/');if(path.StartsWith("//",StringComparison.Ordinal)||path.IndexOf(':')>=0||path.Length>32768)continue;parts=path.TrimStart('/').Split('/');}
                if(parts.Length==0||parts.Length>256||parts.Any(x=>x.Length==0||x=="."||x==".."))continue;
                string scope=location.FileSystem=="APFS"?"APFS-"+ExportComponent(location.VolumeId??"unknown",48)+"/"+ExportComponent(!String.IsNullOrEmpty(location.SnapshotId)?"Снимок-"+location.SnapshotId:!String.IsNullOrEmpty(location.CheckpointId)?"Состояние-"+location.CheckpointId:"Текущее состояние",48):"Том-"+location.VolumeOffset.Value.ToString("X16");string identity=scope+":"+location.VolumeOffset.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)+":"+path;if(!seen.Add(identity))continue;
                yield return new ExportLocation{Relative=scope+"/"+String.Join("/",parts.Select((x,i)=>ExportComponent(x,i==parts.Length-1?100:64))),Original=location.Path,Status=location.Status,Volume=location.VolumeOffset};
            }
            if(seen.Count==0)yield return new ExportLocation{Relative="Без подтверждённой папки/"+ExportComponent(item.Name,100),Status="unknown_or_unconfirmed"};
        }
        static string UniqueExportPath(string output,string relative,RecoveredItem item,Dictionary<string,string> allocated,Dictionary<string,string> directories)
        {
            // Keep the entire target within the classic Windows path limit,
            // Temporary files use a separate short name in the output root.
            int limit=208-output.Length;if(limit<52)throw new IOException("Выбери более короткий путь для экспорта.");
            if(relative.Length>limit)relative="Длинные пути/"+ShortHash(relative)+"_"+ExportComponent(item.Name,Math.Min(100,limit-27));
            var parts=relative.Split('/');string originalPrefix="",actualPrefix="";for(int i=0;i<parts.Length-1;i++){
                originalPrefix+=(i==0?"":"/")+parts[i];string actual;if(!directories.TryGetValue(originalPrefix,out actual)){
                    actual=actualPrefix+(i==0?"":"/")+parts[i];if(allocated.ContainsKey(actual))actual+="~папка-"+ShortHash(originalPrefix);directories.Add(originalPrefix,actual);
                }actualPrefix=actual;
            }
            relative=(actualPrefix.Length==0?"":actualPrefix+"/")+parts[parts.Length-1];
            if(allocated.ContainsKey(relative)||directories.Values.Contains(relative,StringComparer.OrdinalIgnoreCase)){
                string extension=System.IO.Path.GetExtension(relative),baseName=relative.Substring(0,relative.Length-extension.Length);int suffix=1;string candidate;
                do{candidate=baseName+"~"+item.Sha256.Substring(0,12).ToLowerInvariant()+(suffix==1?"":"-"+suffix.ToString(System.Globalization.CultureInfo.InvariantCulture))+extension;suffix++;}while(allocated.ContainsKey(candidate)||directories.Values.Contains(candidate,StringComparer.OrdinalIgnoreCase));relative=candidate;
            }
            if(relative.Length+output.Length>240)relative="Длинные пути/"+ShortHash(relative)+"_"+ShortHash(item.Sha256)+".bin";
            if(allocated.ContainsKey(relative))throw new IOException("Конфликт имён экспорта. Выбери более короткий путь.");
            allocated.Add(relative,item.Sha256);return relative;
        }
        static void CopyExportFile(string source,string target,string temporary,RecoveredItem item,CancellationToken cancel)
        {
            bool ownsTemporary=false;
            try {
                using(var input=new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read))
                using(var file=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) {
                    ownsTemporary=true;
                    using(var hash=SHA256.Create()) {
                        byte[] block=new byte[1024*1024];int count;
                        while((count=input.Read(block,0,block.Length))>0){cancel.ThrowIfCancellationRequested();file.Write(block,0,count);hash.TransformBlock(block,0,count,null,0);}
                        hash.TransformFinalBlock(new byte[0],0,0);
                        if(input.Length!=item.Bytes||!String.Equals(BitConverter.ToString(hash.Hash).Replace("-", ""),item.Sha256,StringComparison.OrdinalIgnoreCase))throw new IOException("Файл изменился после поиска. Экспорт остановлен.");
                        file.Flush(true);
                    }
                }
                cancel.ThrowIfCancellationRequested();File.Move(temporary,target);ownsTemporary=false;
            } finally {if(ownsTemporary&&File.Exists(temporary))File.Delete(temporary);}
        }
        static string ExportFilesCore(string root,string destination,IEnumerable<RecoveredItem> selected,CancellationToken cancel,bool preserveFolders)
        {
            cancel.ThrowIfCancellationRequested();string output=System.IO.Path.Combine(destination,"Recovered-"+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N").Substring(0,8));Directory.CreateDirectory(output);var records=new List<object>();string status="incomplete";var allocated=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);var directories=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);int selectedCount=0;
            try {
                foreach(var item in selected) {
                    selectedCount++;
                    cancel.ThrowIfCancellationRequested();string source=SafeFile(root,item.Path),name=String.Concat(item.Name.Where(c=>Array.IndexOf(System.IO.Path.GetInvalidFileNameChars(),c)<0));
                    if(name.Length>120)name=name.Substring(0,100)+System.IO.Path.GetExtension(name);if(name.Length==0)name="file";
                    var locations=preserveFolders?ExportLocations(item):new[]{new ExportLocation{Relative=(records.Count+1).ToString("D6")+"_"+name,Status="flat_export"}};
                    foreach(var location in locations){
                    cancel.ThrowIfCancellationRequested();string relative=UniqueExportPath(output,location.Relative,item,allocated,directories),target=SafeFile(output,relative),partial=SafeFile(output,".export-"+Guid.NewGuid().ToString("N")+".partial");Directory.CreateDirectory(System.IO.Path.GetDirectoryName(target));SafeFile(output,relative);
                    CopyExportFile(source,target,partial,item,cancel);
                    records.Add(new{file=relative.Replace('\\','/'),source=item.Path,sha256=item.Sha256,otherCopies=item.Copies,quality=item.Quality,qualityLabel=item.QualityLabel,integrityDetail=item.IntegrityDetail,sourceOffset=item.SourceOffset,sourceRanges=item.SourceRanges,sourceCandidate=item.SourceCandidatePath,unreadBytes=item.UnreadBytes,originalPath=item.OriginalPath,pathStatus=item.OriginalPathStatus,pathEvidence=item.OriginalPathEvidence,originalLocations=item.OriginalLocations,exportedOriginalPath=location.Original,exportedPathStatus=location.Status,exportedVolumeOffset=location.Volume});
                    }
                }
                status="complete";return output;
            } finally {RecoveryCore.SaveJson(System.IO.Path.Combine(output,"export-manifest.json"),new{status=status,preserveFolders=preserveFolders,selectedFiles=selectedCount,files=records});}
        }
    }
}
