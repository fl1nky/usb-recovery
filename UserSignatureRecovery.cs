using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class UserSignatureRule
    {
        public string Id,Name,Extension,HeaderHex,FooterHex;
        public long HeaderOffset,FixedBytes,MaxBytes,MinBytes;
    }

    // Independent literal header/footer carver. Unlike a file-format parser,
    // user-supplied boundaries do not prove that a recovered file is intact.
    // Comparable UI concept: https://dmde.com/manual/fullscan.html#raw
    public static class UserSignatureRecovery
    {
        public const int MaximumRules=32,MaximumCandidates=20000,MaximumFiles=10000,MaximumPatternBytes=256;
        public const long MaximumFileBytes=128L*1024*1024,MaximumOutputBytes=512L*1024*1024,MaximumFooterWorkBytes=512L*1024*1024,MaximumHeaderWorkBytes=512L*1024*1024;
        const int BlockBytes=1024*1024;
        public sealed class Result
        {
            public string Path,Sha256,RuleId,RuleName,Boundary,Status="signature_candidate";
            public long Offset,HeaderOffset,Bytes;
            public string Note="Literal user signature candidate; length is based on the supplied fixed size or first matching footer. Original name, deletion state, file-format validity and completeness are unknown.";
        }
        public sealed class Report
        {
            public int Schema=1,Candidates,Recovered;
            public string Status="incomplete";
            public long InputBytes,OutputBytes,FooterWorkBytes,HeaderWorkBytes;
            public List<UserSignatureRule> Rules=new List<UserSignatureRule>();
            public List<Result> Files=new List<Result>();
            public Dictionary<string,int> Skipped=new Dictionary<string,int>(StringComparer.Ordinal);
            public string Scope="Contiguous bytes only. Literal headers and user-provided fixed length or first matching footer; no format validation, fragment reconstruction or proof of deletion. Technical limits make excessively common rules an incomplete scan, not a successful full search.";
        }
        sealed class Compiled
        {
            public UserSignatureRule Rule;public byte[] Header,Footer;public int[] Failure;
        }
        static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=128*1024,RecursionLimit=8};}
        static IOException Invalid(string message){return new IOException("USER_SIGNATURE_INVALID: "+message);}
        public static byte[] DecodeHex(string value)
        {
            if(value==null)throw Invalid("Укажи байты сигнатуры.");
            if(value.Length>MaximumPatternBytes*3+8)throw Invalid("Слишком длинная сигнатура.");
            string compact=Regex.Replace(value,"\\s+","");
            if(compact.Length==0||compact.Length%2!=0||!Regex.IsMatch(compact,"\\A[0-9a-fA-F]+\\z"))throw Invalid("Нужны пары шестнадцатеричных цифр, например 50 4B 03 04.");
            if(compact.Length>MaximumPatternBytes*2)throw Invalid("Не более 256 байт в сигнатуре.");
            var bytes=new byte[compact.Length/2];for(int i=0;i<bytes.Length;i++)bytes[i]=Convert.ToByte(compact.Substring(i*2,2),16);return bytes;
        }
        static string Hex(byte[] bytes){return BitConverter.ToString(bytes).Replace('-', ' ');}
        static UserSignatureRule Clone(UserSignatureRule rule)
        {
            if(rule==null)throw Invalid("Пустое правило.");
            if(String.IsNullOrWhiteSpace(rule.Id)||!Regex.IsMatch(rule.Id,"\\A[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}\\z"))throw Invalid("ID: от 1 до 40 букв, цифр, _ или -.");
            string name=(rule.Name??"").Trim();if(name.Length<1||name.Length>80||name.Any(Char.IsControl))throw Invalid("Название: от 1 до 80 обычных символов.");
            string extension=(rule.Extension??"").Trim().TrimStart('.').ToLowerInvariant();
            if(!Regex.IsMatch(extension,"\\A[a-z0-9]{1,12}\\z"))throw Invalid("Расширение: от 1 до 12 букв или цифр.");
            if(rule.HeaderOffset<0||rule.HeaderOffset>4096)throw Invalid("Смещение заголовка: от 0 до 4096 байт.");
            byte[] header=DecodeHex(rule.HeaderHex);if(header.Length<4||header.Distinct().Count()<3)throw Invalid("Нужны хотя бы 4 байта заголовка и 3 разных значения.");
            long required=rule.HeaderOffset+header.Length;
            bool footer=!String.IsNullOrWhiteSpace(rule.FooterHex),fixedSize=rule.FixedBytes>0;
            if(rule.FixedBytes<0||footer==fixedSize)throw Invalid("Выбери фиксированный размер либо завершающую сигнатуру.");
            byte[] end=footer?DecodeHex(rule.FooterHex):null;
            if(end!=null&&end.Length<4)throw Invalid("Завершающая сигнатура должна содержать хотя бы 4 байта.");
            long minimum=rule.MinBytes==0?required:rule.MinBytes;
            long maximum=rule.MaxBytes==0?(fixedSize?rule.FixedBytes:16L*1024*1024):rule.MaxBytes;
            if(minimum<required||minimum>MaximumFileBytes||maximum<minimum||maximum>MaximumFileBytes)throw Invalid("Размеры должны охватывать заголовок и не превышать 128 МиБ.");
            if(fixedSize&&(rule.FixedBytes<minimum||rule.FixedBytes>maximum))throw Invalid("Фиксированный размер вне указанных границ.");
            if(footer&&maximum<required+end.Length)throw Invalid("В максимальном размере нет места для завершающей сигнатуры.");
            return new UserSignatureRule{Id=rule.Id,Name=name,Extension=extension,HeaderHex=Hex(header),HeaderOffset=rule.HeaderOffset,FooterHex=end==null?null:Hex(end),FixedBytes=rule.FixedBytes,MinBytes=minimum,MaxBytes=maximum};
        }
        public static List<UserSignatureRule> Validate(IEnumerable<UserSignatureRule> rules)
        {
            if(rules==null)throw Invalid("Добавь правило.");var normalized=new List<UserSignatureRule>();var ids=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(var rule in rules){if(normalized.Count>=MaximumRules)throw Invalid("Не более 32 правил.");var value=Clone(rule);if(!ids.Add(value.Id))throw Invalid("ID правил не должны повторяться.");normalized.Add(value);}
            if(normalized.Count==0)throw Invalid("Добавь хотя бы одно правило.");return normalized;
        }
        static string Field(Dictionary<string,object> row,string key)
        {
            object value;if(!row.TryGetValue(key,out value)||value==null)return null;if(!(value is string))throw Invalid("Строковое поле "+key+" имеет другой тип.");return (string)value;
        }
        static long Number(Dictionary<string,object> row,string key)
        {
            object value;if(!row.TryGetValue(key,out value))return 0;
            if(!(value is int)&&!(value is long))throw Invalid("Поле "+key+" должно быть целым числом.");return Convert.ToInt64(value);
        }
        public static List<UserSignatureRule> ParseRules(string json)
        {
            if(json==null||json.Length>128*1024)throw Invalid("Файл правил слишком велик.");object parsed;
            NoDuplicateKeys(json);
            try{parsed=Json().DeserializeObject(json);}catch(ArgumentException){throw Invalid("Некорректный JSON правил.");}catch(InvalidOperationException){throw Invalid("Некорректный JSON правил.");}
            var array=parsed as object[];if(array==null||array.Length>MaximumRules)throw Invalid("Ожидается JSON-массив до 32 правил.");
            var rules=new List<UserSignatureRule>();string[] fields={"Id","Name","Extension","HeaderHex","FooterHex","HeaderOffset","FixedBytes","MaxBytes","MinBytes"};
            foreach(object element in array){var row=element as Dictionary<string,object>;if(row==null||row.Keys.Any(key=>!fields.Contains(key,StringComparer.Ordinal)))throw Invalid("Неизвестное поле или структура правила.");rules.Add(new UserSignatureRule{Id=Field(row,"Id"),Name=Field(row,"Name"),Extension=Field(row,"Extension"),HeaderHex=Field(row,"HeaderHex"),FooterHex=Field(row,"FooterHex"),HeaderOffset=Number(row,"HeaderOffset"),FixedBytes=Number(row,"FixedBytes"),MinBytes=Number(row,"MinBytes"),MaxBytes=Number(row,"MaxBytes")});}
            return Validate(rules);
        }
        static void NoDuplicateKeys(string json)
        {
            // The standard serializer silently keeps the last duplicate key.
            // Reject that ambiguity, including escaped spellings such as Id
            // versus \u0049d, before interpreting a rule's intended boundary.
            var objects=new Stack<HashSet<string>>();
            for(int at=0;at<json.Length;at++){
                char current=json[at];if(current=='{'){objects.Push(new HashSet<string>(StringComparer.Ordinal));continue;}if(current=='}'){if(objects.Count>0)objects.Pop();continue;}if(current!='"')continue;
                int start=at++;bool closed=false;for(;at<json.Length;at++){if(json[at]=='\\'){at++;continue;}if(json[at]=='"'){closed=true;break;}}
                if(!closed)return;int next=at+1;while(next<json.Length&&Char.IsWhiteSpace(json[next]))next++;
                if(next<json.Length&&json[next]==':'&&objects.Count>0){string key;try{key=Json().Deserialize<string>(json.Substring(start,at-start+1));}catch(ArgumentException){throw Invalid("Некорректный JSON правил.");}catch(InvalidOperationException){throw Invalid("Некорректный JSON правил.");}if(!objects.Peek().Add(key))throw Invalid("Поле правила повторяется: "+key);}
            }
        }
        static string FullPath(string path)
        {
            if(String.IsNullOrWhiteSpace(path)||path.StartsWith(@"\\",StringComparison.Ordinal))throw new IOException("Для поиска сигнатур нужен обычный локальный путь.");
            try{string full=Path.GetFullPath(path);if(full.Substring(Path.GetPathRoot(full).Length).IndexOf(':')>=0)throw new IOException("Потоки и устройства не поддерживаются.");return full;}
            catch(ArgumentException){throw new IOException("Недопустимый путь поиска сигнатур.");}catch(NotSupportedException){throw new IOException("Недопустимый путь поиска сигнатур.");}
        }
        static void NoLinks(string path)
        {
            if(File.Exists(path)&&(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("Файл поиска не должен быть ссылкой.");
            for(var parent=new DirectoryInfo(Directory.Exists(path)?path:Path.GetDirectoryName(path));parent!=null;parent=parent.Parent)if(parent.Exists&&(parent.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Путь поиска содержит перенаправление.");
        }
        static int[] Failure(byte[] pattern)
        {
            var failure=new int[pattern.Length];int matched=0;for(int i=1;i<pattern.Length;i++){while(matched>0&&pattern[i]!=pattern[matched])matched=failure[matched-1];if(pattern[i]==pattern[matched])matched++;failure[i]=matched;}return failure;
        }
        static void Skip(Report report,string code){int count;report.Skipped.TryGetValue(code,out count);report.Skipped[code]=count+1;}
        static long Footer(FileStream source,long start,long headerEnd,Compiled rule,Report report,CancellationToken cancel)
        {
            long from=Math.Max(headerEnd,start+rule.Rule.MinBytes-rule.Footer.Length),end=start+Math.Min(source.Length-start,rule.Rule.MaxBytes);if(from>end-rule.Footer.Length)return -1;
            source.Position=from;byte[] buffer=new byte[64*1024];int matched=0;long at=from;
            while(at<end){cancel.ThrowIfCancellationRequested();int amount=(int)Math.Min(buffer.Length,end-at);if(amount>MaximumFooterWorkBytes-report.FooterWorkBytes){report.Status="limited";throw new IOException("Поиск сигнатур достиг предела проверки завершающих байтов.");}int read=source.Read(buffer,0,amount);if(read==0)throw new IOException("Образ изменился во время чтения.");report.FooterWorkBytes+=read;
                for(int i=0;i<read;i++){while(matched>0&&buffer[i]!=rule.Footer[matched])matched=rule.Failure[matched-1];if(buffer[i]==rule.Footer[matched])matched++;if(matched==rule.Footer.Length)return at+i+1-start;}at+=read;
            }return -1;
        }
        static Result Copy(FileStream source,long offset,long count,Compiled rule,string folder,Report report,CancellationToken cancel)
        {
            string name=rule.Rule.Id+"-"+offset.ToString("D16")+"."+rule.Rule.Extension,path=Path.Combine(folder,name),partial=path+".partial";string digest;
            try{using(var output=new FileStream(partial,FileMode.CreateNew,FileAccess.Write,FileShare.Read))using(var sha=SHA256.Create()){
                source.Position=offset;byte[] block=new byte[1024*1024];long left=count;while(left>0){cancel.ThrowIfCancellationRequested();int n=source.Read(block,0,(int)Math.Min(block.Length,left));if(n==0)throw new IOException("Образ изменился во время чтения.");output.Write(block,0,n);sha.TransformBlock(block,0,n,null,0);left-=n;}sha.TransformFinalBlock(new byte[0],0,0);digest=BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();output.Flush(true);
            }cancel.ThrowIfCancellationRequested();File.Move(partial,path);}
            finally{if(File.Exists(partial))File.Delete(partial);}
            return new Result{Path="user-signatures/"+name,Sha256=digest,RuleId=rule.Rule.Id,RuleName=rule.Rule.Name,Offset=offset,HeaderOffset=rule.Rule.HeaderOffset,Bytes=count,Boundary=rule.Footer==null?"user_fixed_size":"first_matching_footer"};
        }
        public static int Recover(string image,string runDirectory,IEnumerable<UserSignatureRule> rules,CancellationToken cancel,Action<long,long> progress)
        {
            cancel.ThrowIfCancellationRequested();var normalized=Validate(rules);image=FullPath(image);runDirectory=FullPath(runDirectory);NoLinks(image);NoLinks(runDirectory);
            if(!File.Exists(image)||Directory.Exists(image))throw new IOException("Для поиска нужен существующий файл образа.");
            if(image.EndsWith(".partial",StringComparison.OrdinalIgnoreCase))throw new IOException("Незавершённый образ .partial не подходит для поиска.");
            string folder=RecoveryCatalog.SafeFile(runDirectory,"user-signatures"),reportPath=RecoveryCatalog.SafeFile(runDirectory,"user-signatures.json");
            if(String.Equals(image,reportPath,StringComparison.OrdinalIgnoreCase)||image.StartsWith(folder+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)||Directory.Exists(folder)||File.Exists(folder)||File.Exists(reportPath)||Directory.Exists(reportPath))throw new IOException("Источник пересекается с отчётами или папка уже содержит результаты сигнатур.");
            if(folder.Length+80>245)throw new IOException("Выбери более короткую папку для результатов сигнатур.");
            Directory.CreateDirectory(folder);var report=new Report{Rules=normalized};var byFirst=new Dictionary<byte,List<Compiled>>();int longest=0;
            foreach(var rule in normalized){var compiled=new Compiled{Rule=rule,Header=DecodeHex(rule.HeaderHex),Footer=String.IsNullOrEmpty(rule.FooterHex)?null:DecodeHex(rule.FooterHex)};if(compiled.Footer!=null)compiled.Failure=Failure(compiled.Footer);List<Compiled> bucket;if(!byFirst.TryGetValue(compiled.Header[0],out bucket)){bucket=new List<Compiled>();byFirst.Add(compiled.Header[0],bucket);}bucket.Add(compiled);longest=Math.Max(longest,compiled.Header.Length);}
            try{using(var source=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read)){
                report.InputBytes=source.Length;byte[] block=new byte[BlockBytes+longest-1];long at=0;
                while(at<source.Length){cancel.ThrowIfCancellationRequested();source.Position=at;int wanted=(int)Math.Min(block.Length,source.Length-at),read=0,n;while(read<wanted&&(n=source.Read(block,read,wanted-read))>0)read+=n;if(read!=wanted)throw new IOException("Образ изменился во время чтения.");int positions=(int)Math.Min(BlockBytes,source.Length-at);
                    for(int i=0;i<positions;i++){if((i&4095)==0)cancel.ThrowIfCancellationRequested();List<Compiled> possible;if(!byFirst.TryGetValue(block[i],out possible))continue;
                        foreach(var rule in possible){if(rule.Header.Length>read-i)continue;bool matches=true;for(int j=1;j<rule.Header.Length;j++){
                            if(++report.HeaderWorkBytes>MaximumHeaderWorkBytes){report.Status="limited";throw new IOException("Достигнут предел сравнений заголовков. Уточни слишком похожие сигнатуры.");}
                            if(block[i+j]!=rule.Header[j]){matches=false;break;}
                        }if(!matches)continue;
                            if(++report.Candidates>MaximumCandidates){report.Status="limited";throw new IOException("Сигнатура слишком частая: достигнут предел кандидатов. Уточни заголовок.");}long offset=at+i-rule.Rule.HeaderOffset;if(offset<0){Skip(report,"negative_start");continue;}
                            long length=rule.Footer==null?rule.Rule.FixedBytes:Footer(source,offset,at+i+rule.Header.Length,rule,report,cancel);
                            if(length<0){Skip(report,"footer_missing");continue;}if(length>source.Length-offset){Skip(report,"truncated_fixed_size");continue;}
                            if(report.Recovered>=MaximumFiles||length>MaximumOutputBytes-report.OutputBytes){report.Status="limited";throw new IOException("Поиск сигнатур достиг предела объёма результатов.");}
                            report.Files.Add(Copy(source,offset,length,rule,folder,report,cancel));report.Recovered++;report.OutputBytes+=length;
                        }
                    }at+=positions;if(progress!=null)progress(at,source.Length);
                }
            }report.Status="complete";return report.Recovered;}
            catch(OperationCanceledException){report.Status="cancelled";throw;}
            catch(IOException){if(report.Status!="limited")report.Status="incomplete";throw;}
            finally{RecoveryCore.SaveJson(reportPath,report);}
        }
    }
}
