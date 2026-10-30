using System;
using System.Collections.Generic;
using System.Drawing;
using System.Reflection;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using UsbRecovery;

public static class TelegramRecoveryProvenanceUiTests
{
    static int checks;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static T Field<T>(object owner,string name) where T:class{return (T)owner.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(owner);}
    static string Show(ArchiveSearchPanel panel,ArchiveMessage message)
    {
        var grid=Field<DataGridView>(panel,"grid");grid.Rows.Clear();int row=grid.Rows.Add();grid.Rows[row].Tag=message;grid.Rows[row].Selected=true;grid.CurrentCell=grid.Rows[row].Cells[0];
        typeof(ArchiveSearchPanel).GetMethod("ShowMessage",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(panel,null);
        return Field<TextBox>(panel,"provenance").Text;
    }
    [STAThread] public static int Main()
    {
        try{
            Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
            var serializer=new JavaScriptSerializer();
            using(var form=new Form{ClientSize=new Size(960,740),ShowInTaskbar=false,Location=new Point(-20000,-20000),StartPosition=FormStartPosition.Manual})
            using(var panel=new ArchiveSearchPanel()){
                form.Controls.Add(panel);form.Show();Application.DoEvents();
                string raw=serializer.Serialize(new{text="recipe from committed WAL",source_file="owned/cache4.db",source_record="messages_v2(mid=3)",
                    record_kind="tl_message",evidence_kind="backup",deleted=(bool?)null,wal_proof="all_pages_from_validated_wal",wal_commit_frame=11,
                    wal_tail_reason="TRUNCATED_FRAME",wal_validated_prefix_bytes=45232L,wal_snapshot_latest_known_commit=true,wal_current_state_confirmed=false});
                var message=serializer.Deserialize<ArchiveMessage>(raw);
                Check(message.wal_snapshot_latest_known_commit==true&&message.wal_current_state_confirmed==false,"typed WAL booleans survive worker JSON");
                Check(Convert.ToInt64(message.wal_validated_prefix_bytes)==45232,"prefix byte count survives JSON");
                string details=Show(panel,message);
                Check(details.Contains("Последний полностью проверенный коммит WAL"),"latest known commit is identified");
                Check(!details.Contains("Предыдущий зафиксированный снимок SQLite"),"latest validated prefix is not labelled a known older snapshot");
                Check(details.Contains("Текущее состояние переписки не подтверждено")&&details.Contains("45232"),"damaged tail uncertainty and validated extent remain visible");
                Check(details.Contains("Факт удаления сообщения не установлен")&&message.deleted==null,"unknown deletion remains explicit");
                Check(Field<TextBox>(panel,"body").Text==message.text,"recovered text remains viewable");
                message.wal_snapshot_latest_known_commit=null;message.wal_current_state_confirmed=null;
                Check(Show(panel,message).Contains("Предыдущий зафиксированный снимок SQLite"),"ordinary historical WAL label stays intact");
                message.sources=new[]{new Dictionary<string,object>{{"wal_current_state_confirmed",false},{"wal_validated_prefix_bytes",600L},{"wal_tail_reason","torn_frame"}}};
                details=Show(panel,message);Check(details.Contains("Для одного из источников")&&details.Contains("Текущее состояние переписки не подтверждено")&&details.Contains("torn_frame"),"deduplicated additional origin retains its uncertainty warning");
                message.residual_sources=message.sources;message.sources=null;
                Check(Show(panel,message).Contains("Текущее состояние переписки не подтверждено"),"residual origin retains uncertainty warning");
                message.residual_sources=new[]{new Dictionary<string,object>{{"wal_current_state_confirmed","false"}}};
                Check(!Show(panel,message).Contains("Текущее состояние переписки не подтверждено"),"malformed string flag is not promoted to a known false boolean");
                message.residual_sources=null;Check(!Show(panel,message).Contains("Текущее состояние переписки не подтверждено"),"unknown flags do not invent uncertainty evidence");
                var ranges=new[]{new Dictionary<string,object>{{"logical_offset",0L},{"bytes",100L},{"sqlite_page",2L},{"physical_source","wal"},{"physical_byte_offset",4096L},{"wal_frame",1L}},
                    new Dictionary<string,object>{{"logical_offset",100L},{"bytes",500L},{"sqlite_page",9L},{"physical_source","db"},{"physical_byte_offset",4294967000L},{"wal_frame",null}}};
                raw=serializer.Serialize(new{text="long recovered recipe",source_file="owned/cache4.db",source_record="messages_v2(mid=3)",deleted=(bool?)null,
                    sqlite_payload_length=600L,sqlite_payload_sha256=new string('a',64),sqlite_payload_ranges=ranges,sqlite_overflow_pages=new long[]{9},sqlite_overflow_chain_verified=true});
                message=serializer.Deserialize<ArchiveMessage>(raw);
                Check(message.sqlite_payload_ranges.Length==2&&message.sqlite_overflow_pages[0]==9,"all physical source ranges survive DTO");
                Check(Convert.ToInt64(message.sqlite_payload_ranges[1]["physical_byte_offset"])==4294967000L,"source offsets retain 64-bit precision");
                details=Show(panel,message);
                Check(details.Contains("цепочки свободных страниц")&&details.Contains("Диапазонов: 2")&&details.Contains("600"),"assembled overflow origin is visible");
                Check(details.Contains("не подтверждает первоначальное содержание")&&details.Contains("JSON архива"),"structural uncertainty and complete map location are visible");
                Check(details.Contains(new string('a',64))&&message.deleted==null,"payload digest and unknown deletion are preserved");
            }
            Console.WriteLine("PASS TelegramRecoveryProvenanceUi: "+checks+" checks; real DTO decoding and controlled WinForms presentation of WAL-prefix uncertainty and mapped overflow candidates. Owned synthetic metadata only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
