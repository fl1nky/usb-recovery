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
                message=new ArchiveMessage{text="Сохранившаяся подпись",record_kind="telegram_media_cache",evidence_kind="backup",media_kind="photo",media_status="photo_reference_only",native_tl_body_sha256=new string('b',64)};
                details=Show(panel,message);
                var category=typeof(ArchiveSearchPanel).GetMethod("MessageCategory",BindingFlags.Static|BindingFlags.NonPublic);
                Check((string)category.Invoke(null,new object[]{message})=="Кэш Telegram","current cache gets its own category instead of backup claim");
                Check(details.Contains("Медиакэш Telegram")&&details.Contains("Байты фотографии из этой записи не извлечены")&&details.Contains("Факт удаления сообщения не установлен"),"cache origin, missing image and unknown deletion are explicit");
                Check(details.Contains(new string('b',64)),"full native body digest is available for different same-text versions");
                Check(Field<ComboBox>(panel,"attachments").Items.Count==0,"photo reference does not create an attachment action");
                message.evidence_kind="previous";
                Check((string)category.Invoke(null,new object[]{message})=="Кэш · предыдущая версия"&&Show(panel,message).Contains("предыдущем проверенном снимке кэша"),"historical cache is distinct and does not prove chat deletion");
                message.record_kind="tl_message";message.evidence_kind="backup";
                message.sources=new[]{new Dictionary<string,object>{{"source_file","owned/cache4.db"},{"source_record","media_v4(mid=41,uid=77,type=0)"},{"record_kind","telegram_media_cache"},{"native_tl_body_sha256",new string('c',64)},{"wal_db_sha256",new string('d',64)}}};
                details=Show(panel,message);
                Check((string)category.Invoke(null,new object[]{message})=="Из резервной копии","cache extra source preserves stronger primary category");
                Check(details.Contains("Дополнительный источник — медиакэш Telegram")&&details.Contains(new string('c',64))&&details.Contains(new string('d',64)),"extra cache origin and body/WAL binding remain visible");
                message.recovery_status="imported_recovery_claim";message.provenance_verification="provided_archive_metadata";
                message.archive_claims=new Dictionary<string,object>{{"recovery_status","deleted_supported_by_evidence"},{"deletion_interpretation","claimed in supplied archive"},{"deleted",true}};
                details=Show(panel,message);
                Check((string)category.Invoke(null,new object[]{message})=="Заявлено в архиве","imported deletion claim has a separate display category");
                Check(details.Contains("независимо не проверялись")&&details.Contains("проверенной находкой удалённой записи в этом анализе она не считается"),"imported claim cannot masquerade as a freshly checked deleted find");
                Check(details.Contains("deleted_supported_by_evidence")&&details.Contains("claimed in supplied archive")&&message.deleted==null,"original archive claim remains inspectable with unknown actual deletion");
                var validClaims=typeof(ArchiveSearchService).GetMethod("ValidArchiveClaims",BindingFlags.Static|BindingFlags.NonPublic);
                message.archive_claims["deletion_interpretation"]=String.Concat(System.Linq.Enumerable.Repeat(Char.ConvertFromUtf32(0x1f967),4096));
                Check((bool)validClaims.Invoke(null,new object[]{message}),"claim display boundary counts Unicode code points, including4096astral emoji");
                message.archive_claims["deletion_interpretation"]+=(Char.ConvertFromUtf32(0x1f967));
                Check(!(bool)validClaims.Invoke(null,new object[]{message}),"claim boundary rejects4097Unicode code points");
                foreach(string kind in new[]{"tl_message_caption","sqlite_deleted_caption","telegram_media_cache_caption"}){
                    raw=serializer.Serialize(new{app="Telegram",text="Отдельная подпись 🥧",record_kind=kind,text_field="media.legacy_caption",evidence_kind="backup",media_kind="photo",media_status="photo_reference_only"});
                    message=serializer.Deserialize<ArchiveMessage>(raw);details=Show(panel,message);
                    Check(message.text_field=="media.legacy_caption"&&((string)category.Invoke(null,new object[]{message})).IndexOf("подпись",StringComparison.OrdinalIgnoreCase)>=0,"caption role survives DTO and receives a caption category: "+kind);
                    Check(details.Contains("Отдельное поле той же исходной записи, не самостоятельное сообщение")&&Field<TextBox>(panel,"body").Text=="Отдельная подпись 🥧","supplemental caption stays a separate labelled field without synthesized combined text: "+kind);
                    Check(Field<ComboBox>(panel,"attachments").Items.Count==0&&message.deleted==null,"caption reference invents neither recovered image nor deletion: "+kind);
                    message.recovery_status="imported_recovery_claim";message.provenance_verification="provided_archive_metadata";
                    Check((string)category.Invoke(null,new object[]{message})=="Заявлено в архиве","imported claim label precedes every supplemental caption kind: "+kind);
                }
                message=new ArchiveMessage{app="Telegram",text="Only caption",record_kind="tl_message",text_field="media.legacy_caption",evidence_kind="backup"};
                Check((string)category.Invoke(null,new object[]{message})=="Подпись к фото"&&!Show(panel,message).Contains("не самостоятельное сообщение"),"primary legacy-caption fallback identifies its field without claiming another supplemental record");
                message.record_kind="tl_message_caption";message.text_field=null;
                Check(Show(panel,message).Contains("Поле текста: неизвестно"),"unknown field remains unknown instead of being inferred from caption record kind");
                message=new ArchiveMessage{app="Telegram",text="Original",record_kind="tl_message",text_field="message",evidence_kind="backup",
                    sources=new[]{new Dictionary<string,object>{{"source_file","owned/cache4.db"},{"record_kind","telegram_media_cache_caption"},{"text_field","media.legacy_caption"}}},
                    residual_sources=new[]{new Dictionary<string,object>{{"physical_source","wal"},{"sqlite_page",2},{"physical_byte_offset",4096},{"text_field","media.legacy_caption"}}}};
                details=Show(panel,message);
                Check(details.Contains("Поле текста источника: подпись к фото")&&details.Contains("Поле текста остатка: подпись к фото"),"additional and residual source field roles are visible");
                Check(details.Contains("Дополнительный источник — медиакэш Telegram")&&(string)category.Invoke(null,new object[]{message})=="Из резервной копии","supplemental cache origin does not replace a stronger main record category");
                var validFields=typeof(ArchiveSearchService).GetMethod("ValidTextFields",BindingFlags.Static|BindingFlags.NonPublic);
                Check((bool)validFields.Invoke(null,new object[]{message}),"strict known roles accepted in top-level and both provenance arrays");
                message.text_field="legacy_caption";
                Check(!(bool)validFields.Invoke(null,new object[]{message}),"unsupported top-level role is rejected at helper response boundary");
                message.text_field="message";message.sources[0]["text_field"]=true;
                Check(!(bool)validFields.Invoke(null,new object[]{message}),"boolean cannot become a source field role");
                message.sources[0]["text_field"]=null;message.residual_sources[0]["text_field"]="message.text";
                Check(!(bool)validFields.Invoke(null,new object[]{message}),"unknown residual role cannot be treated as a known field");
                message=new ArchiveMessage{record_kind="tl_message_caption",text_field="media.legacy_caption",evidence_kind="backup",application_confirmed=true,
                    rollback_journal_sha256=new string('a',64),rollback_page_map="provenance/rollback/"+new string('a',64)+".json",rollback_page_map_sha256=new string('b',64),
                    rollback_hot_state="unknown",rollback_current_state_confirmed=false,rollback_content_authenticity_verified=false,rollback_checksum_kind="sqlite_sparse_32bit",
                    rollback_initial_pages=3,rollback_parse_status="complete",rollback_proof="all_pages_from_validated_rollback_journal",rollback_snapshot_sha256=new string('c',64)};
                var validRollback=typeof(ArchiveSearchService).GetMethod("ValidRollback",BindingFlags.Static|BindingFlags.NonPublic);
                Check((bool)validRollback.Invoke(null,new object[]{message}),"complete rollback permits a confirmed supplemental TL caption with exact role");
                message.text_field="message";
                Check(!(bool)validRollback.Invoke(null,new object[]{message}),"supplemental rollback caption cannot claim the main text role");
                message.text_field="media.legacy_caption";message.application_confirmed=false;
                Check(!(bool)validRollback.Invoke(null,new object[]{message}),"unconfirmed caption cannot retain complete rollback proof");
                message.application_confirmed=true;message.record_kind="telegram_media_cache_caption";
                Check(!(bool)validRollback.Invoke(null,new object[]{message}),"rollback allowance does not expand to cache-caption records");
                message.record_kind="tl_message";message.text_field=null;
                Check((bool)validRollback.Invoke(null,new object[]{message}),"legacy complete TL rollback record without a field label remains valid");
                string summary=TelegramAnalysisService.Summary(new HelperResult{Status="complete",Messages=2,HistoryMessages=2,ReadableSources=1});
                Check(summary.Contains("Найдено записей Telegram: 2")&&!summary.Contains("Найдено сообщений"),"summary counts records rather than inventing independent chat-message count");
            }
            Console.WriteLine("PASS TelegramRecoveryProvenanceUi: "+checks+" checks; real DTO decoding and controlled WinForms presentation of WAL-prefix uncertainty and mapped overflow candidates. Owned synthetic metadata only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
