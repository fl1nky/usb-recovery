using System;
using System.Collections.Generic;
using System.Text;
using System.Web.Script.Serialization;

// A deliberately isolated worker fixture: reads only the redirected test request.
public static class TelegramUiProtocolFixture
{
    public static int Main(string[] args)
    {
        try {
            Console.InputEncoding = Console.OutputEncoding = new UTF8Encoding(false);
            var json = new JavaScriptSerializer();
            var request = json.Deserialize<Dictionary<string, object>>(Console.ReadLine());
            if (args.Length != 0 || Convert.ToString(request["operation"]) != "search" || Convert.ToString(request["app"]) != "Telegram" || Convert.ToString(request["sort"]) != "latest") return 2;
            if (Convert.ToString(request["query"]) == "regex-protocol" && Convert.ToString(request["query_mode"]) != "regex") return 4;
            bool empty = Convert.ToString(request["query"]) == "ничего";
            var records = new List<object>();
            if (Convert.ToString(request["query"]) == "уведомление") records.Add(new { app = "Telegram", chat_id = "tg-synthetic-chat", sender_name = (string)null, message_id = "tg-synthetic-3", timestamp = (string)null, text = "Сохранившийся фрагмент уведомления", source_file = "cache4.db", source_record = "unread_push_messages/3", evidence_kind = "backup", record_kind = "notification", completeness = "saved_notification_preview", attachments = new string[0] });
            else if (Convert.ToString(request["query"]) == "bad-app") records.Add(new { app = "WhatsApp", text = "This must never be displayed", evidence_kind = "export" });
            else if (!empty) records.Add(new { app = "Telegram", chat_id = "tg-synthetic-chat", sender_name = "Тестовый автор", message_id = "tg-synthetic-2", timestamp = "2026-10-13T10:00:00+03:00", text = "Ключевое слово: рецепт пирожков", source_file = "synthetic-export.json", source_record = "2", evidence_kind = "export", attachments = new string[0] });
            Console.WriteLine(json.Serialize(new { protocol = 1, type = "result", status = "complete", code = "COMPLETE", archive = Convert.ToString(request["archive"]), total = records.Count, offset = Convert.ToInt64(request["offset"]), limit = 100, records = records, warnings = new string[0] }));
            return 0;
        } catch { return 3; }
    }
}
