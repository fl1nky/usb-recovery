using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using UsbRecovery;

public static class TelegramParserTests
{
        private static int checks = 0;

        private static void Check(bool condition, string description)
        {
            if (!condition)
            {
                throw new Exception("Check failed: " + description);
            }
            checks++;
        }

        public static int Main(string[] args)
        {
            Console.WriteLine("Running TelegramParserTests...");
            string work = Path.Combine(Path.GetTempPath(), "tg-parser-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(work);

            try
            {
                TestTdfPayloadRoundtrip();
                TestTdfPayloadIntegrityRejection();
                TestTdataDirectoryInspection(work);
                TestSqliteMessageCarving();
                TestTdfStreamCarving();
                TestForensicTimelineIntegration();
                TestTopLevelAnalyze(work);
                TestFragmentExport();

                Console.WriteLine("PASS TelegramParserTests: {0} checks passed; TDF$ containers, MD5 verification, tdata inspection, SQLite message carving, and forensic timeline integration verified.", checks);
                return 0;
            }
            finally
            {
                try
                {
                    if (Directory.Exists(work))
                    {
                        Directory.Delete(work, true);
                    }
                }
                catch { }
            }
        }

        private static void TestTdfPayloadRoundtrip()
        {
            byte[] body = Encoding.UTF8.GetBytes("{\"version\": 5002, \"user\": \"forensic_examiner\"}");
            uint version = 1004;
            byte[] container = TelegramParser.CreateTdfContainer(body, version);

            Check(container != null, "TDF container created");
            Check(container.Length == body.Length + 24, "Container length matches body + 24 (8 header + 16 MD5)");
            Check(container[0] == 0x54 && container[1] == 0x44 && container[2] == 0x46 && container[3] == 0x24, "TDF$ magic bytes present");

            byte[] extractedBody;
            uint extractedVer;
            bool ok = TelegramParser.TryParseTdfPayload(container, out extractedBody, out extractedVer);

            Check(ok, "TryParseTdfPayload succeeded on valid container");
            Check(extractedVer == version, "Extracted version matches original 1004");
            Check(extractedBody != null && extractedBody.Length == body.Length, "Extracted body length matches");
            Check(Encoding.UTF8.GetString(extractedBody) == Encoding.UTF8.GetString(body), "Extracted body payload exact match");
        }

        private static void TestTdfPayloadIntegrityRejection()
        {
            byte[] body = Encoding.UTF8.GetBytes("Tamper-proof payload check");
            byte[] container = TelegramParser.CreateTdfContainer(body, 2001);

            byte[] outBody;
            uint outVer;

            // 1. Corrupt payload body byte
            byte[] tamperedBody = (byte[])container.Clone();
            tamperedBody[10] ^= 0xFF;
            Check(!TelegramParser.TryParseTdfPayload(tamperedBody, out outBody, out outVer), "Tampered body byte rejected by MD5 digest check");

            // 2. Corrupt MD5 trailer byte
            byte[] tamperedTrailer = (byte[])container.Clone();
            tamperedTrailer[tamperedTrailer.Length - 1] ^= 0x01;
            Check(!TelegramParser.TryParseTdfPayload(tamperedTrailer, out outBody, out outVer), "Tampered MD5 trailer rejected");

            // 3. Corrupt magic bytes
            byte[] badMagic = (byte[])container.Clone();
            badMagic[0] = 0x00;
            Check(!TelegramParser.TryParseTdfPayload(badMagic, out outBody, out outVer), "Corrupt magic rejected");

            // 4. Truncated container (< 28 bytes)
            byte[] tooShort = new byte[20];
            Check(!TelegramParser.TryParseTdfPayload(tooShort, out outBody, out outVer), "Short buffer (< 28 bytes) rejected");

            // 5. Null container
            Check(!TelegramParser.TryParseTdfPayload(null, out outBody, out outVer), "Null buffer rejected");
        }

        private static void TestTdataDirectoryInspection(string root)
        {
            string tdata = Path.Combine(root, "tdata_sample");
            Directory.CreateDirectory(tdata);

            byte[] keyDatasTdf = TelegramParser.CreateTdfContainer(new byte[350], 1);
            File.WriteAllBytes(Path.Combine(tdata, "key_datas"), keyDatasTdf);
            File.WriteAllBytes(Path.Combine(tdata, "D877F783D5D3EF8C"), new byte[32]);
            File.WriteAllBytes(Path.Combine(tdata, "settingss"), new byte[16]);
            File.WriteAllBytes(Path.Combine(tdata, "maps"), new byte[16]);

            string userDir = Path.Combine(tdata, "user_data");
            Directory.CreateDirectory(userDir);
            File.WriteAllBytes(Path.Combine(userDir, "passcode.bin"), new byte[32]);

            string mediaDir = Path.Combine(tdata, "media_cache");
            Directory.CreateDirectory(mediaDir);
            File.WriteAllBytes(Path.Combine(mediaDir, "f_0001"), new byte[256]);

            // Embed 2 valid TDF containers
            byte[] tdf1 = TelegramParser.CreateTdfContainer(Encoding.UTF8.GetBytes("key_payload"), 1);
            File.WriteAllBytes(Path.Combine(tdata, "data.tdf"), tdf1);
            byte[] tdf2 = TelegramParser.CreateTdfContainer(Encoding.UTF8.GetBytes("map_payload"), 2);
            File.WriteAllBytes(Path.Combine(tdata, "map.tdf"), tdf2);

            TelegramDesktopProfile profile = TelegramParser.InspectTdata(tdata);

            Check(profile != null, "Tdata inspection profile returned");
            Check(profile.HasKeyData, "Profile HasKeyData is true");
            Check(!profile.HasPasscode.HasValue, "Passcode cannot be inferred from key file length");
            Check(profile.AccountsCount >= 1, "Profile AccountsCount >= 1");
            Check(profile.MediaFilesCount == 1, "Profile MediaFilesCount matches 1");
            Check(profile.TotalTdfFiles >= 2, "Profile TotalTdfFiles >= 2");
            Check(profile.DiscoveredFiles.Contains("key_datas"), "Discovered files contains key_datas");
            Check(profile.DiscoveredFiles.Contains("settingss"), "Discovered files contains settingss");
        }

        private static void TestSqliteMessageCarving()
        {
            // Build synthetic SQLite database with Telegram message row
            byte[] db = CreateSyntheticDatabase(4096, 2);

            // Columns: id (int), peer_id (int), timestamp (int), message (text), is_out (int)
            long messageId = 7001;
            long peerId = 987654321;
            long timestamp = 1700000000L; // Sun, 14 Nov 2023 UTC
            string text = "Secret recovery phrase: alpha bravo charlie";
            long isOut = 1;

            byte[] payload = BuildMessageRecordPayload(messageId, peerId, timestamp, text, isOut);
            byte[] cell = BuildTableCell(1, payload);

            // Inject cell into B-Tree leaf page 2 at offset 200
            int page2Offset = 4096;
            db[page2Offset] = 0x0D; // Leaf table B-tree page flag
            db[page2Offset + 1] = 0; db[page2Offset + 2] = 0; // freeblock offset 0
            db[page2Offset + 3] = 0; db[page2Offset + 4] = 1; // 1 cell
            db[page2Offset + 5] = (byte)(200 >> 8); db[page2Offset + 6] = (byte)(200 & 0xFF); // cell content area offset
            db[page2Offset + 7] = 0; // fragmented free bytes

            // Cell pointer array at offset 8
            db[page2Offset + 8] = (byte)(200 >> 8);
            db[page2Offset + 9] = (byte)(200 & 0xFF);

            // Copy cell into offset 200
            Buffer.BlockCopy(cell, 0, db, page2Offset + 200, cell.Length);

            using (var ms = new MemoryStream(db))
            {
                List<TelegramTextFragment> records = TelegramParser.CarveDatabase(ms);

                Check(records != null && records.Count > 0, "CarveDatabase found unattributed text");
                TelegramTextFragment rec = records.Find(f => f.Text == text && f.SourceOrigin == "ActiveCell");
                Check(rec != null, "Active record text located among unclassified fragments");
                Check(rec.Text == text, "Message text matches: " + rec.Text);
                Check(rec.EvidenceKind == "UnattributedSqliteText", "No Telegram attribution inferred from integer ranges");
                Check(rec.PageNumber == 2 && rec.Offset == 4296, "Exact page and cell offset retained");
                Check(rec.ColumnIndex == 3 && rec.SqliteRowId == 1, "SQLite coordinates retained, not treated as message identifiers");
                Check(rec.SourcePath == null, "Anonymous stream has no invented path");
            }
        }

        private static void TestTdfStreamCarving()
        {
            byte[] container1 = TelegramParser.CreateTdfContainer(Encoding.UTF8.GetBytes("CarvedContainerNumberOne"), 10);
            byte[] container2 = TelegramParser.CreateTdfContainer(Encoding.UTF8.GetBytes("CarvedContainerNumberTwoSecond"), 20);

            MemoryStream ms = new MemoryStream();
            // 512 bytes padding
            byte[] pad = new byte[512];
            for (int i = 0; i < pad.Length; i++) pad[i] = 0xCC;
            ms.Write(pad, 0, pad.Length);

            // Write container 1
            ms.Write(container1, 0, container1.Length);

            // Write 1024 bytes noise
            byte[] noise = new byte[1024];
            for (int i = 0; i < noise.Length; i++) noise[i] = 0xAA;
            ms.Write(noise, 0, noise.Length);

            // Write container 2
            ms.Write(container2, 0, container2.Length);
            ms.Position = 0;

            List<byte[]> carved = TelegramParser.CarveTdfContainers(ms);

            Check(carved != null && carved.Count == 2, "CarveTdfContainers carved exactly 2 containers");

            byte[] b1; uint v1;
            Check(TelegramParser.TryParseTdfPayload(carved[0], out b1, out v1), "Carved container 1 is valid");
            Check(v1 == 10 && Encoding.UTF8.GetString(b1) == "CarvedContainerNumberOne", "Container 1 payload exact match");

            byte[] b2; uint v2;
            Check(TelegramParser.TryParseTdfPayload(carved[1], out b2, out v2), "Carved container 2 is valid");
            Check(v2 == 20 && Encoding.UTF8.GetString(b2) == "CarvedContainerNumberTwoSecond", "Container 2 payload exact match");
        }

        private static void TestForensicTimelineIntegration()
        {
            var timeline = new ForensicTimeline();
            var messages = new List<TelegramMessageRecord>
            {
                new TelegramMessageRecord
                {
                    MessageId = 8801,
                    PeerId = 445566,
                    PeerType = "User",
                    TimestampUtc = new DateTime(2026, 11, 21, 15, 30, 0, DateTimeKind.Utc),
                    IsOut = true,
                    Text = "Wire transfer authorization approved",
                    IsDeletedOrCarved = true,
                    SourceOrigin = "FreelistSlack",
                    Offset = 16384
                }
            };

            timeline.AddTelegramMessages(messages);
            Check(timeline.Events.Count == 1, "Timeline event added from Telegram message");

            var ev = timeline.Events[0];
            Check(ev.Source == "Telegram", "Timeline event source is Telegram");
            Check(ev.Action == "CARVED_MESSAGE_CANDIDATE (Telegram; deletion unconfirmed)", "Carving does not prove deletion");
            Check(ev.TargetPath == "User:445566", "Timeline TargetPath contains User:445566");
            Check(ev.Description.Contains("FreelistSlack"), "Timeline description highlights FreelistSlack origin");
            Check(ev.Description.Contains("Wire transfer authorization approved"), "Timeline description contains text");

            // Verify CSV export format
            using (var ms = new MemoryStream())
            {
                timeline.ExportToCsv(ms);
                string csv = Encoding.UTF8.GetString(ms.ToArray());
                Check(csv.Contains("Wire transfer authorization approved"), "CSV contains message text");
                Check(csv.Contains("Telegram"), "CSV contains Telegram source");
            }
        }

        private static void TestTopLevelAnalyze(string root)
        {
            string tgRoot = Path.Combine(root, "top_level_tg");
            Directory.CreateDirectory(tgRoot);

            // Subdir tdata
            string tdata = Path.Combine(tgRoot, "tdata");
            Directory.CreateDirectory(tdata);
            File.WriteAllBytes(Path.Combine(tdata, "key_datas"), new byte[64]);
            byte[] tdf = TelegramParser.CreateTdfContainer(Encoding.UTF8.GetBytes("tdata_tdf"), 1);
            File.WriteAllBytes(Path.Combine(tdata, "settings.tdf"), tdf);

            // Subdir database
            string dbFile = Path.Combine(tgRoot, "cache4.db");
            byte[] db = CreateSyntheticDatabase(4096, 2);
            byte[] payload = BuildMessageRecordPayload(9001, 112233, 1700000000L, "Top level report check", 0);
            byte[] cell = BuildTableCell(1, payload);
            Buffer.BlockCopy(cell, 0, db, 4096 + 200, cell.Length);
            db[4096] = 0x0D; // leaf table
            db[4096 + 3] = 0; db[4096 + 4] = 1; // 1 cell
            db[4096 + 5] = (byte)(200 >> 8); db[4096 + 6] = (byte)(200 & 0xFF);
            db[4096 + 8] = (byte)(200 >> 8); db[4096 + 9] = (byte)(200 & 0xFF);
            File.WriteAllBytes(dbFile, db);

            TelegramForensicReport report = TelegramParser.Analyze(tgRoot);

            Check(report != null, "Report generated");
            Check(report.DesktopProfiles.Count == 1, "Report found 1 desktop profile");
            Check(report.Messages.Count == 0, "Unknown schema cannot produce messages");
            Check(report.ActiveMessagesCount == 0 && report.CarvedMessagesCount == 0, "Fragments do not inflate message counts");
            Check(report.TextFragments.Count >= 1, "Report keeps unattributed fragments separately");
            Check(report.TotalTdfContainersFound >= 1, "Report found TDF containers");
            Check(report.TextFragments.Exists(f => f.Text == "Top level report check"), "Fragment text preserved");
            Check(report.TextFragments[0].SourcePath == dbFile, "Directory scan retains exact database path");
            var direct = TelegramParser.Analyze(dbFile);
            Check(direct.Messages.Count == 0 && direct.TextFragments[0].SourcePath == dbFile, "Direct scan also retains provenance and uncertainty");
            var timeline = new ForensicTimeline();
            timeline.AddTelegramMessages(report.Messages);
            Check(timeline.Events.Count == 0, "Fragments cannot create dated Telegram timeline events");
        }

        private static void TestFragmentExport()
        {
            var fragments = new List<TelegramTextFragment> {
                new TelegramTextFragment { Text = "Привет, \"мир\"\n<script>test</script>", SourcePath = "a.db", SourceOrigin = "Freeblock", Offset = 42, PageNumber = 1, ColumnIndex = 3 },
                new TelegramTextFragment { Text = "=1+1", SourcePath = "b.db", SourceOrigin = "ActiveCell", Offset = 42, PageNumber = 1, ColumnIndex = 3 }
            };
            var writer = new StringWriter();
            TelegramEvidenceExport.WriteFragmentsCsv(writer, fragments);
            string csv = writer.ToString();
            Check(csv.Contains("Привет, \"\"мир\"\"\n<script>test</script>"), "CSV quotes Unicode and multiline evidence without truncation");
            Check(csv.Contains("\"'=1+1\""), "Spreadsheet formula is neutralized");
            Check(csv.Contains("\"a.db\"") && csv.Contains("\"b.db\""), "Different sources with equal offsets are retained");
            Check(!csv.Contains("MessageId") && !csv.Contains("IsDeleted"), "Fragment export does not invent message fields");
            Check(fragments[1].Text == "=1+1", "Presentation protection does not mutate evidence");
        }

        // ---------------------------------------------------------------------
        // Synthetic SQLite Helpers
        // ---------------------------------------------------------------------
        private static byte[] CreateSyntheticDatabase(int pageSize, int pageCount)
        {
            byte[] db = new byte[pageSize * pageCount];
            Encoding.ASCII.GetBytes("SQLite format 3\0").CopyTo(db, 0);
            db[16] = (byte)(pageSize >> 8);
            db[17] = (byte)(pageSize & 0xFF);
            db[18] = 1; db[19] = 1; db[20] = 0;
            db[21] = 64; db[22] = 32; db[23] = 32;
            WriteUInt32BE(db, 28, (uint)pageCount);
            WriteUInt32BE(db, 56, 1); // UTF-8
            return db;
        }

        private static byte[] BuildMessageRecordPayload(long id, long peerId, long timestamp, string text, long isOut)
        {
            byte[] textBytes = Encoding.UTF8.GetBytes(text);
            long textSerialType = 13 + (textBytes.Length * 2);

            long[] serialTypes = new long[] { 4, 4, 4, textSerialType, 1 };
            object[] values = new object[] { id, peerId, timestamp, textBytes, (byte)isOut };

            MemoryStream hStream = new MemoryStream();
            for (int i = 0; i < serialTypes.Length; i++)
            {
                byte[] stVarint = EncodeVarint(serialTypes[i]);
                hStream.Write(stVarint, 0, stVarint.Length);
            }
            byte[] stBytes = hStream.ToArray();

            int hLen = stBytes.Length + 1;
            byte[] hLenVarint = EncodeVarint(hLen);
            if (hLenVarint.Length + stBytes.Length != hLen)
            {
                hLen = hLenVarint.Length + stBytes.Length;
                hLenVarint = EncodeVarint(hLen);
            }

            MemoryStream payload = new MemoryStream();
            payload.Write(hLenVarint, 0, hLenVarint.Length);
            payload.Write(stBytes, 0, stBytes.Length);

            WriteInt32BE(payload, (int)id);
            WriteInt32BE(payload, (int)peerId);
            WriteInt32BE(payload, (int)timestamp);
            payload.Write(textBytes, 0, textBytes.Length);
            payload.WriteByte((byte)isOut);

            return payload.ToArray();
        }

        private static byte[] BuildTableCell(long rowId, byte[] payload)
        {
            byte[] pLenVarint = EncodeVarint(payload.Length);
            byte[] rowIdVarint = EncodeVarint(rowId);

            byte[] cell = new byte[pLenVarint.Length + rowIdVarint.Length + payload.Length];
            Buffer.BlockCopy(pLenVarint, 0, cell, 0, pLenVarint.Length);
            Buffer.BlockCopy(rowIdVarint, 0, cell, pLenVarint.Length, rowIdVarint.Length);
            Buffer.BlockCopy(payload, 0, cell, pLenVarint.Length + rowIdVarint.Length, payload.Length);
            return cell;
        }

        private static byte[] EncodeVarint(long value)
        {
            if (value < 0) value = 0;
            List<byte> bytes = new List<byte>();
            bytes.Add((byte)(value & 0x7F));
            value >>= 7;
            while (value > 0)
            {
                bytes.Insert(0, (byte)((value & 0x7F) | 0x80));
                value >>= 7;
            }
            return bytes.ToArray();
        }

        private static void WriteUInt32BE(byte[] buffer, int offset, uint value)
        {
            buffer[offset] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)(value & 0xFF);
        }

        private static void WriteInt32BE(MemoryStream ms, int value)
        {
            ms.WriteByte((byte)(value >> 24));
            ms.WriteByte((byte)(value >> 16));
            ms.WriteByte((byte)(value >> 8));
            ms.WriteByte((byte)(value & 0xFF));
        }
    }
