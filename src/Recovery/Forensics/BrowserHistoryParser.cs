using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace UsbRecovery
{
    public enum BrowserType
    {
        Unknown = 0,
        Chromium = 1,
        Firefox = 2
    }

    public enum BrowserVisitType
    {
        Unknown = 0,
        Link = 1,
        Typed = 2,
        Bookmark = 3,
        Subframe = 4,
        Embed = 5,
        RedirectPermanent = 6,
        RedirectTemporary = 7,
        Download = 8,
        Reload = 9,
        FormSubmit = 10,
        Other = 11
    }

    public sealed class BrowserVisitDetail
    {
        public DateTime VisitTimeUtc { get; set; }
        public long RawVisitTime { get; set; }
        public BrowserVisitType VisitType { get; set; }
        public int TransitionCode { get; set; }
        public int DurationSeconds { get; set; }
        public long FromVisitId { get; set; }

        public BrowserVisitDetail()
        {
            VisitType = BrowserVisitType.Unknown;
        }
    }

    public sealed class BrowserHistoryRecord
    {
        public BrowserType Browser { get; set; }
        public string Url { get; set; }
        public string Title { get; set; }
        public int VisitCount { get; set; }
        public int TypedCount { get; set; }
        public DateTime LastVisitUtc { get; set; }
        public long RawTimestamp { get; set; }
        public bool Hidden { get; set; }
        public string Origin { get; set; }
        public long RecordId { get; set; }
        public List<BrowserVisitDetail> Visits { get; set; }

        public BrowserHistoryRecord()
        {
            Browser = BrowserType.Unknown;
            Url = String.Empty;
            Title = String.Empty;
            Origin = String.Empty;
            Visits = new List<BrowserVisitDetail>();
        }
    }

    public sealed class BrowserCacheRecord
    {
        public BrowserType Browser { get; set; }
        public string KeyUrl { get; set; }
        public int HttpStatusCode { get; set; }
        public string HttpStatusText { get; set; }
        public string ContentType { get; set; }
        public long DataSize { get; set; }
        public DateTime FetchTimeUtc { get; set; }
        public DateTime? ExpiryTimeUtc { get; set; }
        public int FetchCount { get; set; }
        public string SourcePath { get; set; }
        public Dictionary<string, string> ResponseHeaders { get; set; }

        public BrowserCacheRecord()
        {
            Browser = BrowserType.Unknown;
            KeyUrl = String.Empty;
            HttpStatusText = String.Empty;
            ContentType = String.Empty;
            SourcePath = String.Empty;
            ResponseHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    public static class BrowserTimestampConverter
    {
        public static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        public static readonly DateTime WebKitEpoch = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private const long MaxSafeWebKitMicroseconds = 265046774399999999L;
        private const long MaxSafePrTimeMicroseconds = 253402300799999999L;

        public static DateTime WebKitTimeToUtc(long webKitMicroseconds)
        {
            if (webKitMicroseconds <= 0)
            {
                return DateTime.MinValue;
            }
            if (webKitMicroseconds > MaxSafeWebKitMicroseconds)
            {
                return DateTime.MaxValue;
            }

            try
            {
                long ticks = webKitMicroseconds * 10;
                return DateTime.FromFileTimeUtc(ticks);
            }
            catch (ArgumentOutOfRangeException)
            {
                return DateTime.MaxValue;
            }
        }

        public static long UtcToWebKitTime(DateTime utc)
        {
            if (utc <= WebKitEpoch) return 0;
            return utc.ToFileTimeUtc() / 10;
        }

        public static DateTime PrTimeToUtc(long prTimeMicroseconds)
        {
            if (prTimeMicroseconds <= 0)
            {
                return DateTime.MinValue;
            }
            if (prTimeMicroseconds > MaxSafePrTimeMicroseconds)
            {
                return DateTime.MaxValue;
            }

            try
            {
                long ticks = prTimeMicroseconds * 10;
                return UnixEpoch.AddTicks(ticks);
            }
            catch (ArgumentOutOfRangeException)
            {
                return DateTime.MaxValue;
            }
        }

        public static long UtcToPrTime(DateTime utc)
        {
            if (utc <= UnixEpoch) return 0;
            return (utc.Ticks - UnixEpoch.Ticks) / 10;
        }
    }

    public static class BrowserHistoryParser
    {
        // -------------------------------------------------------------------------
        // Chromium History Parsing
        // -------------------------------------------------------------------------
        public static List<BrowserHistoryRecord> ParseChromium(string dbPath)
        {
            if (dbPath == null) throw new ArgumentNullException("dbPath");
            if (!File.Exists(dbPath)) throw new FileNotFoundException("Database not found", dbPath);

            using (FileStream fs = new FileStream(dbPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                return ParseChromium(fs);
            }
        }

        public static List<BrowserHistoryRecord> ParseChromium(Stream stream)
        {
            List<CarvedSqliteRecord> carvedRecords = SqliteCarver.CarveDatabase(stream);
            return InterpretChromiumRecords(carvedRecords);
        }

        public static List<BrowserHistoryRecord> InterpretChromiumRecords(IEnumerable<CarvedSqliteRecord> records)
        {
            List<BrowserHistoryRecord> results = new List<BrowserHistoryRecord>();
            if (records == null) return results;

            Dictionary<long, BrowserHistoryRecord> urlMap = new Dictionary<long, BrowserHistoryRecord>();
            List<CarvedVisitCandidate> visitCandidates = new List<CarvedVisitCandidate>();

            foreach (CarvedSqliteRecord rec in records)
            {
                if (rec == null || rec.Columns == null || rec.Columns.Count == 0) continue;

                if (IsChromiumUrlRecord(rec))
                {
                    BrowserHistoryRecord item = ExtractChromiumUrlRecord(rec);
                    if (item != null && !String.IsNullOrEmpty(item.Url))
                    {
                        if (item.RecordId > 0 && !urlMap.ContainsKey(item.RecordId))
                        {
                            urlMap[item.RecordId] = item;
                        }
                        else
                        {
                            results.Add(item);
                        }
                    }
                }
                else if (IsChromiumVisitRecord(rec))
                {
                    CarvedVisitCandidate visit = ExtractChromiumVisitRecord(rec);
                    if (visit != null)
                    {
                        visitCandidates.Add(visit);
                    }
                }
            }

            // Correlate visits to URLs
            for (int i = 0; i < visitCandidates.Count; i++)
            {
                CarvedVisitCandidate visit = visitCandidates[i];
                BrowserHistoryRecord parentUrl;
                if (urlMap.TryGetValue(visit.UrlId, out parentUrl))
                {
                    BrowserVisitDetail detail = new BrowserVisitDetail();
                    detail.VisitTimeUtc = visit.VisitTimeUtc;
                    detail.RawVisitTime = visit.RawVisitTime;
                    detail.TransitionCode = visit.Transition;
                    detail.VisitType = MapChromiumTransition(visit.Transition);
                    detail.DurationSeconds = visit.Duration;
                    detail.FromVisitId = visit.FromVisit;
                    parentUrl.Visits.Add(detail);
                }
                else
                {
                    // Orphaned visit
                    BrowserHistoryRecord orphan = new BrowserHistoryRecord();
                    orphan.Browser = BrowserType.Chromium;
                    orphan.Url = "[Orphaned Visit: URL_ID=" + visit.UrlId + "]";
                    orphan.LastVisitUtc = visit.VisitTimeUtc;
                    orphan.RawTimestamp = visit.RawVisitTime;
                    orphan.Origin = "OrphanedVisit";
                    orphan.RecordId = visit.UrlId;

                    BrowserVisitDetail detail = new BrowserVisitDetail();
                    detail.VisitTimeUtc = visit.VisitTimeUtc;
                    detail.RawVisitTime = visit.RawVisitTime;
                    detail.TransitionCode = visit.Transition;
                    detail.VisitType = MapChromiumTransition(visit.Transition);
                    detail.DurationSeconds = visit.Duration;
                    detail.FromVisitId = visit.FromVisit;
                    orphan.Visits.Add(detail);

                    results.Add(orphan);
                }
            }

            results.AddRange(urlMap.Values);
            return results;
        }

        private static bool IsChromiumUrlRecord(CarvedSqliteRecord rec)
        {
            if (rec.Columns.Count < 2) return false;

            // Pattern: Col 0 or 1 is URL string, and some column has a WebKit timestamp (year 1970 to 2235)
            int urlCol = -1;
            for (int i = 0; i < Math.Min(3, rec.Columns.Count); i++)
            {
                if (rec.Columns[i].Type == SqliteColumnType.Text)
                {
                    string s = rec.Columns[i].AsString();
                    if (LooksLikeUrl(s))
                    {
                        urlCol = i;
                        break;
                    }
                }
            }

            if (urlCol < 0) return false;

            for (int i = 0; i < rec.Columns.Count; i++)
            {
                if (i == urlCol) continue;
                if (rec.Columns[i].Type == SqliteColumnType.Integer)
                {
                    long val = rec.Columns[i].AsLong(0);
                    // WebKit timestamp range: 11644473600000000L (1970) to 20000000000000000L (~2235)
                    if (val >= 11644473600000000L && val <= 25000000000000000L)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static BrowserHistoryRecord ExtractChromiumUrlRecord(CarvedSqliteRecord rec)
        {
            BrowserHistoryRecord item = new BrowserHistoryRecord();
            item.Browser = BrowserType.Chromium;
            item.Origin = rec.Origin.ToString();

            int urlCol = -1;
            for (int i = 0; i < Math.Min(3, rec.Columns.Count); i++)
            {
                if (rec.Columns[i].Type == SqliteColumnType.Text && LooksLikeUrl(rec.Columns[i].AsString()))
                {
                    urlCol = i;
                    break;
                }
            }

            if (urlCol < 0) return null;

            item.Url = rec.Columns[urlCol].AsString();

            // RowId
            if (rec.RowId.HasValue)
            {
                item.RecordId = rec.RowId.Value;
            }
            else if (urlCol == 1 && rec.Columns[0].Type == SqliteColumnType.Integer)
            {
                item.RecordId = rec.Columns[0].AsLong(0);
            }

            // Title usually at urlCol + 1
            if (urlCol + 1 < rec.Columns.Count && rec.Columns[urlCol + 1].Type == SqliteColumnType.Text)
            {
                item.Title = rec.Columns[urlCol + 1].AsString();
            }

            // Visit count and last visit time
            for (int i = 0; i < rec.Columns.Count; i++)
            {
                if (i == urlCol) continue;
                if (rec.Columns[i].Type == SqliteColumnType.Integer)
                {
                    long val = rec.Columns[i].AsLong(0);
                    if (val >= 11644473600000000L && val <= 25000000000000000L)
                    {
                        item.RawTimestamp = val;
                        item.LastVisitUtc = BrowserTimestampConverter.WebKitTimeToUtc(val);
                    }
                    else if (val >= 0 && val < 1000000 && item.VisitCount == 0 && i != 0)
                    {
                        item.VisitCount = (int)val;
                    }
                }
            }

            return item;
        }

        private static bool IsChromiumVisitRecord(CarvedSqliteRecord rec)
        {
            if (rec.Columns.Count < 3) return false;

            // Visit record: no text URLs, but contains a WebKit timestamp
            for (int i = 0; i < rec.Columns.Count; i++)
            {
                if (rec.Columns[i].Type == SqliteColumnType.Text && LooksLikeUrl(rec.Columns[i].AsString()))
                {
                    return false;
                }
            }

            for (int i = 0; i < rec.Columns.Count; i++)
            {
                if (rec.Columns[i].Type == SqliteColumnType.Integer)
                {
                    long val = rec.Columns[i].AsLong(0);
                    if (val >= 11644473600000000L && val <= 25000000000000000L)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static CarvedVisitCandidate ExtractChromiumVisitRecord(CarvedSqliteRecord rec)
        {
            CarvedVisitCandidate cand = new CarvedVisitCandidate();

            int timeCol = -1;
            for (int i = 0; i < rec.Columns.Count; i++)
            {
                if (rec.Columns[i].Type == SqliteColumnType.Integer)
                {
                    long val = rec.Columns[i].AsLong(0);
                    if (val >= 11644473600000000L && val <= 25000000000000000L)
                    {
                        timeCol = i;
                        cand.RawVisitTime = val;
                        cand.VisitTimeUtc = BrowserTimestampConverter.WebKitTimeToUtc(val);
                        break;
                    }
                }
            }

            if (timeCol < 0) return null;

            // In visits table: col 1 is url ID, col 2 is visit_time
            if (timeCol == 2 && rec.Columns[1].Type == SqliteColumnType.Integer)
            {
                cand.UrlId = rec.Columns[1].AsLong(0);
            }
            else if (timeCol > 0 && rec.Columns[timeCol - 1].Type == SqliteColumnType.Integer)
            {
                cand.UrlId = rec.Columns[timeCol - 1].AsLong(0);
            }

            if (timeCol + 1 < rec.Columns.Count && rec.Columns[timeCol + 1].Type == SqliteColumnType.Integer)
            {
                cand.FromVisit = rec.Columns[timeCol + 1].AsLong(0);
            }

            if (timeCol + 2 < rec.Columns.Count && rec.Columns[timeCol + 2].Type == SqliteColumnType.Integer)
            {
                cand.Transition = (int)rec.Columns[timeCol + 2].AsLong(0);
            }

            if (timeCol + 4 < rec.Columns.Count && rec.Columns[timeCol + 4].Type == SqliteColumnType.Integer)
            {
                cand.Duration = (int)rec.Columns[timeCol + 4].AsLong(0);
            }

            return cand;
        }

        private static BrowserVisitType MapChromiumTransition(int transition)
        {
            int core = transition & 0xFF;
            switch (core)
            {
                case 0: return BrowserVisitType.Link;
                case 1: return BrowserVisitType.Typed;
                case 2: return BrowserVisitType.Bookmark;
                case 3: return BrowserVisitType.Subframe;
                case 4: return BrowserVisitType.Embed;
                case 5: return BrowserVisitType.RedirectPermanent;
                case 6: return BrowserVisitType.RedirectTemporary;
                case 7: return BrowserVisitType.Download;
                case 8: return BrowserVisitType.Reload;
                case 9: return BrowserVisitType.FormSubmit;
                default: return BrowserVisitType.Other;
            }
        }

        // -------------------------------------------------------------------------
        // Firefox History Parsing
        // -------------------------------------------------------------------------
        public static List<BrowserHistoryRecord> ParseFirefox(string dbPath)
        {
            if (dbPath == null) throw new ArgumentNullException("dbPath");
            if (!File.Exists(dbPath)) throw new FileNotFoundException("Database not found", dbPath);

            using (FileStream fs = new FileStream(dbPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                return ParseFirefox(fs);
            }
        }

        public static List<BrowserHistoryRecord> ParseFirefox(Stream stream)
        {
            List<CarvedSqliteRecord> carvedRecords = SqliteCarver.CarveDatabase(stream);
            return InterpretFirefoxRecords(carvedRecords);
        }

        public static List<BrowserHistoryRecord> InterpretFirefoxRecords(IEnumerable<CarvedSqliteRecord> records)
        {
            List<BrowserHistoryRecord> results = new List<BrowserHistoryRecord>();
            if (records == null) return results;

            Dictionary<long, BrowserHistoryRecord> placeMap = new Dictionary<long, BrowserHistoryRecord>();
            List<CarvedVisitCandidate> visitCandidates = new List<CarvedVisitCandidate>();

            foreach (CarvedSqliteRecord rec in records)
            {
                if (rec == null || rec.Columns == null || rec.Columns.Count == 0) continue;

                if (IsFirefoxPlaceRecord(rec))
                {
                    BrowserHistoryRecord item = ExtractFirefoxPlaceRecord(rec);
                    if (item != null && !String.IsNullOrEmpty(item.Url))
                    {
                        if (item.RecordId > 0 && !placeMap.ContainsKey(item.RecordId))
                        {
                            placeMap[item.RecordId] = item;
                        }
                        else
                        {
                            results.Add(item);
                        }
                    }
                }
                else if (IsFirefoxVisitRecord(rec))
                {
                    CarvedVisitCandidate visit = ExtractFirefoxVisitRecord(rec);
                    if (visit != null)
                    {
                        visitCandidates.Add(visit);
                    }
                }
            }

            // Correlate visits to places
            for (int i = 0; i < visitCandidates.Count; i++)
            {
                CarvedVisitCandidate visit = visitCandidates[i];
                BrowserHistoryRecord parentPlace;
                if (placeMap.TryGetValue(visit.UrlId, out parentPlace))
                {
                    BrowserVisitDetail detail = new BrowserVisitDetail();
                    detail.VisitTimeUtc = visit.VisitTimeUtc;
                    detail.RawVisitTime = visit.RawVisitTime;
                    detail.TransitionCode = visit.Transition;
                    detail.VisitType = MapFirefoxVisitType(visit.Transition);
                    parentPlace.Visits.Add(detail);
                }
                else
                {
                    BrowserHistoryRecord orphan = new BrowserHistoryRecord();
                    orphan.Browser = BrowserType.Firefox;
                    orphan.Url = "[Orphaned Visit: Place_ID=" + visit.UrlId + "]";
                    orphan.LastVisitUtc = visit.VisitTimeUtc;
                    orphan.RawTimestamp = visit.RawVisitTime;
                    orphan.Origin = "OrphanedVisit";
                    orphan.RecordId = visit.UrlId;

                    BrowserVisitDetail detail = new BrowserVisitDetail();
                    detail.VisitTimeUtc = visit.VisitTimeUtc;
                    detail.RawVisitTime = visit.RawVisitTime;
                    detail.TransitionCode = visit.Transition;
                    detail.VisitType = MapFirefoxVisitType(visit.Transition);
                    orphan.Visits.Add(detail);

                    results.Add(orphan);
                }
            }

            results.AddRange(placeMap.Values);
            return results;
        }

        private static bool IsFirefoxPlaceRecord(CarvedSqliteRecord rec)
        {
            if (rec.Columns.Count < 2) return false;

            int urlCol = -1;
            for (int i = 0; i < Math.Min(3, rec.Columns.Count); i++)
            {
                if (rec.Columns[i].Type == SqliteColumnType.Text && LooksLikeUrl(rec.Columns[i].AsString()))
                {
                    urlCol = i;
                    break;
                }
            }

            if (urlCol < 0) return false;

            // PRTime timestamp range: 946684800000000L (year 2000) to 5000000000000000L (~year 2128)
            for (int i = 0; i < rec.Columns.Count; i++)
            {
                if (i == urlCol) continue;
                if (rec.Columns[i].Type == SqliteColumnType.Integer)
                {
                    long val = rec.Columns[i].AsLong(0);
                    if (val >= 946684800000000L && val <= 5000000000000000L)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static BrowserHistoryRecord ExtractFirefoxPlaceRecord(CarvedSqliteRecord rec)
        {
            BrowserHistoryRecord item = new BrowserHistoryRecord();
            item.Browser = BrowserType.Firefox;
            item.Origin = rec.Origin.ToString();

            int urlCol = -1;
            for (int i = 0; i < Math.Min(3, rec.Columns.Count); i++)
            {
                if (rec.Columns[i].Type == SqliteColumnType.Text && LooksLikeUrl(rec.Columns[i].AsString()))
                {
                    urlCol = i;
                    break;
                }
            }

            if (urlCol < 0) return null;

            item.Url = rec.Columns[urlCol].AsString();

            if (rec.RowId.HasValue)
            {
                item.RecordId = rec.RowId.Value;
            }
            else if (urlCol == 1 && rec.Columns[0].Type == SqliteColumnType.Integer)
            {
                item.RecordId = rec.Columns[0].AsLong(0);
            }

            if (urlCol + 1 < rec.Columns.Count && rec.Columns[urlCol + 1].Type == SqliteColumnType.Text)
            {
                item.Title = rec.Columns[urlCol + 1].AsString();
            }

            for (int i = 0; i < rec.Columns.Count; i++)
            {
                if (i == urlCol) continue;
                if (rec.Columns[i].Type == SqliteColumnType.Integer)
                {
                    long val = rec.Columns[i].AsLong(0);
                    if (val >= 946684800000000L && val <= 5000000000000000L)
                    {
                        item.RawTimestamp = val;
                        item.LastVisitUtc = BrowserTimestampConverter.PrTimeToUtc(val);
                    }
                    else if (val >= 0 && val < 1000000 && item.VisitCount == 0 && i != 0)
                    {
                        item.VisitCount = (int)val;
                    }
                }
            }

            return item;
        }

        private static bool IsFirefoxVisitRecord(CarvedSqliteRecord rec)
        {
            if (rec.Columns.Count < 3) return false;

            for (int i = 0; i < rec.Columns.Count; i++)
            {
                if (rec.Columns[i].Type == SqliteColumnType.Text && LooksLikeUrl(rec.Columns[i].AsString()))
                {
                    return false;
                }
            }

            for (int i = 0; i < rec.Columns.Count; i++)
            {
                if (rec.Columns[i].Type == SqliteColumnType.Integer)
                {
                    long val = rec.Columns[i].AsLong(0);
                    if (val >= 946684800000000L && val <= 5000000000000000L)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static CarvedVisitCandidate ExtractFirefoxVisitRecord(CarvedSqliteRecord rec)
        {
            CarvedVisitCandidate cand = new CarvedVisitCandidate();

            int timeCol = -1;
            for (int i = 0; i < rec.Columns.Count; i++)
            {
                if (rec.Columns[i].Type == SqliteColumnType.Integer)
                {
                    long val = rec.Columns[i].AsLong(0);
                    if (val >= 946684800000000L && val <= 5000000000000000L)
                    {
                        timeCol = i;
                        cand.RawVisitTime = val;
                        cand.VisitTimeUtc = BrowserTimestampConverter.PrTimeToUtc(val);
                        break;
                    }
                }
            }

            if (timeCol < 0) return null;

            // moz_historyvisits: col 1 from_visit, col 2 place_id, col 3 visit_date, col 4 visit_type
            if (timeCol == 3 && rec.Columns.Count > 2 && rec.Columns[2].Type == SqliteColumnType.Integer)
            {
                cand.UrlId = rec.Columns[2].AsLong(0);
            }
            else if (timeCol > 0 && rec.Columns[timeCol - 1].Type == SqliteColumnType.Integer)
            {
                cand.UrlId = rec.Columns[timeCol - 1].AsLong(0);
            }

            if (timeCol + 1 < rec.Columns.Count && rec.Columns[timeCol + 1].Type == SqliteColumnType.Integer)
            {
                cand.Transition = (int)rec.Columns[timeCol + 1].AsLong(0);
            }

            return cand;
        }

        private static BrowserVisitType MapFirefoxVisitType(int type)
        {
            switch (type)
            {
                case 1: return BrowserVisitType.Link;
                case 2: return BrowserVisitType.Typed;
                case 3: return BrowserVisitType.Bookmark;
                case 4: return BrowserVisitType.Embed;
                case 5: return BrowserVisitType.RedirectPermanent;
                case 6: return BrowserVisitType.RedirectTemporary;
                case 7: return BrowserVisitType.Download;
                case 8: return BrowserVisitType.Subframe;
                case 9: return BrowserVisitType.Reload;
                default: return BrowserVisitType.Other;
            }
        }

        private static bool LooksLikeUrl(string s)
        {
            if (String.IsNullOrEmpty(s) || s.Length < 4) return false;
            return s.IndexOf("://", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   s.StartsWith("http:", StringComparison.OrdinalIgnoreCase) ||
                   s.StartsWith("https:", StringComparison.OrdinalIgnoreCase) ||
                   s.StartsWith("chrome:", StringComparison.OrdinalIgnoreCase) ||
                   s.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ||
                   s.StartsWith("about:", StringComparison.OrdinalIgnoreCase);
        }

        private sealed class CarvedVisitCandidate
        {
            public long UrlId { get; set; }
            public DateTime VisitTimeUtc { get; set; }
            public long RawVisitTime { get; set; }
            public int Transition { get; set; }
            public int Duration { get; set; }
            public long FromVisit { get; set; }
        }

        // -------------------------------------------------------------------------
        // Browser Cache Parsers (Chromium Simple Cache & Firefox Cache2)
        // -------------------------------------------------------------------------
        public static BrowserCacheRecord ParseChromiumSimpleCache(Stream stream, string sourcePath)
        {
            if (stream == null || stream.Length < 24) return null;

            byte[] buffer = new byte[(int)Math.Min(stream.Length, 65536)];
            stream.Seek(0, SeekOrigin.Begin);
            int read = stream.Read(buffer, 0, buffer.Length);
            if (read < 24) return null;

            // SimpleFileHeader magic: 0xfcfb6d0543706173UL
            ulong magic = BitConverter.ToUInt64(buffer, 0);
            if (magic != 0xfcfb6d0543706173UL)
            {
                return null;
            }

            uint version = BitConverter.ToUInt32(buffer, 8);
            uint keyLength = BitConverter.ToUInt32(buffer, 12);
            if (keyLength == 0 || keyLength > buffer.Length - 24)
            {
                return null;
            }

            string rawKey = Encoding.UTF8.GetString(buffer, 20, (int)keyLength);
            string cleanUrl = CleanChromiumCacheKey(rawKey);

            BrowserCacheRecord record = new BrowserCacheRecord();
            record.Browser = BrowserType.Chromium;
            record.KeyUrl = cleanUrl;
            record.SourcePath = sourcePath ?? String.Empty;
            record.DataSize = stream.Length;

            int payloadOffset = 20 + (int)keyLength;
            if (payloadOffset < read)
            {
                ParseHttpPickleHeaders(buffer, payloadOffset, read - payloadOffset, record);
            }

            return record;
        }

        private static string CleanChromiumCacheKey(string key)
        {
            if (String.IsNullOrEmpty(key)) return String.Empty;
            int schemeIdx = key.IndexOf("http://", StringComparison.OrdinalIgnoreCase);
            if (schemeIdx < 0) schemeIdx = key.IndexOf("https://", StringComparison.OrdinalIgnoreCase);
            if (schemeIdx >= 0)
            {
                return key.Substring(schemeIdx);
            }
            return key;
        }

        private static void ParseHttpPickleHeaders(byte[] buffer, int offset, int length, BrowserCacheRecord record)
        {
            // Search for "HTTP/1." or "HTTP/2."
            int httpIdx = -1;
            for (int i = offset; i < offset + length - 7; i++)
            {
                if (buffer[i] == 'H' && buffer[i + 1] == 'T' && buffer[i + 2] == 'T' && buffer[i + 3] == 'P' && buffer[i + 4] == '/')
                {
                    httpIdx = i;
                    break;
                }
            }

            if (httpIdx < 0) return;

            string headerText = Encoding.ASCII.GetString(buffer, httpIdx, offset + length - httpIdx);
            string[] lines = headerText.Split(new string[] { "\r\n", "\n", "\0" }, StringSplitOptions.RemoveEmptyEntries);

            if (lines.Length > 0)
            {
                string statusLine = lines[0].Trim();
                string[] parts = statusLine.Split(' ');
                if (parts.Length >= 2)
                {
                    int statusCode;
                    if (Int32.TryParse(parts[1], out statusCode))
                    {
                        record.HttpStatusCode = statusCode;
                    }
                    if (parts.Length >= 3)
                    {
                        record.HttpStatusText = parts[2];
                    }
                }

                for (int i = 1; i < lines.Length; i++)
                {
                    string line = lines[i].Trim();
                    if (String.IsNullOrEmpty(line)) break;
                    int colon = line.IndexOf(':');
                    if (colon > 0)
                    {
                        string headerKey = line.Substring(0, colon).Trim();
                        string headerVal = line.Substring(colon + 1).Trim();
                        record.ResponseHeaders[headerKey] = headerVal;

                        if (String.Equals(headerKey, "Content-Type", StringComparison.OrdinalIgnoreCase))
                        {
                            record.ContentType = headerVal;
                        }
                    }
                }
            }
        }

        public static BrowserCacheRecord ParseFirefoxCache2(Stream stream, string sourcePath)
        {
            if (stream == null || stream.Length < 24) return null;

            long fileLength = stream.Length;
            byte[] footer = new byte[4];
            stream.Seek(fileLength - 4, SeekOrigin.Begin);
            if (stream.Read(footer, 0, 4) != 4) return null;

            uint metaDataSize = ((uint)footer[0] << 24) | ((uint)footer[1] << 16) | ((uint)footer[2] << 8) | footer[3];
            if (metaDataSize < 20 || metaDataSize > fileLength - 4)
            {
                return null;
            }

            long metaOffset = fileLength - 4 - metaDataSize;
            stream.Seek(metaOffset, SeekOrigin.Begin);
            byte[] metaBytes = new byte[metaDataSize];
            if (stream.Read(metaBytes, 0, (int)metaDataSize) != (int)metaDataSize)
            {
                return null;
            }

            uint fetchCount = ((uint)metaBytes[0] << 24) | ((uint)metaBytes[1] << 16) | ((uint)metaBytes[2] << 8) | metaBytes[3];
            uint lastFetchedSec = ((uint)metaBytes[4] << 24) | ((uint)metaBytes[5] << 16) | ((uint)metaBytes[6] << 8) | metaBytes[7];
            uint expirationSec = ((uint)metaBytes[8] << 24) | ((uint)metaBytes[9] << 16) | ((uint)metaBytes[10] << 8) | metaBytes[11];
            uint keyLength = ((uint)metaBytes[16] << 24) | ((uint)metaBytes[17] << 16) | ((uint)metaBytes[18] << 8) | metaBytes[19];

            if (keyLength == 0 || 20 + keyLength > metaDataSize)
            {
                return null;
            }

            string rawKey = Encoding.UTF8.GetString(metaBytes, 20, (int)keyLength);
            string cleanUrl = CleanFirefoxCache2Key(rawKey);

            BrowserCacheRecord record = new BrowserCacheRecord();
            record.Browser = BrowserType.Firefox;
            record.KeyUrl = cleanUrl;
            record.FetchCount = (int)fetchCount;
            if (lastFetchedSec > 0)
            {
                record.FetchTimeUtc = BrowserTimestampConverter.UnixEpoch.AddSeconds(lastFetchedSec);
            }
            if (expirationSec > 0)
            {
                record.ExpiryTimeUtc = BrowserTimestampConverter.UnixEpoch.AddSeconds(expirationSec);
            }
            record.DataSize = metaOffset;
            record.SourcePath = sourcePath ?? String.Empty;

            int headerOffset = 20 + (int)keyLength;
            if (headerOffset < metaDataSize)
            {
                ParseFirefoxNullDelimitedHeaders(metaBytes, headerOffset, (int)metaDataSize - headerOffset, record);
            }

            return record;
        }

        private static string CleanFirefoxCache2Key(string key)
        {
            if (String.IsNullOrEmpty(key)) return String.Empty;
            if (key.StartsWith(":")) key = key.Substring(1);
            int httpIdx = key.IndexOf("http://", StringComparison.OrdinalIgnoreCase);
            if (httpIdx < 0) httpIdx = key.IndexOf("https://", StringComparison.OrdinalIgnoreCase);
            if (httpIdx >= 0) return key.Substring(httpIdx);
            return key;
        }

        private static void ParseFirefoxNullDelimitedHeaders(byte[] buffer, int offset, int length, BrowserCacheRecord record)
        {
            int cursor = offset;
            int limit = offset + length;

            while (cursor < limit)
            {
                string key = ReadNullString(buffer, ref cursor, limit);
                if (String.IsNullOrEmpty(key)) break;

                string val = ReadNullString(buffer, ref cursor, limit);

                if (String.Equals(key, "response-head", StringComparison.OrdinalIgnoreCase))
                {
                    string[] lines = val.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                    if (lines.Length > 0)
                    {
                        string statusLine = lines[0].Trim();
                        string[] parts = statusLine.Split(' ');
                        if (parts.Length >= 2)
                        {
                            int sc;
                            if (Int32.TryParse(parts[1], out sc)) record.HttpStatusCode = sc;
                            if (parts.Length >= 3) record.HttpStatusText = parts[2];
                        }

                        for (int i = 1; i < lines.Length; i++)
                        {
                            int c = lines[i].IndexOf(':');
                            if (c > 0)
                            {
                                string hk = lines[i].Substring(0, c).Trim();
                                string hv = lines[i].Substring(c + 1).Trim();
                                record.ResponseHeaders[hk] = hv;
                                if (String.Equals(hk, "Content-Type", StringComparison.OrdinalIgnoreCase))
                                {
                                    record.ContentType = hv;
                                }
                            }
                        }
                    }
                }
                else
                {
                    record.ResponseHeaders[key] = val;
                }
            }
        }

        private static string ReadNullString(byte[] buffer, ref int cursor, int limit)
        {
            int start = cursor;
            while (cursor < limit && buffer[cursor] != 0)
            {
                cursor++;
            }
            int len = cursor - start;
            string s = (len > 0) ? Encoding.UTF8.GetString(buffer, start, len) : String.Empty;
            if (cursor < limit && buffer[cursor] == 0)
            {
                cursor++; // skip null terminator
            }
            return s;
        }
    }
}
