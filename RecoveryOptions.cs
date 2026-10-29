using System;
using System.Collections.Generic;
using System.Linq;

namespace UsbRecovery
{
    public sealed class RecoveryOptions
    {
        public bool FatMetadata = true, NtfsMetadata = true, LostPartitions = true, AlternateFat;
        public bool Signatures = true, SmallBlocks = true, JpegFragments, KeepCorrupted;
        public bool EmbeddedPhotos = true, Containers = true, TolerateReadErrors;
        public bool OrphanDirectories, TextFragments;
        public bool MetadataRescue, ArchiveMembers, FragmentedArchives;
        public bool CustomSignatures;
        public List<UserSignatureRule> CustomRules=new List<UserSignatureRule>();
        public string TextQuery = "";
        public bool Photos = true, Video = true, Audio = true, Documents = true, Archives = true, Other = true;
        public static RecoveryOptions Legacy(bool deep) { return new RecoveryOptions { LostPartitions = false, Containers = false, SmallBlocks = deep, JpegFragments = deep, KeepCorrupted = deep, EmbeddedPhotos = deep }; }
        public void Validate()
        {
            if (!(FatMetadata || NtfsMetadata || Signatures || EmbeddedPhotos || Containers || TextFragments || MetadataRescue || ArchiveMembers || FragmentedArchives || CustomSignatures)) throw new ArgumentException("Выбери хотя бы один способ извлечения файлов.");
            if(CustomSignatures)try{UserSignatureRecovery.Validate(CustomRules);}catch(System.IO.IOException e){throw new ArgumentException(e.Message.Replace("USER_SIGNATURE_INVALID: ",""));}
            if (Signatures && !(Photos || Video || Audio || Documents || Archives || Other)) throw new ArgumentException("Выбери хотя бы одну группу форматов PhotoRec.");
            if (TextFragments && (String.IsNullOrWhiteSpace(TextQuery) || TextQuery.Length > 256 || TextQuery.Split((char[])null,StringSplitOptions.RemoveEmptyEntries).Length > 8)) throw new ArgumentException("Для текстовых остатков укажи от 1 до 8 ключевых слов, не более 256 символов.");
            if(OrphanDirectories&&!FatMetadata)throw new ArgumentException("Для поиска потерянных каталогов включи FAT/exFAT.");
        }
        public string PhotoRecCommand()
        {
            var tokens = new List<string> { "partition_none", "options", JpegFragments ? "paranoid_bf" : "paranoid", KeepCorrupted ? "keep_corrupted_file" : "keep_corrupted_file_no" };
            if (SmallBlocks) tokens.AddRange(new[] { "blocksize", "512" });
            // Other means the complete upstream format set. Narrow groups are
            // explicit PhotoRec handler names, never user-supplied CLI tokens.
            tokens.AddRange(new[] { "fileopt", "everything", Other ? "enable" : "disable" });
            if (!Other) {
                if (Photos) Enable(tokens, "jpg", "png", "gif", "bmp", "tif", "riff", "mov", "raf", "crw", "orf", "rw2", "psd");
                if (Video) Enable(tokens, "mov", "riff", "mpg", "mkv", "flv", "m2ts");
                if (Audio) Enable(tokens, "mp3", "riff", "ogg", "flac", "mid", "amr", "au");
                if (Documents) Enable(tokens, "pdf", "zip", "doc", "txt");
                if (Archives) Enable(tokens, "zip", "rar", "7z", "gz", "bz2", "tar", "xz");
            }
            tokens.AddRange(new[] { "wholespace", "search" });
            return String.Join(",", tokens);
        }
        static void Enable(List<string> tokens, params string[] formats) { foreach (string format in formats) { tokens.Add(format); tokens.Add("enable"); } }
    }
}
