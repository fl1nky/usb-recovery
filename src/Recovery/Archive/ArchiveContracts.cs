using System;
using System.Collections.Generic;

namespace UsbRecovery
{
    // Public names are the version-1 helper protocol, not UI control names.
    // Nullable fields preserve unknown attribution. Object identifiers retain
    // the original string/number representation across supported archive types.
    public sealed class ArchiveMessage
    {
        public string app;
        public string snapshot_id;
        public string chat_name;
        public string sender_name;
        public string evidence_kind;
        public string source_file;
        public string source_record;
        public string text;
        public string source_id;
        public string original_relative_path;
        public string source_sha256;
        public string record_kind;
        public string completeness;
        public string text_field;
        public string native_postbox_value_sha256;
        public string recovery_status;
        public string deletion_interpretation;
        public string physical_source;
        public string record_sha256;
        public string proof;
        public string native_tl_body_sha256;
        public string provenance_verification;
        public Dictionary<string,object> archive_claims;
        public Dictionary<string,object>[] residual_sources;
        public object sqlite_page;
        public object record_page_offset;
        public object blob_page_offset;
        public object record_length;
        public object physical_byte_offset;
        public object wal_frame;
        public object candidate_message_id;
        public object candidate_peer;
        public object candidate_date;
        public object sqlite_stored_mid;
        public string sqlite_region;
        public string offset_kind;
        public string sqlite_record_sha256;
        public object sqlite_record_page_offset;
        public object sqlite_record_length;
        public object sqlite_blob_page_offset;
        public bool? sqlite_header_length_reconstructed;
        public string sqlite_payload_sha256;
        public object sqlite_payload_length;
        public Dictionary<string,object>[] sqlite_payload_ranges;
        public long[] sqlite_overflow_pages;
        public bool? sqlite_overflow_chain_verified;
        public string heap_class;
        public string heap_object_id;
        public string heap_record_sha256;
        public string heap_text_sha256;
        public string heap_version;
        public object candidate_sender;
        public object heap_record_length;
        public object heap_snapshot_ms;
        public object heap_identifier_bytes;
        public bool? header_length_reconstructed;
        public bool? deleted;
        public string identity_scope;
        public string native_constructor;
        public string wal_proof;
        public string wal_db_sha256;
        public string wal_sha256;
        public string wal_snapshot_sha256;
        public string wal_tail_reason;
        public object wal_validated_prefix_bytes;
        public bool? wal_snapshot_latest_known_commit;
        public bool? wal_current_state_confirmed;
        public string rollback_journal_sha256;
        public string rollback_snapshot_sha256;
        public string rollback_proof;
        public string container_sha256;
        public string container_source_id;
        public string container_source_file;
        public string rollback_page_map;
        public string rollback_page_map_sha256;
        public string rollback_hot_state;
        public string rollback_checksum_kind;
        public string rollback_parse_status;
        public string rollback_tail_reason;
        public string rollback_payload_sha256;
        public object rollback_initial_pages;
        public object rollback_validated_prefix_bytes;
        public object rollback_header_offset;
        public object rollback_record_offset;
        public object rollback_page;
        public object rollback_payload_length;
        public bool? rollback_current_state_confirmed;
        public bool? rollback_content_authenticity_verified;
        public bool? rollback_payload_chain_verified;
        public Dictionary<string,object>[] rollback_payload_ranges;
        public string media_kind;
        public string media_id;
        public string media_status;
        public object thumbnail_count;
        public object native_layer;
        public object wal_commit_frame;
        public object byte_offset;
        public object byte_length;
        public string encoding;
        public string archive_record_key;
        public long text_offset;
        public long text_end;
        public long match_offset;
        public long match_end;
        public bool? application_confirmed;
        public object chat_id;
        public object sender_id;
        public object message_id;
        public object timestamp;
        public object timestamp_raw;
        public bool text_truncated;
        public bool? date_ambiguous;
        public bool? timezone_unknown;
        public long text_length;
        public string[] attachments;
        public Dictionary<string, object>[] sources;
    }

    public class ArchiveResponse
    {
        public string status;
        public string code;
        public string archive;
    }
    public sealed class ArchiveSearchResult : ArchiveResponse
    {
        public long total;
        public long offset;
        public int limit;
        public string[] warnings;
        public List<ArchiveMessage> records;
    }
    public sealed class ArchiveTextPage : ArchiveResponse
    {
        public string record_key;
        public string text;
        public long text_offset;
        public long next_offset;
        public long text_length;
        public int limit;
        public bool eof;
    }

}
