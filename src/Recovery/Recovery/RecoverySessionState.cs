using System;
using System.Collections.Generic;

namespace UsbRecovery
{
    public sealed class SessionArtifact
    {
        public string Path, Sha256;
        public long Bytes;
    }

    public sealed class SessionStage
    {
        public string Key, Status, Message;
        public int Candidates;
        public bool Warnings;
        public string CheckpointPath, CheckpointSha256;
        public long CheckpointSequence, CheckpointBytes;
        public List<SessionArtifact> Artifacts = new List<SessionArtifact>();
    }

    public sealed class RecoverySessionState
    {
        public int Schema = 1;
        public string SourcePath, SourceSha256, Status, UpdatedUtc, ReadMapSha256, SourceReadMapSha256;
        public long SourceBytes;
        public bool ExternalImage, SourceInWorkingDirectory;
        public string RelativeSourcePath;
        public RecoveryOptions Options;
        public List<SessionStage> Stages = new List<SessionStage>();
    }
}
