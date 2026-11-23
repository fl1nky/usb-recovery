using System;

namespace UsbRecovery
{
    public sealed class RecoveryStageProgress
    {
        public string Key,Title,State;
        public long Completed,Total,Candidates=-1;
        // Published only after the session has durably accepted the checkpoint.
        public long CheckpointSequence;
        public bool ResumingCheckpoint;
    }
}
