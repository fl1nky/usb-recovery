using System;

namespace UsbRecovery
{
    public sealed class RecoveryStageProgress
    {
        public string Key,Title,State;
        public long Completed,Total,Candidates=-1;
    }
}
