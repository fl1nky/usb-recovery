using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace UsbRecovery
{
    // An inventory lives outside engine scopes, so its own pages never enter
    // the inventory. Only the parent-acknowledged head selects page contents.
    internal static class RecoveryArtifactInventory
    {
        internal const int InlineArtifacts = 1024, LegacyInlineArtifacts = 100000, MaximumArtifacts = 250000;
        const long MaximumIndexBytes = 256L * 1024 * 1024;

        static RecoveryOutputLedger<SessionArtifact> Ledger(string root, string key,
            RecoveryOutputHead head, CancellationToken cancel)
        {
            var context = new RecoveryCheckpointContext { Directory = root, Method = key };
            return new RecoveryOutputLedger<SessionArtifact>(context, head, MaximumArtifacts, cancel,
                RecoveryLedgerScope.SessionArtifacts, MaximumIndexBytes);
        }

        internal static RecoveryOutputHead Write(string root, string key, List<SessionArtifact> artifacts,
            CancellationToken cancel)
        {
            if (artifacts == null || artifacts.Count > MaximumArtifacts)
                throw new IOException("SESSION_ARTIFACT_INVENTORY_LIMIT");
            if (artifacts.Count <= InlineArtifacts) return null;
            return Ledger(root, key, null, cancel).Append(null, artifacts);
        }

        internal static List<SessionArtifact> Read(string root, string key, RecoveryOutputHead head,
            CancellationToken cancel)
        {
            if (head == null || head.Count <= InlineArtifacts || head.Count > MaximumArtifacts)
                throw new IOException("SESSION_ARTIFACT_INVENTORY_INVALID");
            return Ledger(root, key, head, cancel).Records;
        }
    }
}
