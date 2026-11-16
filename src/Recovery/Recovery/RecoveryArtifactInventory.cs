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

        internal static int MaximumFor(string key)
        {
            // FAT keeps an output, an immutable reconstruction plan and an
            // acknowledged ledger page per candidate, plus directory metadata.
            // Keep the existing bound for every other engine and the same byte
            // budget for all indexes; the search still stops at 100000 outputs.
            return key == "fat" ? 400000 : MaximumArtifacts;
        }

        static RecoveryOutputLedger<SessionArtifact> Ledger(string root, string key,
            RecoveryOutputHead head, CancellationToken cancel)
        {
            var context = new RecoveryCheckpointContext { Directory = root, Method = key };
            return new RecoveryOutputLedger<SessionArtifact>(context, head, MaximumFor(key), cancel,
                RecoveryLedgerScope.SessionArtifacts, MaximumIndexBytes);
        }

        internal static RecoveryOutputHead Write(string root, string key, List<SessionArtifact> artifacts,
            CancellationToken cancel)
        {
            if (artifacts == null || artifacts.Count > MaximumFor(key))
                throw new IOException("SESSION_ARTIFACT_INVENTORY_LIMIT");
            if (artifacts.Count <= InlineArtifacts) return null;
            return Ledger(root, key, null, cancel).Append(null, artifacts);
        }

        internal static List<SessionArtifact> Read(string root, string key, RecoveryOutputHead head,
            CancellationToken cancel)
        {
            if (head == null || head.Count <= InlineArtifacts || head.Count > MaximumFor(key))
                throw new IOException("SESSION_ARTIFACT_INVENTORY_INVALID");
            return Ledger(root, key, head, cancel).Records;
        }
    }
}
