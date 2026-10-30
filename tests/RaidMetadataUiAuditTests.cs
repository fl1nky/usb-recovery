using System;
using System.Drawing;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;
using UsbRecovery;

// Constructor/state checks for the real controls; no native app automation,
// source discovery, physical devices, or modal dialogs are invoked.
public static class RaidMetadataUiAuditTests
{
    static int checks;
    static void Check(bool condition,string why){checks++;if(!condition)throw new Exception(why);}
    static Control Find(Control root,string name){foreach(Control child in root.Controls){if(child.Name==name)return child;var found=Find(child,name);if(found!=null)return found;}return null;}
    static T Field<T>(object target,string name){return (T)target.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(target);}
    static string Notes(RaidMetadataProbe.Report report){return (string)typeof(RaidMetadataSelection).GetMethod("Notes",BindingFlags.Static|BindingFlags.NonPublic).Invoke(null,new object[]{report});}
    static RaidMetadataProbe.Group Candidate()
    {
        var group=new RaidMetadataProbe.Group{Uuid="owned-fixture",Name="fixture",Status="candidate",Format="1.2",Level="1",Layout="mirror",RaidDisks=2,Configuration=new RaidConfiguration{Level="1",Layout="mirror",LogicalSize=1048576,ChunkSize=512}};
        group.Configuration.Members.Add(new RaidMember{Path=@"C:\Synthetic\role0.raw",Offset=1048576});group.Configuration.Members.Add(new RaidMember{Missing=true});return group;
    }
    static void Selection()
    {
        var empty=new RaidMetadataProbe.Report();
        using(var form=new RaidMetadataSelection(empty)){
            Check(form.SelectedGroup==null&&!Find(form,"raid-apply-metadata").Enabled,"No candidate means no enabled apply action");
            Check(Find(form,"raid-metadata-notes")==null,"Empty report does not invent failure explanations");
        }
        var invalid=new RaidMetadataProbe.Report();invalid.Members.Add(new RaidMetadataProbe.Member{Path=@"C:\Synthetic\corrupt.raw",Status="invalid",Code="MD_CHECKSUM_INVALID"});
        using(var form=new RaidMetadataSelection(invalid)){
            Check(form.SelectedGroup==null&&!Find(form,"raid-apply-metadata").Enabled,"Damaged metadata cannot be applied");
            Check(Find(form,"raid-metadata-notes")!=null,"Actual rejection is accessible even with no candidate groups");
            string note=Notes(invalid);Check(note.Contains("corrupt.raw")&&note.Contains("MD_CHECKSUM_INVALID")&&note.Contains("контрольная сумма"),"Failure source and concrete explanation retained");
        }
        var mixed=new RaidMetadataProbe.Report();var candidate=Candidate();mixed.Groups.Add(candidate);mixed.Groups.Add(new RaidMetadataProbe.Group{Uuid="other",Name="injected\r\nname",Status="inconsistent",Reasons={"MD_EVENT_COUNTER_MISMATCH"}});
        using(var form=new RaidMetadataSelection(mixed)){
            var arrays=Field<ComboBox>(form,"arrays");var disks=Field<DataGridView>(form,"disks");
            Check(arrays.Items.Count==1&&Object.ReferenceEquals(form.SelectedGroup,candidate),"Only supported candidate can be selected for apply");
            Check(Find(form,"raid-apply-metadata").Enabled&&Find(form,"raid-metadata-notes")!=null,"Candidate apply and other-array remarks remain separately available");
            Check(disks.ReadOnly&&!disks.AllowUserToAddRows&&!disks.AllowUserToDeleteRows,"Review grid cannot silently edit decoded roles");
            Check(disks.Rows.Count==2&&Convert.ToString(disks.Rows[0].Cells[1].Value)=="role0.raw"&&Convert.ToString(disks.Rows[1].Cells[1].Value)=="Диск отсутствует","Role order and explicit missing member shown");
            Check(disks.Rows[0].Cells[1].ToolTipText==candidate.Configuration.Members[0].Path,"Full source path retained for review");
            string notes=Notes(mixed);Check(notes.Contains("разные версии")&&notes.Contains("MD_EVENT_COUNTER_MISMATCH")&&!notes.Contains("injected\r\nname"),"Conflicting generation and sanitized label remain reviewable");
        }
        Check(candidate.Configuration.Members.Count==2&&candidate.Configuration.Members[1].Missing&&candidate.Configuration.Members[0].Offset==1048576,"Review does not mutate proposed configuration");
    }
    static void BusyState()
    {
        using(var panel=new StorageRecoveryPanel()){
            var modes=Field<TabControl>(panel,"modes");modes.SelectedIndex=1;var members=Field<DataGridView>(panel,"members");members.Rows.Add(@"C:\Synthetic\unchanged.raw","512",false);
            var setter=typeof(StorageRecoveryPanel).GetMethod("SetBusy",BindingFlags.Instance|BindingFlags.NonPublic);setter.Invoke(panel,new object[]{true});
            Check(panel.IsBusy&&!modes.Enabled&&!members.Enabled,"Probe disables all RAID editors through their parent");
            foreach(string field in new[]{"level","layoutKind","chunk","raidSize","expectedSha"})Check(!Field<Control>(panel,field).Enabled,"Busy geometry editor disabled: "+field);
            setter.Invoke(panel,new object[]{false});Check(!panel.IsBusy&&modes.Enabled&&members.Enabled,"Editors return after cancellation or completion");
            Check(members.Rows.Count==1&&Convert.ToString(members.Rows[0].Cells[0].Value)==@"C:\Synthetic\unchanged.raw"&&Convert.ToString(members.Rows[0].Cells[1].Value)=="512","Busy transitions preserve supplied member paths and offsets");
        }
    }
    [STAThread]public static int Main()
    {
        try{Application.EnableVisualStyles();Selection();BusyState();Console.WriteLine("PASS RaidMetadataUiAudit: "+checks+" checks; real controls reject unsupported apply, preserve source role/path/offset, expose failure reasons and disable editors while busy. No devices or modal interaction.");return 0;}catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
