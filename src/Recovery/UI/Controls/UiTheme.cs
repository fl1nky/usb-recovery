using System;
using System.Drawing;
using System.Runtime.CompilerServices;
using System.Windows.Forms;

namespace UsbRecovery
{
    public static class UiTheme
    {
        public static readonly Color Background = Color.FromArgb(244, 247, 251);
        public static readonly Color Surface = Color.White;
        public static readonly Color Text = Color.FromArgb(27, 39, 57);
        public static readonly Color Muted = Color.FromArgb(107, 122, 143);
        public static readonly Color Border = Color.FromArgb(222, 229, 238);
        public static readonly Color Accent = Color.FromArgb(48, 99, 221);
        public static readonly Color Sidebar = Color.FromArgb(23, 31, 45);

        static readonly ConditionalWeakTable<Button,object> StyledButtons=new ConditionalWeakTable<Button,object>();
        static void ButtonState(Button button)
        {
            var owner=button.FindForm();if(button.IsDisposed||button.Disposing||(owner!=null&&(owner.IsDisposed||owner.Disposing)))return;
            bool primary=Convert.ToString(button.Tag)=="primary";
            button.BackColor=button.Enabled?(primary?Accent:Surface):Color.FromArgb(234,239,246);
            button.ForeColor=button.Enabled?(primary?Color.White:Text):Muted;
            button.FlatAppearance.BorderColor=button.Enabled&&primary?Accent:Border;
            button.Cursor=button.Enabled?Cursors.Hand:Cursors.Default;
        }
        public static void ApplyTree(Control control)
        {
            bool muted=control is Label && control.ForeColor==Muted;
            control.ForeColor = muted?Muted:Text;
            if(Convert.ToString(control.Tag)=="sidebar")control.BackColor=Sidebar;
            if(Convert.ToString(control.Tag)=="on-dark")control.ForeColor=Color.White;
            if(Convert.ToString(control.Tag)=="muted-dark")control.ForeColor=Color.FromArgb(136,154,178);
            if (control is Form || control is UserControl) control.BackColor = Background;
            if (control is Label && Convert.ToString(control.Tag) == "muted") control.ForeColor = Muted;
            var button = control as Button;
            if (button != null && !(button is NavigationButton)) {
                bool primary = Convert.ToString(button.Tag) == "primary";
                button.FlatStyle = FlatStyle.Flat; button.FlatAppearance.BorderSize = 1;
                button.FlatAppearance.BorderColor = primary ? Accent : Border;
                button.FlatAppearance.MouseOverBackColor = primary ? Color.FromArgb(37, 83, 192) : Color.FromArgb(239, 244, 252);
                button.FlatAppearance.MouseDownBackColor = primary ? Color.FromArgb(31, 69, 165) : Color.FromArgb(228, 236, 249);
                button.UseVisualStyleBackColor = false; button.BackColor = primary ? Accent : Surface; button.ForeColor = primary ? Color.White : Text;
                object marker;if(!StyledButtons.TryGetValue(button,out marker)){StyledButtons.Add(button,new object());button.EnabledChanged+=delegate{ButtonState(button);};}ButtonState(button);
            }
            var textbox = control as TextBox;
            if (textbox != null) { textbox.BorderStyle = BorderStyle.FixedSingle; textbox.BackColor = textbox.ReadOnly ? Color.FromArgb(248,250,253) : Surface; }
            var tree = control as TreeView;
            if (tree != null) { tree.BorderStyle = BorderStyle.FixedSingle; tree.BackColor = Surface; }
            var tab = control as TabPage;
            if (tab != null) tab.BackColor = Surface;
            var grid = control as DataGridView;
            if (grid != null) { grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(229,238,255); grid.DefaultCellStyle.SelectionForeColor = Text; grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(242,246,252); grid.ColumnHeadersDefaultCellStyle.ForeColor = Muted; grid.EnableHeadersVisualStyles = false;grid.GridColor=Border;grid.BorderStyle=BorderStyle.None;grid.CellBorderStyle=DataGridViewCellBorderStyle.SingleHorizontal;grid.ColumnHeadersBorderStyle=DataGridViewHeaderBorderStyle.None;grid.RowTemplate.Height=38;grid.ColumnHeadersHeight=40;grid.AlternatingRowsDefaultCellStyle.BackColor=Color.FromArgb(250,252,255); }
            foreach (Control child in control.Controls) ApplyTree(child);
        }
    }
}
