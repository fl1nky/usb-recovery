using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace UsbRecovery
{
    public sealed class SurfaceCard : Panel
    {
        public SurfaceCard(){DoubleBuffered=true;BackColor=Color.White;Padding=new Padding(18);Margin=new Padding(0,0,0,14);}
        protected override void OnPaint(PaintEventArgs e){base.OnPaint(e);using(var pen=new Pen(UiTheme.Border))e.Graphics.DrawRectangle(pen,0,0,Math.Max(0,Width-1),Math.Max(0,Height-1));}
    }
    public sealed class NavigationButton : Button
    {
        public bool Selected;public string Glyph;
        bool hover;
        public NavigationButton(){SetStyle(ControlStyles.UserPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.AllPaintingInWmPaint,true);FlatStyle=FlatStyle.Flat;FlatAppearance.BorderSize=0;Cursor=Cursors.Hand;Height=46;}
        protected override void OnMouseEnter(EventArgs e){hover=true;Invalidate();base.OnMouseEnter(e);}
        protected override void OnMouseLeave(EventArgs e){hover=false;Invalidate();base.OnMouseLeave(e);}
        protected override void OnPaint(PaintEventArgs e){
            e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;e.Graphics.Clear(UiTheme.Sidebar);Color background=Selected?Color.FromArgb(43,54,78):hover?Color.FromArgb(34,42,57):UiTheme.Sidebar;
            using(var brush=new SolidBrush(background))e.Graphics.FillRectangle(brush,0,0,Width,Height);
            if(Selected)using(var brush=new SolidBrush(UiTheme.Accent))e.Graphics.FillRectangle(brush,0,10,3,Height-20);
            Color foreground=Selected?Color.White:Color.FromArgb(181,193,210);
            using(var font=new Font("Segoe UI",9F,FontStyle.Bold))TextRenderer.DrawText(e.Graphics,Glyph??"",font,new Rectangle(12,0,32,Height),Selected?Color.FromArgb(145,178,255):Color.FromArgb(119,139,165),TextFormatFlags.VerticalCenter|TextFormatFlags.HorizontalCenter);
            TextRenderer.DrawText(e.Graphics,Text,Font,new Rectangle(50,0,Width-54,Height),foreground,TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
            if(Focused)ControlPaint.DrawFocusRectangle(e.Graphics,new Rectangle(5,5,Width-10,Height-10));
        }
    }
    public sealed class WorkflowSteps : Control
    {
        public int Current;
        public WorkflowSteps(){Height=42;DoubleBuffered=true;}
        protected override void OnPaint(PaintEventArgs e){
            base.OnPaint(e);string[] names={"Источник","Образ и поиск","Проверка файлов"};int width=Math.Max(1,Width/3);
            using(var font=new Font("Segoe UI",9F))for(int i=0;i<3;i++){
                int x=i*width;Color c=i<=Current?UiTheme.Accent:UiTheme.Muted;
                using(var b=new SolidBrush(i==Current?Color.FromArgb(232,239,255):Color.FromArgb(237,241,246)))e.Graphics.FillEllipse(b,x,10,24,24);
                TextRenderer.DrawText(e.Graphics,(i+1).ToString(),font,new Rectangle(x,10,24,24),c,TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter);
                TextRenderer.DrawText(e.Graphics,names[i],font,new Rectangle(x+32,8,Math.Max(30,width-46),28),c,TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
            }
        }
    }
}
